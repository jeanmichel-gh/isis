# frozen_string_literal: true

require_relative "../../test_helper"

# Spf::LinkAttributes: one node's link attributes for flex-algo, read by
# RFC 9350 section 12 and RFC 9479 sections 4.2 and 4.3, on hand-built
# LSPs. test/unit/fault_test.rb has each finding from the fault catalog.
class TestLinkAttributes < Minitest::Test
  LA = ISIS::Spf::LinkAttributes
  N2 = "0000.0000.0002.00"

  def lsp(tlvs, number: 0)
    ISIS::Pdu::Lsp.new(level: 1, lsp_id: ISIS::Octets.new(ISIS::Pdu.dotted_octets("0000.0000.0001") + "\x00".b + number.chr),
                       lifetime: 1200, sequence: 1, tlvs: tlvs)
  end

  def link(subtlvs, neighbor: N2, interface: "10.0.12.1", remote: "10.0.12.2")
    addresses = []
    addresses << { ipv4_interface_address: interface } if interface
    addresses << { ipv4_neighbor_address: remote } if remote
    ISIS::Tlv::ExtendedIsReachability.new({ neighbor: neighbor, metric: 10, subtlvs: addresses + subtlvs })
  end

  def asla(subtlvs, applications: %w[X], **mask)
    { asla: { applications: applications, subtlvs: subtlvs, **mask } }
  end

  def te(metric) = { te_default_metric: { metric: metric } }

  def read(*lsps, policy: :rfc)
    LA.new(lsps, policy: policy)
  end

  def only(la)
    assert_equal 1, la.links.size
    la.links.first
  end

  # Every attribute from one ASLA with X: the EAG's groups, the TE
  # metric, the three delays.
  def test_x_values
    l = only(read(lsp([link([asla([{ extended_admin_group: { groups: [1, 40] } }, te(100),
                                   { link_delay: { delay: 5000 } }, { min_max_link_delay: { min: 4000, max: 6000 } }])])])))
    assert_equal({ affinity: [1, 40], te_metric: 100, delay: { min: 4000, max: 6000, average: 5000 } }, l.to_hash)
    assert_equal 4000, l.min_delay
    assert_equal %w[00000000000200 10.0.12.1 10.0.12.2], [l.neighbor.unpack1("H*"), l.interface, l.remote]
  end

  # Legacy sub-TLVs beside the ASLA are not flex-algo's (9350 section 12).
  def test_legacy_values_alone_are_not_read
    l = only(read(lsp([link([te(50), { admin_group: { groups: [3] } }])])))
    assert_empty l.to_hash
    assert_nil l.min_delay
  end

  # An ASLA for other applications only, R and S: not flex-algo's.
  def test_another_application
    assert_empty only(read(lsp([link([asla([te(100)], applications: %w[R S])])]))).to_hash
  end

  # 9479 section 4.2: a zero-length mask's values when no ASLA with X
  # gives the attribute; X's win where both give one.
  def test_zero_length_mask
    l = only(read(lsp([link([asla([te(5), { link_delay: { delay: 9 } }], applications: []), asla([te(100)])])])))
    assert_equal({ te_metric: 100, delay: { average: 9 } }, l.to_hash)
  end

  # The L flag set for X: the legacy sub-TLVs, and TLV 138's SRLGs.
  def test_l_flag_takes_the_legacy_sub_tlvs
    srlg = ISIS::Tlv::Srlg.new(neighbor: N2, local: "10.0.12.1", remote: "10.0.12.2", srlgs: [7])
    asla238 = ISIS::Tlv::AslaSrlg.new(neighbor: N2, applications: %w[X], legacy: true,
                                      links: [{ ipv4_interface_address: "10.0.12.1" }])
    l = only(read(lsp([link([te(50), { admin_group: { groups: [3] } }, asla([], legacy: true)]), srlg, asla238])))
    assert_equal({ affinity: [3], te_metric: 50, srlg: [7], asla_legacy: true }, l.to_hash)
  end

  # Mixed L flags: under rfc the L flag is taken as set; under lenient,
  # the values of the sub-TLV with L clear.
  def test_l_flag_mixed
    tlvs = [link([te(50), asla([], legacy: true), asla([te(100)])])]
    rfc = read(lsp(tlvs))
    assert_equal({ te_metric: 50, asla_legacy: true }, only(rfc).to_hash)
    assert_equal [:asla_l_flag_mixed], rfc.findings.map(&:name)
    assert_equal({ te_metric: 100 }, only(read(lsp(tlvs), policy: :lenient)).to_hash)
  end

  # Values beside the L flag: ignored under rfc, the legacy sub-TLVs used;
  # used under lenient. The same for SRLGs in a TLV 238 with L set.
  def test_values_beside_the_l_flag
    srlg = ISIS::Tlv::AslaSrlg.new(neighbor: N2, applications: %w[X], legacy: true,
                                   links: [{ ipv4_interface_address: "10.0.12.1" }], srlgs: [9])
    tlvs = [link([te(50), asla([te(100)], legacy: true)]), srlg]
    rfc = read(lsp(tlvs))
    assert_equal({ te_metric: 50, asla_legacy: true }, only(rfc).to_hash)
    assert_equal %i[asla_l_flag_values asla_l_flag_values], rfc.findings.map(&:name)
    assert_equal({ te_metric: 100, srlg: [9] }, only(read(lsp(tlvs), policy: :lenient)).to_hash)
  end

  # A conflict across fragments: the first in the lowest LSP Number,
  # under rfc; none under strict.
  def test_conflict_across_fragments
    zero = lsp([link([asla([te(100)])])])
    one = lsp([link([asla([te(200)])])], number: 1)
    la = read(one, zero)
    assert_equal [:asla_conflict], la.findings.map(&:name)
    assert_equal 100, only(read(zero, one)).te_metric
    assert_nil only(read(zero, one, policy: :strict)).te_metric
  end

  # The same value twice is no conflict.
  def test_the_same_value_twice
    la = read(lsp([link([asla([te(100)]), asla([te(100)])])]))
    assert_empty la.findings
    assert_equal 100, only(la).te_metric
  end

  # RFC 7308 section 2.3.1: the AG for 0 to 31, the EAG past it.
  def test_admin_group_and_eag
    l = only(read(lsp([link([asla([{ admin_group: { groups: [1] } }, { extended_admin_group: { groups: [1, 33] } }])])])))
    assert_equal [1, 33], l.affinity
    mismatch = read(lsp([link([asla([{ admin_group: { groups: [1] } }, { extended_admin_group: { groups: [2, 33] } }])])]))
    assert_equal [1, 33], only(mismatch).affinity
    assert_equal [:admin_group_mismatch], mismatch.findings.map(&:name)
  end

  # A mask over 8 octets: the whole sub-TLV ignored, but not under
  # lenient.
  def test_mask_too_long
    tlvs = [link([asla([te(100)], sabm_length: 9)])]
    assert_nil only(read(lsp(tlvs))).te_metric
    assert_equal 100, only(read(lsp(tlvs), policy: :lenient)).te_metric
  end

  # Two parallel links to one neighbour, told apart by their addresses;
  # TLV 238 names the second by its neighbour address.
  def test_parallel_links_and_srlg
    a = link([asla([te(10)])])
    b = link([asla([te(20)])], interface: "10.0.21.1", remote: "10.0.21.2")
    srlg = ISIS::Tlv::AslaSrlg.new(neighbor: N2, applications: %w[X], links: [{ ipv4_neighbor_address: "10.0.21.2" }],
                                   srlgs: [5, 6])
    la = read(lsp([a, b, srlg]))
    assert_equal [{ te_metric: 10 }, { te_metric: 20, srlg: [5, 6] }], la.links.map(&:to_hash)
    entry = b.entries.first
    assert_equal 20, la.for(entry).te_metric
  end

  # TLV 238 with a zero-length mask counts when none has X; one naming no
  # link of this node is not used.
  def test_srlg_zero_length_and_unmatched
    zero = ISIS::Tlv::AslaSrlg.new(neighbor: N2, applications: [], links: [{ ipv4_interface_address: "10.0.12.1" }],
                                   srlgs: [3])
    other = ISIS::Tlv::AslaSrlg.new(neighbor: N2, applications: %w[X], links: [{ ipv4_interface_address: "10.9.9.9" }],
                                    srlgs: [4])
    assert_equal [3], only(read(lsp([link([]), zero, other]))).srlg
  end

  # FRR 10.7.1's link, captured on ospflab: its ASLA has X, the EAG's
  # groups 1, 32 and 40, TE metric 77 and the average delay only.
  def test_frr
    hex = File.read(File.expand_path("../../fixtures/frr-10.7.1-l2-lsp-flex-algo.hex", __dir__)).strip
    la = read(ISIS::Pdu.factory(ISIS::Octets.from_hex(hex)))
    assert_empty la.findings
    assert_equal({ affinity: [1, 32, 40], te_metric: 77, delay: { average: 5000 } }, only(la).to_hash)
    assert_nil only(la).min_delay, "no Min/Max, so no metric for metric type 1"
  end
end
