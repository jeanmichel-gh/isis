# frozen_string_literal: true

require_relative "../../test_helper"

# Spf::Labels runs ISIS::Validation's segment routing rules on LSPs no
# isisd would send, built by hand, and acts on each finding under the
# receive policy. A computes, in a line a ---- b ---- c; b's SRGB is
# 18000, c's 20000 unless a test breaks it; c's loopback 10.255.0.3/32 has
# index 3.
class TestSrFindings < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @db = ISIS::Database.new(level: 1, clock: @clock)
  end

  def id(letter)
    (ISIS::Pdu.dotted_octets("0000.0000.000#{letter}") + "\x00".b).b
  end

  def adj(letter)
    ISIS::Spf::Adjacency.new(circuit: "eth-#{letter}", neighbor: ISIS::Pdu.dotted_octets("0000.0000.000#{letter}"),
                             circuit_id: 1, address: "10.0.0.#{letter.hex}")
  end

  # TLV 242 with one SR-Capabilities per entry of +srgbs+, each a list of
  # [first, range], and SR-Algorithm +algorithms+.
  def capability(n, srgbs, algorithms: [0])
    subs = srgbs.map do |srgb|
      ISIS::SubTlv::SrCapabilities.new(flags: %w[I], descriptors: srgb.map { |first, range| { range: range, label: first } })
    end
    ISIS::Tlv::RouterCapability.new(router_id: "10.255.0.#{n}", subtlvs: subs + [ISIS::SubTlv::SrAlgorithm.new(*algorithms)])
  end

  def prefix(n, sid)
    ISIS::Tlv::ExtendedIpReachability.new([{ prefix: "10.255.0.#{n}/32", metric: 0, subtlvs: [{ prefix_sid: sid }] }])
  end

  def store(letter, links, tlvs)
    lsp_id = id(letter) + "\x00".b
    reach = ISIS::Tlv::ExtendedIsReachability.new(links.map do |n, m|
      ISIS::Tlv::ExtendedIsReachability::Entry.new(neighbor: id(n), metric: m)
    end)
    pdu = ISIS::Pdu::Lsp.new(level: 1, lsp_id: ISIS::Octets.new(lsp_id), lifetime: 1200, sequence: 1,
                             tlvs: [reach] + tlvs)
    @db.entry(lsp_id).store(pdu)
  end

  # The line, with c's SR-Capabilities and Prefix-SID as given.
  def line(c_srgbs: [[[20_000, 8_000]]], c_sid: { flags: ["N"], algorithm: 0, index: 3 }, c_algorithms: [0],
           b_sid: nil)
    store("a", { "b" => 10 }, [])
    b_tlvs = [capability(2, [[[18_000, 8_000]]])]
    b_tlvs << prefix(2, b_sid) if b_sid
    store("b", { "a" => 10, "c" => 10 }, b_tlvs)
    store("c", { "b" => 10 }, [capability(3, c_srgbs, algorithms: c_algorithms), prefix(3, c_sid)])
  end

  def labels(policy: nil)
    calc = ISIS::Spf::Calculation.new(database: @db, system_id: "0000.0000.000a", adjacencies: [[id("b"), 10, adj("b")]]).run
    own = ISIS::SegmentRouting.new(router_id: "10.255.0.1", srgb: [[16_000, 8_000]])
    ISIS::Spf::Labels.new(own: own, database: @db, paths: calc.paths, policy: policy).build(calc.routes, [])
  end

  def names(table)
    table.findings.map(&:name)
  end

  def test_good_data_has_no_finding
    line
    t = labels
    assert_empty t.findings
    assert_equal 18_003, t.entries[16_003].hops.first[1]
  end

  # RFC 8660 section 2.3: c's SRGB is "completely ignored", and c is
  # treated as having none. a still swaps toward b, whose SRGB is good.
  def test_an_srgb_that_overlaps
    line(c_srgbs: [[[20_000, 1_000], [20_500, 1_000]]])
    t = labels
    assert_equal [:srgb_overlap], names(t)
    assert_nil t.nodes[id("c")].srgb
    assert_equal 18_003, t.entries[16_003].hops.first[1]
    assert_equal 1, t.problems.grep(/\A0000.0000.000c: ranges 20000-20999 and 20500-21499 overlap \(RFC 8660/).size
  end

  def test_a_range_of_zero
    line(c_srgbs: [[[20_000, 0]]])
    assert_equal [:srgb_range_zero], names(labels)
  end

  def test_reserved_labels
    line(c_srgbs: [[[8, 100]]])
    assert_equal [:srgb_reserved], names(labels)
  end

  # RFC 8667 section 3.1: the first is used.
  def test_two_sr_capabilities
    line(c_srgbs: [[[20_000, 8_000]], [[30_000, 8_000]]])
    t = labels
    assert_equal [:sr_capabilities_twice], names(t)
    assert_equal [[20_000, 27_999]], t.nodes[id("c")].srgb
  end

  def test_an_invalid_v_and_l
    line(c_sid: { flags: %w[N V], algorithm: 0, index: 3 })
    t = labels
    assert_equal [:prefix_sid_vl_invalid], names(t)
    refute t.entries.key?(16_003)
    assert_nil t.nodes[id("c")].sid, "nor is it c's Node-SID"
  end

  def test_a_sid_that_is_a_label
    line(c_sid: { flags: %w[N V L], algorithm: 0, label: 20_003 })
    t = labels
    assert_equal [:prefix_sid_label], names(t)
    assert_equal :gaps, t.findings.first.channel
  end

  # SPF keeps a prefix's algorithm 0 Prefix-SID only (Spf::Calculation),
  # so the case that reaches here is an origin that does not list 0.
  def test_an_algorithm_not_advertised
    line(c_algorithms: [1])
    assert_equal [:algorithm_not_advertised], names(labels)
    refute labels.entries.key?(16_003)
  end

  def test_one_index_on_two_prefixes
    line(b_sid: { flags: ["N"], algorithm: 0, index: 3 })
    t = labels
    assert_equal [:prefix_sid_duplicate], names(t)
    refute t.entries.key?(16_003)
  end

  # :strict refuses c's SR data whole: no SRGB, no Node-SID, no label
  # for its prefix.
  def test_strict
    line(c_srgbs: [[[20_000, 1_000], [20_500, 1_000]]])
    t = labels(policy: :strict)
    assert_equal :strict, t.policy
    assert t.nodes[id("c")].ignored
    assert_nil t.nodes[id("c")].sid
    refute t.entries.key?(16_003)
  end

  # :lenient uses what arrived where it can.
  def test_lenient
    line(c_srgbs: [[[20_000, 1_000], [20_500, 1_000]]], c_algorithms: [1])
    t = labels(policy: :lenient)
    assert_equal %i[srgb_overlap algorithm_not_advertised], names(t)
    assert_equal [[20_000, 20_999], [20_500, 21_499]], t.nodes[id("c")].srgb
    assert t.entries.key?(16_003)
  end

  # The policy comes from the configuration when none is given.
  def test_the_policy_from_segment_routing
    line
    calc = ISIS::Spf::Calculation.new(database: @db, system_id: "0000.0000.000a", adjacencies: [[id("b"), 10, adj("b")]]).run
    own = ISIS::SegmentRouting.from_config({ receive_policy: "lenient" }, router_id: "10.255.0.1", prefixes: [], ipv6: false)
    assert_equal :lenient, ISIS::Spf::Labels.new(own: own, database: @db, paths: calc.paths).policy
  end

  def test_segment_routing_refuses_an_unknown_key
    e = assert_raises(ArgumentError) do
      ISIS::SegmentRouting.from_config({ srgb_size: 1 }, router_id: "10.255.0.1", prefixes: [], ipv6: false)
    end
    assert_equal "segment_routing: unknown key srgb_size; the keys are srgb, srlb, receive_policy", e.message
    assert_raises(ArgumentError) do
      ISIS::SegmentRouting.from_config({ receive_policy: "loose" }, router_id: "10.255.0.1", prefixes: [], ipv6: false)
    end
  end
end
