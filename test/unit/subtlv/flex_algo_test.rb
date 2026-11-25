# frozen_string_literal: true

require_relative "../../test_helper"

# The FAD sub-TLV and its sub-TLVs, RFC 9350 sections 5.1 and 6, and the
# FAPM, section 8. Expected hex is our own arithmetic from those layouts;
# FRR's FAD is the captured LSP of test/unit/pdu/lsp_flex_algo_test.rb.
class TestFlexAlgoSubTlvs < Minitest::Test
  def octets(hex) = ISIS::Octets.from_hex(hex)

  # Type 26, length 4 + 6 + 3: algorithm 128, metric type 1 (delay),
  # calculation type 0, priority 200, then exclude group 1 and M.
  def test_fad_from_fields
    f = ISIS::SubTlv::Fad.new(algorithm: 128, metric_type: "delay", priority: 200,
                              subtlvs: [{ fad_exclude_admin_group: { groups: [1] } }, { fad_flags: { flags: %w[M] } }])
    assert_equal "1a0d" "800100c8" "010400000002" "040180", f.to_shex
    assert_equal [128, 1, 0, 200], f.fixed
    assert_equal "FAD 128: metric delay, calc 0, priority 200; exclude 1; flags M", f.to_s
    assert_equal f.to_shex, ISIS::SubTlv::Fad.new(f.to_hash).to_shex
    assert_equal f.to_shex, ISIS::SubTlv::Fad.new(octets(f.to_shex)).to_shex
  end

  # A metric type past 2 is kept by number; building never validates.
  def test_fad_unknown_metric_type
    f = ISIS::SubTlv::Fad.new(algorithm: 5, metric_type: 7)
    assert_equal({ algorithm: 5, metric_type: 7, calc_type: 0, priority: 0 }, f.to_hash)
  end

  # Under TLV 242 the FAD is read; its sub-TLVs from the FAD's registry,
  # where 6 is unknown.
  def test_fad_under_tlv_242
    cap = ISIS::Tlv::RouterCapability.new(router_id: "10.255.0.1",
                                          subtlvs: [{ fad: { algorithm: 129, subtlvs: [{ unknown: { type: 6, value: "ff" } }] } }])
    fad = ISIS::Tlv::RouterCapability.new(octets(cap.to_shex)).subtlvs.first
    assert_instance_of ISIS::SubTlv::Fad, fad
    assert_instance_of ISIS::SubTlv::Unknown, fad.subtlvs.first
  end

  # The admin group rules take ExtendedAdminGroup's numbering: group 32
  # is the low bit of the second word.
  def test_admin_group_rules
    { ISIS::SubTlv::FadExcludeAdminGroup => "01", ISIS::SubTlv::FadIncludeAnyAdminGroup => "02",
      ISIS::SubTlv::FadIncludeAllAdminGroup => "03" }.each do |klass, type|
      s = klass.new(groups: [1, 32])
      assert_equal "#{type}08" "00000002" "00000001", s.to_shex
      assert_equal [1, 32], klass.new(octets(s.to_shex)).groups
    end
    assert_equal "include-all 3", ISIS::SubTlv::FadIncludeAllAdminGroup.new(groups: [3]).to_s
  end

  # M is bit 0, the high bit of the first octet; bits not sent are 0.
  def test_flags
    assert_equal "040180", ISIS::SubTlv::FadFlags.new(flags: %w[M]).to_shex
    f = ISIS::SubTlv::FadFlags.new(octets("0402c000"))
    assert_equal [0, 1], f.bits
    assert f.m?
    assert_equal({ flags: ["M"], bits: [1], length: 2 }, f.to_hash)
    assert_equal "flags M, bit 1", f.to_s
    refute ISIS::SubTlv::FadFlags.new(octets("0400")).m?
  end

  def test_exclude_srlg
    s = ISIS::SubTlv::FadExcludeSrlg.new(srlgs: [10, 20])
    assert_equal "0508" "0000000a" "00000014", s.to_shex
    assert_equal "exclude SRLG 10, 20", s.to_s
  end

  # Type 6, length 5: the algorithm, then the 4-octet metric; under TLVs
  # 135 and 236.
  def test_fapm
    f = ISIS::SubTlv::Fapm.new(algorithm: 128, metric: 20)
    assert_equal "0605" "80" "00000014", f.to_shex
    assert_equal "FAPM algorithm 128 metric 20", f.to_s
    v4 = ISIS::Tlv::ExtendedIpReachability.new({ prefix: "10.255.0.1/32", metric: 0, subtlvs: [{ fapm: { algorithm: 128, metric: 20 } }] })
    assert_instance_of ISIS::SubTlv::Fapm, ISIS::Tlv::ExtendedIpReachability.new(octets(v4.to_shex)).entries.first.subtlvs.first
    v6 = ISIS::Tlv::Ipv6Reachability.new({ prefix: "2001:db8::1/128", metric: 0, subtlvs: [{ fapm: { algorithm: 128, metric: 20 } }] })
    assert_instance_of ISIS::SubTlv::Fapm, ISIS::Tlv::Ipv6Reachability.new(octets(v6.to_shex)).entries.first.subtlvs.first
  end

  def test_refusals
    assert_raises(ArgumentError) { ISIS::SubTlv::Fad.new(algorithm: 256) }
    assert_raises(ArgumentError) { ISIS::SubTlv::FadFlags.new(flags: %w[Q]) }
    assert_raises(ArgumentError) { ISIS::SubTlv::Fapm.new(algorithm: 128, metric: 1 << 32) }
  end
end
