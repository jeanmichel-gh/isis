# frozen_string_literal: true

require_relative "../../test_helper"

# The TLV 22 link attributes flex-algo reads (docs/design/flex-algo.md,
# step 1): Admin Group and TE Default Metric (RFC 5305 sections 3.1 and
# 3.7), Extended Admin Group (RFC 7308 section 2.1), the two link delays
# (RFC 8570 sections 4.1 and 4.2), Link Identifiers (RFC 5307 section
# 1.1), the IPv6 addresses (RFC 6119 sections 4.2 and 4.3), and the ASLA
# sub-TLV (RFC 9479 sections 4.1 and 4.2). Expected hex is our own
# arithmetic from those layouts, unless it says FRR sent it.
class TestSubTlvLinkAttributes < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # Group 0 is the least significant bit (RFC 5305 section 3.1): groups 0
  # and 31 are 0x80000001.
  def test_admin_group_bits
    g = ISIS::SubTlv::AdminGroup.new(groups: [0, 31])
    assert_equal "030480000001", g.to_shex
    assert_equal [0, 31], ISIS::SubTlv::AdminGroup.new(octets("030480000001")).groups
    assert g.group?(31)
    refute g.group?(1)
    assert_equal "Admin Group 0, 31", g.to_s
  end

  def test_admin_group_refuses_a_group_past_31
    assert_raises(ArgumentError) { ISIS::SubTlv::AdminGroup.new(groups: [32]) }
  end

  # Bits 0 to 31 of an EAG are the AG's (RFC 7308 section 2.2); group 32 is
  # the low bit of the second word. FRR 10.7.1 sent exactly this for bit
  # positions 1, 32 and 40.
  def test_extended_admin_group_numbers_by_word
    g = ISIS::SubTlv::ExtendedAdminGroup.new(groups: [1, 32, 40])
    assert_equal "0e080000000200000101", g.to_shex
    assert_equal 8, g.size
    assert_equal [1, 32, 40], ISIS::SubTlv::ExtendedAdminGroup.new(octets("0e080000000200000101")).groups
  end

  # "The EAG may be of any non-zero length, but it MUST be a multiple of
  # 4 bytes": a length that is not is kept, the odd octets as a tail.
  def test_extended_admin_group_keeps_an_odd_length
    g = ISIS::SubTlv::ExtendedAdminGroup.new(octets("0e0500000001aa"))
    assert_equal({ groups: [0], tail: "aa" }, g.to_hash)
    assert_equal "0e0500000001aa", g.to_shex
  end

  def test_te_default_metric_is_24_bits
    assert_equal "120300004d", ISIS::SubTlv::TeDefaultMetric.new(metric: 77).to_shex
    assert_equal 0xffffff, ISIS::SubTlv::TeDefaultMetric.new(octets("1203ffffff")).metric
    assert_raises(ArgumentError) { ISIS::SubTlv::TeDefaultMetric.new(metric: 1 << 24) }
  end

  # RFC 8570 section 4.1: |A| RESERVED | Delay |. 5000 us is 0x001388.
  def test_link_delay
    d = ISIS::SubTlv::LinkDelay.new(delay: 5000)
    assert_equal "210400001388", d.to_shex
    a = ISIS::SubTlv::LinkDelay.new(octets("210480001388"))
    assert a.anomalous?
    assert_equal 5000, a.delay
    assert_equal "Link Delay 5000 us anomalous", a.to_s
  end

  # RFC 8570 section 4.2: |A| RESERVED | Min | then | RESERVED | Max |.
  def test_min_max_link_delay
    d = ISIS::SubTlv::MinMaxLinkDelay.new(min: 5000, max: 6000)
    assert_equal "22080000138800001770", d.to_shex
    back = ISIS::SubTlv::MinMaxLinkDelay.new(octets("22080000138800001770"))
    assert_equal [5000, 6000, false], [back.min, back.max, back.anomalous?]
    assert_equal "Min/Max Link Delay 5000/6000 us", back.to_s
  end

  # A value too short for the fields is kept whole and replays.
  def test_short_values_replay
    %w[0302abcd 12020001 2102ffff 2203000001 0d020102].each do |hex|
      s = ISIS::SubTlv::List.parse_under(22, octets(hex)).first
      assert_equal hex, s.to_shex
      assert s.to_hash.key?(:short), hex
    end
  end

  def test_link_identifiers
    assert_equal "04080000000700000000", ISIS::SubTlv::LinkIdentifiers.new(local: 7).to_shex
  end

  def test_ipv6_addresses
    s = ISIS::SubTlv::Ipv6InterfaceAddress.new(address: "2001:db8::1")
    assert_equal "0c1020010db8000000000000000000000001", s.to_shex
    assert_equal "IPv6 Interface Address 2001:db8::1", s.to_s
    assert_raises(ArgumentError) { ISIS::SubTlv::Ipv6NeighborAddress.new(address: "192.0.2.1") }
  end

  # RFC 9479 section 4.1: bit 0 is the most significant bit, R S F, and
  # RFC 9350 section 12's X is bit 3, 0x10. The SABM length is the fewest
  # octets that hold the bits set.
  def test_asla_mask
    a = ISIS::SubTlv::Asla.new(applications: %w[X], subtlvs: [{ te_default_metric: { metric: 100 } }])
    assert_equal "1008010010120300006" "4", a.to_shex
    assert_equal %w[X], a.applications
    refute a.legacy?
    assert_equal 100, a.attribute(ISIS::SubTlv::TeDefaultMetric).metric
    assert_equal "ASLA X: TE Default Metric 100", a.to_s
  end

  # L set: the applications use the legacy sub-TLVs; a zero-length mask:
  # any application (section 4.2).
  def test_asla_legacy_and_any_application
    l = ISIS::SubTlv::Asla.new(octets("1003810010"))
    assert l.legacy?
    assert_equal %w[X], l.applications
    assert_equal "ASLA X, legacy", l.to_s
    any = ISIS::SubTlv::Asla.new(subtlvs: [{ link_delay: { delay: 10 } }])
    assert_equal "1008" "0000" "21040000000a", any.to_shex
    assert_equal "ASLA any application: Link Delay 10 us", any.to_s
  end

  # The attributes are read from the ASLA's own registry, under their
  # legacy numbers (section 7.3); an Adj-SID's 31 is not one of them.
  def test_asla_registry
    a = ISIS::SubTlv::Asla.new(octets("100e0100103103000000" "030400000002"))
    assert_instance_of ISIS::SubTlv::Unknown, a.subtlvs.first
    assert_instance_of ISIS::SubTlv::AdminGroup, a.subtlvs.to_a.last
  end

  # A mask length past 8 is kept: "the entire sub-TLV MUST be ignored" is
  # the receiver's decision. Past the value, it is not a mask: short.
  def test_asla_long_masks_are_kept
    long = ISIS::SubTlv::Asla.new(octets("100b0900" "000000000000000010"))
    assert_equal 9, long.sabm_length
    assert_equal [67], long.sabm_bits
    short = ISIS::SubTlv::Asla.new(octets("1003050000"))
    assert_equal({ short: "050000" }, short.to_hash)
  end

  def test_asla_refuses_an_unknown_application
    assert_raises(ArgumentError) { ISIS::SubTlv::Asla.new(applications: %w[Q]) }
  end

  # Registered under TLV 22 and the ASLA; under TLV 135 the same numbers
  # stay unknown.
  def test_registered_under_tlv_22
    list = ISIS::SubTlv::List.parse_under(22, octets("030400000001" "0e0400000001" "120300000a"))
    assert_equal [ISIS::SubTlv::AdminGroup, ISIS::SubTlv::ExtendedAdminGroup, ISIS::SubTlv::TeDefaultMetric],
                 list.map(&:class)
    assert_instance_of ISIS::SubTlv::Unknown, ISIS::SubTlv::List.parse_under(135, octets("120300000a")).first
  end

  def test_four_ways_in
    g = ISIS::SubTlv::ExtendedAdminGroup.new(groups: [3])
    [ISIS::SubTlv::ExtendedAdminGroup.new(g), ISIS::SubTlv::ExtendedAdminGroup.new(g.to_hash),
     ISIS::SubTlv::ExtendedAdminGroup.new(octets(g.to_shex))].each do |o|
      assert_equal g.to_shex, o.to_shex
    end
  end
end
