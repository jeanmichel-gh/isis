# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 22 sub-TLVs 6 and 8, RFC 5305 sections 3.2 and 3.3: type, length 4,
# then a four octet IPv4 address. Expected hex is our own arithmetic from
# section 3's table.
class TestSubTlvExtendedIsReachability < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # 06 type, 04 length, c0000201 is 192.0.2.1.
  def test_interface_address_pton
    assert_equal "0604c0000201", ISIS::SubTlv::Ipv4InterfaceAddress.new("192.0.2.1").to_shex
  end

  # 08 type, 04 length, c0000202 is 192.0.2.2.
  def test_neighbor_address_pton
    assert_equal "0804c0000202", ISIS::SubTlv::Ipv4NeighborAddress.new("192.0.2.2").to_shex
  end

  def test_ntop
    s = ISIS::SubTlv::Ipv4InterfaceAddress.new(octets("0604c0000201"))
    assert_equal "192.0.2.1", s.address.to_s
    assert_equal "IPv4 Interface Address 192.0.2.1", s.to_s
    assert_equal "IPv4 Neighbor Address 192.0.2.2", ISIS::SubTlv::Ipv4NeighborAddress.new(octets("0804c0000202")).to_s
  end

  def test_round_trip
    assert_equal "0804c0000202", ISIS::SubTlv::Ipv4NeighborAddress.new(octets("0804c0000202")).to_shex
  end

  def test_hash_rebuilds
    [ISIS::SubTlv::Ipv4InterfaceAddress.new("192.0.2.1"), ISIS::SubTlv::Ipv4NeighborAddress.new("192.0.2.2")].each do |s|
      assert_kind_of String, s.to_hash
      assert_equal s.to_shex, s.class.new(s.to_hash).to_shex
    end
  end

  def test_copy_constructor
    s = ISIS::SubTlv::Ipv4InterfaceAddress.new("192.0.2.1")
    assert_equal "0604c0000201", ISIS::SubTlv::Ipv4InterfaceAddress.new(s).to_shex
  end

  # Registered under TLV 22, and only there: under TLV 135 the same numbers
  # stay unknown.
  def test_registered_under_tlv_22_only
    list = ISIS::SubTlv::List.parse_under(22, octets("0604c0000201" "0804c0000202"))
    assert_equal [ISIS::SubTlv::Ipv4InterfaceAddress, ISIS::SubTlv::Ipv4NeighborAddress], list.map(&:class)
    other = ISIS::SubTlv::List.parse_under(135, octets("0604c0000201"))
    assert_instance_of ISIS::SubTlv::Unknown, other.first
  end

  # A wrong length is kept: five octets replay as five, three as three.
  def test_odd_lengths_replay
    long = ISIS::SubTlv::Ipv4InterfaceAddress.new(octets("0605c0000201ff"))
    assert_equal({ address: "192.0.2.1", tail: "ff" }, long.to_hash)
    assert_equal "0605c0000201ff", long.to_shex
    assert_equal "0605c0000201ff", ISIS::SubTlv::Ipv4InterfaceAddress.new(long.to_hash).to_shex

    short = ISIS::SubTlv::Ipv4NeighborAddress.new(octets("0803c00002"))
    assert_nil short.address
    assert_equal "0803c00002", short.to_shex
    assert_equal "0803c00002", ISIS::SubTlv::Ipv4NeighborAddress.new(short.to_hash).to_shex
  end

  def test_prefix_and_ipv6_are_refused
    assert_raises(ArgumentError) { ISIS::SubTlv::Ipv4InterfaceAddress.new("192.0.2.0/24") }
    assert_raises(ArgumentError) { ISIS::SubTlv::Ipv4NeighborAddress.new("2001:db8::1") }
  end

  # In a TLV 22 entry: 7 octets of neighbor, 3 of metric, a sub-TLV length
  # of 12, then the two sub-TLVs. 16 is 22, 17 is 23 octets of value.
  def test_in_a_tlv_22_entry
    tlv = ISIS::Tlv::ExtendedIsReachability.new(
      neighbor: "0000.0000.0002.00", metric: 10,
      subtlvs: [{ ipv4_interface_address: "192.0.2.1" }, { ipv4_neighbor_address: "192.0.2.2" }]
    )
    hex = "1617" "00000000000200" "00000a" "0c" "0604c0000201" "0804c0000202"
    assert_equal hex, tlv.to_shex
    again = ISIS::Tlv::ExtendedIsReachability.new(octets(hex))
    assert_equal [{ neighbor: "0000.0000.0002.00", metric: 10,
                    subtlvs: [{ ipv4_interface_address: "192.0.2.1" }, { ipv4_neighbor_address: "192.0.2.2" }] }],
                 again.to_hash
  end
end
