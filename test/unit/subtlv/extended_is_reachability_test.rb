# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 22 sub-TLVs 6 and 8, RFC 5305 sections 3.2 and 3.3: type, length 4,
# then a four octet IPv4 address. Expected hex is our own arithmetic from
# section 3's table. Then the Adj-SID and LAN-Adj-SID of RFC 8667 section
# 2.2; the Adj-SID with label 15000 is also what FRR 10.2.1 sent.
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

  def replays(klass, hex)
    s = klass.new(octets(hex))
    assert_equal hex, s.to_shex, "#{klass} replays"
    assert_equal hex, klass.new(s.to_hash).to_shex, "#{klass} rebuilds from its hash"
    assert_equal hex, klass.new(s).to_shex, "#{klass} copies"
    s
  end

  # Adj-SID, section 2.2.1: 1f type (31), 05 length, flags, weight, then a
  # 3-octet label. V 0x20 and L 0x10, "By default, the flag is SET". This
  # is FRR's, label 15000.
  def test_adj_sid
    s = ISIS::SubTlv::AdjSid.new(label: 15000)
    assert_equal "1f053000003a98", s.to_shex
    assert_equal({ flags: %w[V L], label: 15000 }, replays(ISIS::SubTlv::AdjSid, s.to_shex).to_hash)
  end

  # F 0x80, B 0x40, V 0x20, L 0x10, S 0x08, P 0x04; weight in its own octet.
  def test_adj_sid_flags_and_weight
    s = ISIS::SubTlv::AdjSid.new(label: 15001, weight: 2, flags: %w[B V L P])
    assert_equal "1f057402003a99", s.to_shex
    assert_equal({ flags: %w[B V L P], weight: 2, label: 15001 }, replays(ISIS::SubTlv::AdjSid, s.to_shex).to_hash)
  end

  # LAN-Adj-SID, section 2.2.2: 20 type (32), flags, weight, the
  # neighbor's System ID, then the label. 2 + 6 + 3 is 11, 0b.
  def test_lan_adj_sid
    s = ISIS::SubTlv::LanAdjSid.new(neighbor: "0000.0000.0002", label: 15001)
    assert_equal "200b3000" "000000000002" "003a99", s.to_shex
    assert_equal({ neighbor: "0000.0000.0002", flags: %w[V L], label: 15001 },
                 replays(ISIS::SubTlv::LanAdjSid, s.to_shex).to_hash)
    assert_match(/LAN-Adj-SID 0000.0000.0002 label 15001/, s.to_s)
  end

  # Too short for a System ID: the octets are the SID alone, and replay.
  def test_lan_adj_sid_without_room_for_a_neighbor
    s = replays(ISIS::SubTlv::LanAdjSid, "20053000003a99")
    assert_nil s.neighbor
  end

  # Adj-SID and LAN-Adj-SID under 22 (RFC 8667 section 2.2); under 135
  # the same numbers stay unknown.
  def test_adj_sids_registered_under_tlv_22
    adj = ISIS::SubTlv::List.parse_under(22, octets("1f053000003a98" "200b3000000000000002003a99"))
    assert_equal [ISIS::SubTlv::AdjSid, ISIS::SubTlv::LanAdjSid], adj.map(&:class)
    assert_instance_of ISIS::SubTlv::Unknown, ISIS::SubTlv::List.parse_under(135, octets("1f053000003a98")).first
  end
end
