# frozen_string_literal: true

require_relative "../../test_helper"

# The LAN hello, RFC 1142 clauses 9.5 and 9.6, with the field order FRR and
# Wireshark use (see the class). Two kinds of expectation here: hex laid
# out field by field below, which is our own arithmetic from the clause,
# and a hello captured from FRR, which is somebody else agreeing.
class TestLanHello < Minitest::Test
  # Common header: 83 IRPD, 1b Length Indicator (8 + 19 = 27), 01, 00 ID
  # Length (six octets), 0f PDU type 15, 01 version, 00 reserved, 00 max
  # area addresses.
  COMMON = "831b01000f010000"
  # Fixed header: 01 circuit type L1, 192168001001 Source ID, 001e holding
  # time 30, 0029 PDU Length (27 + 14 = 41), 40 priority 64, 19216800100101
  # LAN ID, the System ID and octet 01.
  FIXED = "01" "192168001001" "001e" "0029" "40" "19216800100101"
  # TLVs, 14 octets: area 49.0001 (6), and IS Neighbours with one MAC (8).
  TLVS = "010403490001" "0606000000000002"
  HELLO = COMMON + FIXED + TLVS

  # An L1 LAN hello from FRR 8.4.4's isisd, captured on a veth pair here on
  # 2026-10-31 with the LLC header removed. 1497 octets, most of them TLV 8
  # padding, and a LAN ID of zeros, since no DIS had been elected yet.
  FRR = File.read(File.expand_path("../../fixtures/frr-8.4.4-l1-lan-hello.hex", __dir__)).strip

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def built(**over)
    ISIS::Pdu::LanHello.new(level: 1, circuit_type: :l1, source_id: "1921.6800.1001", holding_time: 30,
                            priority: 64, lan_id: "1921.6800.1001.01",
                            tlvs: [ISIS::Tlv::AreaAddresses.new("49.0001"),
                                   ISIS::Tlv::IsNeighbors.new("00:00:00:00:00:02")], **over)
  end

  def test_built_from_fields
    assert_equal HELLO, built.to_shex
  end

  # 27 and 41 are both in the PDU and mean different things.
  def test_length_indicator_and_pdu_length_are_different_fields
    o = built.encode
    assert_equal 27, o.getbyte(1), "Length Indicator"
    assert_equal 41, o.byteslice(17, 2).unpack1("n"), "PDU Length"
  end

  # The level is the PDU type, 15 or 16, and nothing else changes.
  def test_level_2_is_type_16
    hex = built(level: 2).to_shex
    assert_equal "10", hex[8, 2]
    assert_equal HELLO[10..], hex[10..]
  end

  # The circuit type is its own field and says which levels the sender runs,
  # whatever the PDU type: an L1 hello from an L1L2 system says 3.
  def test_circuit_type_is_separate_from_the_level
    hello = built(circuit_type: :l1l2)
    assert_equal 1, hello.level
    assert_equal "03", hello.to_shex[16, 2]
  end

  def test_parse_through_the_factory
    pdu = ISIS::Pdu.factory(octets(HELLO))
    assert_instance_of ISIS::Pdu::LanHello, pdu
    assert_equal 1, pdu.level
    assert_equal :l1, pdu.circuit_type
    assert_equal "1921.6800.1001", pdu.source_id_s
    assert_equal 30, pdu.holding_time
    assert_equal 64, pdu.priority
    assert_equal "1921.6800.1001.01", pdu.lan_id_s
    assert_equal [Datalink::MAC.new("00:00:00:00:00:02")], pdu.neighbors
    assert_equal HELLO, pdu.to_shex
  end

  def test_frr_hello_parses_and_replays
    pdu = ISIS::Pdu.factory(octets(FRR))
    assert_instance_of ISIS::Pdu::LanHello, pdu
    assert_equal [1, :l1, "0000.0000.0002", 10, 64, "0000.0000.0000.00"],
                 [pdu.level, pdu.circuit_type, pdu.source_id_s, pdu.holding_time, pdu.priority, pdu.lan_id_s]
    assert_equal 1497, pdu.declared_pdu_length
    assert_equal [ISIS::Tlv::ProtocolsSupported, ISIS::Tlv::AreaAddresses, ISIS::Tlv::IpInterfaceAddresses],
                 pdu.tlvs.first(3).map(&:class)
    assert(pdu.tlvs.drop(3).all? { |t| t.is_a?(ISIS::Tlv::Padding) })
    assert_equal FRR, pdu.to_shex
  end

  # Several TLV 6s are allowed, "This option field can occur multiple
  # times", so the neighbours are gathered from all of them.
  def test_neighbors_from_every_is_neighbors_tlv
    hello = built(tlvs: [ISIS::Tlv::IsNeighbors.new("00:00:00:00:00:02"),
                         ISIS::Tlv::IsNeighbors.new("00:00:00:00:00:03")])
    assert_equal %w[00:00:00:00:00:02 00:00:00:00:00:03], hello.neighbors.map(&:to_s)
  end

  # ID Length 2: LI 8 + 1 + 2 + 2 + 2 + 1 + 3 = 19 (13), the Source ID and
  # the LAN ID both scale, and the PDU Length is 19 + 6 = 25 (19).
  def test_two_octet_ids
    hex = "8313010" "20f010000".delete(" ") + "01" "0102" "001e" "0019" "40" "010201" "010403490001"
    pdu = ISIS::Pdu.factory(octets(hex))
    assert_equal "0102", pdu.source_id_s
    assert_equal "0102.01", pdu.lan_id_s
    assert_equal hex, pdu.to_shex
  end

  def test_lan_id_must_be_one_longer_than_the_source_id
    assert_raises(ArgumentError) { built(lan_id: "1921.6800.1001") }
  end

  def test_priority_is_seven_bits
    assert_raises(ArgumentError) { built(priority: 128) }
    assert_equal "7f", built(priority: 127).to_shex[38, 2]
  end

  # Priority octet c0: priority 64 with the reserved bit 8 set, kept,
  # echoed and carried by the hash.
  def test_reserved_priority_bit_is_echoed
    hex = HELLO.sub("002940", "0029c0")
    pdu = ISIS::Pdu.factory(octets(hex))
    assert_equal 64, pdu.priority
    assert_equal 0x80, pdu.priority_reserved_bit
    assert_equal hex, pdu.to_shex
    assert_equal 0x80, pdu.to_hash[:priority_bit]
    assert_equal hex, ISIS::Pdu::LanHello.new(pdu.to_hash).to_shex
  end

  def test_setting_the_priority_keeps_the_reserved_bit
    pdu = ISIS::Pdu.factory(octets(HELLO.sub("002940", "0029c0")))
    pdu.priority = 1
    assert_equal "81", pdu.to_shex[38, 2]
  end

  # Circuit Type octet fd: type 1 with the six reserved bits set.
  def test_reserved_circuit_bits_are_echoed
    hex = COMMON + "fd" + FIXED[2..] + TLVS
    pdu = ISIS::Pdu.factory(octets(hex))
    assert_equal :l1, pdu.circuit_type
    assert_equal hex, pdu.to_shex
    assert_equal hex, ISIS::Pdu::LanHello.new(pdu.to_hash).to_shex
  end

  def test_hash_rebuilds
    assert_equal HELLO, ISIS::Pdu::LanHello.new(built.to_hash).to_shex
    l2 = built(level: 2, circuit_type: :l1l2)
    assert_equal l2.to_shex, ISIS::Pdu::LanHello.new(l2.to_hash).to_shex
  end

  def test_copy_constructor
    assert_equal HELLO, ISIS::Pdu::LanHello.new(built).to_shex
  end

  # A PDU Length of 0x0030 claims more than arrived: replayed as declared,
  # computed again once the content moves.
  def test_declared_length_replays_until_edited
    hex = COMMON + FIXED.sub("0029", "0030") + TLVS
    pdu = ISIS::Pdu.factory(octets(hex))
    assert pdu.preserved?
    assert_equal hex, pdu.to_shex
    pdu.holding_time = 31
    refute pdu.preserved?
    assert_equal "0029", pdu.to_shex[34, 4]
  end

  def test_cut_inside_the_fixed_header_is_truncated
    assert_instance_of ISIS::Pdu::Truncated, ISIS::Pdu.factory(octets(COMMON + FIXED[0, 20]))
  end

  def test_pdu_length_below_the_fixed_header_is_malformed
    hex = COMMON + FIXED.sub("0029", "0005") + TLVS
    pdu = ISIS::Pdu.factory(octets(hex))
    assert_instance_of ISIS::Pdu::Malformed, pdu
    assert_equal hex, pdu.to_shex
  end

  def test_to_s
    assert_equal "L1 LAN hello l1 from 1921.6800.1001, holding 30, priority 64, LAN ID 1921.6800.1001.01, 2 TLVs",
                 built.to_s
  end
end
