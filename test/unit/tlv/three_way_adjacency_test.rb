# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 240, RFC 5303 section 3.1: type f0, then the state octet (0 Up, 1
# Initializing, 2 Down), a 4 octet Extended Local Circuit ID, an ID Length
# octet Neighbor System ID, and a 4 octet Neighbor Extended Local Circuit
# ID. The expected hex is our own arithmetic from that section.
class TestTlvThreeWayAdjacency < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # f0, 01 length, 02 Down: the state alone.
  def test_state_only
    assert_equal "f00102", ISIS::Tlv::ThreeWayAdjacency.new(:down).to_shex
  end

  # The state numbers, each asserted against the section, not the table.
  def test_state_numbers
    assert_equal "f00100", ISIS::Tlv::ThreeWayAdjacency.new(:up).to_shex
    assert_equal "f00101", ISIS::Tlv::ThreeWayAdjacency.new(:initializing).to_shex
    assert_equal "f00102", ISIS::Tlv::ThreeWayAdjacency.new(:down).to_shex
  end

  # Down, as sent before the neighbour is known: f0 05 02, circuit 00000001.
  def test_down_with_circuit
    assert_equal "f0050200000001", ISIS::Tlv::ThreeWayAdjacency.new(:down, extended_circuit_id: 1).to_shex
  end

  # Up with the neighbour known: f0, 0f (15 = 1 + 4 + 6 + 4), 00 Up,
  # 00000001, 192168001001, 00000007.
  FULL = "f00f0000000001192168001001" + "00000007"

  def full
    ISIS::Tlv::ThreeWayAdjacency.new(:up, extended_circuit_id: 1, neighbor_system_id: "1921.6800.1001",
                                          neighbor_extended_circuit_id: 7)
  end

  def test_all_fields
    assert_equal FULL, full.to_shex
  end

  def test_parse_all_fields
    tlv = ISIS::Tlv::ThreeWayAdjacency.new(octets(FULL))
    assert_equal :up, tlv.state
    assert_equal 1, tlv.extended_circuit_id
    assert_equal "192168001001", tlv.neighbor_system_id.unpack1("H*")
    assert_equal 7, tlv.neighbor_extended_circuit_id
    assert_equal FULL, tlv.to_shex
  end

  # Eleven octets of value: with six octet IDs, the neighbour ID and no
  # neighbour circuit. With two octet IDs, the same octets are a neighbour
  # ID and a circuit ID. The ID width decides, not the length.
  def test_id_width_decides_the_neighbor_fields
    hex = "f00b0000000001192168001001"
    six = ISIS::Tlv::ThreeWayAdjacency.new(octets(hex))
    assert_equal "192168001001", six.neighbor_system_id.unpack1("H*")
    assert_nil six.neighbor_extended_circuit_id

    two = ISIS::Tlv::ThreeWayAdjacency.new(octets(hex), id_width: 2)
    assert_equal "1921", two.neighbor_system_id.unpack1("H*")
    assert_equal 0x68001001, two.neighbor_extended_circuit_id
    assert_equal hex, two.to_shex
  end

  def test_factory_passes_the_id_width
    tlv = ISIS::Tlv.factory(octets("f00b0000000001192168001001"), id_width: 2)
    assert_equal "1921", tlv.neighbor_system_id.unpack1("H*")
  end

  # A PSNP whose ID Length is 8 carries a TLV 240 with an eight octet
  # neighbour ID. The width reaches the TLV from the common header.
  # 83 11 01 08 1a 01 00 00: ID Length 08, so the fixed header is
  # 8 + 2 + 9 = 19 (0x13) octets; PDU Length 0x0028 = 19 + 21; Source ID
  # 9 octets; then f0 13 (19 = 1 + 4 + 8 + 4) 00 00000001
  # 0102030405060708 00000002.
  def test_id_length_threads_from_the_pdu_header
    hex = "831301081a010000" "0028" "192168001001000000" \
          "f0130000000001" "0102030405060708" "00000002"
    pdu = ISIS::Pdu.factory(octets(hex))
    tlv = pdu.tlvs.first
    assert_instance_of ISIS::Tlv::ThreeWayAdjacency, tlv
    assert_equal "0102030405060708", tlv.neighbor_system_id.unpack1("H*")
    assert_equal 2, tlv.neighbor_extended_circuit_id
    assert_equal hex, pdu.to_shex
  end

  def test_copy_keeps_the_width_it_was_read_with
    tlv = ISIS::Tlv::ThreeWayAdjacency.new(octets("f00b0000000001192168001001"), id_width: 2)
    assert_equal 0x68001001, ISIS::Tlv::ThreeWayAdjacency.new(tlv).neighbor_extended_circuit_id
  end

  def test_list_copy_keeps_the_width
    list = ISIS::Tlv::List.new(octets("f00b0000000001192168001001"), id_width: 2)
    assert_equal "1921", ISIS::Tlv::List.new(list).first.neighbor_system_id.unpack1("H*")
  end

  # A state RFC 5303 does not define is kept as a number: discarding the
  # PDU is the receive policy's call.
  def test_unknown_state_is_kept
    tlv = ISIS::Tlv::ThreeWayAdjacency.new(octets("f00107"))
    assert_equal 7, tlv.state
    assert_equal "f00107", tlv.to_shex
  end

  # Three octets after the state cannot be a circuit ID: a tail.
  def test_part_field_is_a_tail
    tlv = ISIS::Tlv::ThreeWayAdjacency.new(octets("f00402aabbcc"))
    assert_nil tlv.extended_circuit_id
    assert_equal({ state: :down, tail: "aabbcc" }, tlv.to_hash)
    assert_equal "f00402aabbcc", ISIS::Tlv::ThreeWayAdjacency.new(tlv.to_hash).to_shex
  end

  def test_empty_value_replays
    assert_equal "f000", ISIS::Tlv::ThreeWayAdjacency.new(octets("f000")).to_shex
  end

  def test_hash_rebuilds_every_field
    h = full.to_hash
    assert_equal({ state: :up, extended_circuit_id: 1, neighbor_system_id: "1921.6800.1001",
                   neighbor_extended_circuit_id: 7 }, h)
    assert_equal FULL, ISIS::Tlv::ThreeWayAdjacency.new(h).to_shex
  end

  def test_copy_constructor
    assert_equal FULL, ISIS::Tlv::ThreeWayAdjacency.new(full).to_shex
  end

  def test_refusals
    assert_raises(ArgumentError) { ISIS::Tlv::ThreeWayAdjacency.new(:sideways) }
    assert_raises(ArgumentError) { ISIS::Tlv::ThreeWayAdjacency.new(:up, extended_circuit_id: 2**32) }
    assert_raises(ArgumentError) { ISIS::Tlv::ThreeWayAdjacency.new(:up, neighbor_system_id: "abc") }
  end

  def test_other_tlvs_do_not_take_the_width
    assert_raises(ArgumentError) { ISIS::Tlv::Padding.new(octets("0800"), id_width: 6) }
  end

  def test_to_s
    assert_equal "Three-Way Adjacency up, circuit 1, neighbor 1921.6800.1001, neighbor circuit 7", full.to_s
  end
end
