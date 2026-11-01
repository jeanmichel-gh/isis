# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 6, RFC 1142 clause 9.5: code 6, then six octet LAN addresses. The
# expected hex is our own arithmetic from that clause.
class TestTlvIsNeighbors < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # 06 type, 06 length, then the MAC 00:00:00:00:00:02.
  def test_one_neighbor
    assert_equal "0606000000000002", ISIS::Tlv::IsNeighbors.new("00:00:00:00:00:02").to_shex
  end

  # Two MACs, twelve octets, length 0c.
  def test_two_neighbors
    assert_equal "060c000000000002aabbccddeeff",
                 ISIS::Tlv::IsNeighbors.new("00:00:00:00:00:02", "aa:bb:cc:dd:ee:ff").to_shex
  end

  def test_none_is_an_empty_value
    assert_equal "0600", ISIS::Tlv::IsNeighbors.new([]).to_shex
  end

  def test_parse
    tlv = ISIS::Tlv::IsNeighbors.new(octets("060c000000000002aabbccddeeff"))
    assert_equal ["00:00:00:00:00:02", "aa:bb:cc:dd:ee:ff"], tlv.to_hash
    assert_equal [Datalink::MAC.new("aa:bb:cc:dd:ee:ff")], tlv.neighbors.last(1)
  end

  # The entries are LAN addresses, not System IDs, so an eight octet ID
  # Length does not change them: the factory does not hand this class
  # id_width at all.
  def test_id_length_does_not_reach_it
    assert_empty ISIS::Tlv::IsNeighbors::PARSE_INPUTS
    tlv = ISIS::Tlv.factory(octets("0606000000000002"), id_width: 8)
    assert_equal ["00:00:00:00:00:02"], tlv.to_hash
  end

  # Eight octets: one address and two left over, kept as a tail.
  def test_part_address_is_a_tail
    tlv = ISIS::Tlv::IsNeighbors.new(octets("0608000000000002ffff"))
    assert_equal({ neighbors: ["00:00:00:00:00:02"], tail: "ffff" }, tlv.to_hash)
    assert_equal "0608000000000002ffff", tlv.to_shex
    assert_equal "0608000000000002ffff", ISIS::Tlv::IsNeighbors.new(tlv.to_hash).to_shex
  end

  def test_hash_rebuilds
    tlv = ISIS::Tlv::IsNeighbors.new("00:00:00:00:00:02", "aa:bb:cc:dd:ee:ff")
    assert_equal tlv.to_shex, ISIS::Tlv::IsNeighbors.new(tlv.to_hash).to_shex
  end

  def test_factory_builds_this_class
    assert_instance_of ISIS::Tlv::IsNeighbors, ISIS::Tlv.factory(octets("0606000000000002"))
  end

  def test_copy_constructor
    tlv = ISIS::Tlv::IsNeighbors.new("00:00:00:00:00:02")
    assert_equal "0606000000000002", ISIS::Tlv::IsNeighbors.new(tlv).to_shex
  end

  def test_to_s
    assert_equal "IS Neighbors 00:00:00:00:00:02", ISIS::Tlv::IsNeighbors.new("00:00:00:00:00:02").to_s
  end
end
