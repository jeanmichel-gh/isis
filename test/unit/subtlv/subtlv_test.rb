# frozen_string_literal: true

require_relative "../../test_helper"

# Sub-TLV framing and the per parent registry. With no sub-TLV classes
# implemented yet, everything reads as SubTlv::Unknown, which is what lets
# a capture with any sub-TLV in it replay.
class TestSubTlv < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def test_unknown_under_a_parent_replays
    list = ISIS::SubTlv::List.parse_under(135, octets("01040000002a" "02020102"))
    assert_equal [1, 2], list.map(&:type)
    assert(list.all? { |s| s.is_a?(ISIS::SubTlv::Unknown) })
    assert_equal "01040000002a02020102", list.to_shex
  end

  # The boundary is the parent's: a sub-TLV past it is clamped, and one
  # octet left is a tail, never a loop.
  def test_boundary_wins
    list = ISIS::SubTlv::List.parse_under(135, octets("0105000000" "ff"), boundary: 5)
    assert list.first.clamped?
    assert_equal "0105000000", list.to_shex

    list = ISIS::SubTlv::List.parse_under(135, octets("010100" "ee"))
    assert_equal "ee", list.tail.unpack1("H*")
  end

  def test_list_hash_rebuilds
    list = ISIS::SubTlv::List.parse_under(135, octets("01040000002a"))
    again = ISIS::SubTlv::List.new(135, list.to_hash)
    assert_equal "01040000002a", again.to_shex
    assert_equal 135, again.parent
  end

  def test_a_key_not_registered_under_the_parent_is_refused
    assert_raises(ArgumentError) { ISIS::SubTlv::List.new(135, { tlvs: [{ admin_tag: [1] }] }) }
  end

  def test_to_s_says_sub_tlv
    assert_equal "sub-TLV 1, 4 octets", ISIS::SubTlv::List.parse_under(135, octets("01040000002a")).first.to_s
  end
end
