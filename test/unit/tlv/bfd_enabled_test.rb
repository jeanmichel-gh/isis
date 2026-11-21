# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 148, BFD-Enabled, RFC 6213 section 6: type 148, a length of 3 to 255,
# and per entry two octets of four reserved bits and a 12 bit MTID, then one
# NLPID octet. The NLPIDs are TLV 129's, cc IPv4 and 8e IPv6. The expected
# hex is our own arithmetic from the section's figure.
class TestTlvBfdEnabled < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def test_codepoint
    assert_equal 148, ISIS::TLV_BFD_ENABLED
    assert_equal 148, ISIS::Tlv::BfdEnabled::TYPE
  end

  # 94 is 148, 03 length, 0000 MTID 0, cc IPv4.
  def test_ipv4
    assert_equal "94030000cc", ISIS::Tlv::BfdEnabled.new([0, :ipv4]).to_shex
  end

  # Two entries, 6 octets: 0000 cc, 0000 8e.
  def test_ipv4_and_ipv6
    assert_equal "94060000cc00008e", ISIS::Tlv::BfdEnabled.new([0, :ipv4], [0, :ipv6]).to_shex
    assert_equal "94060000cc00008e", ISIS::Tlv::BfdEnabled.new([[0, :ipv4], [0, :ipv6]]).to_shex
  end

  # MTID 2, IPv6 unicast (RFC 5120), is 0002; the widest MTID is 0fff.
  def test_mtid_takes_twelve_bits
    assert_equal "94030002 8e".delete(" "), ISIS::Tlv::BfdEnabled.new([2, :ipv6]).to_shex
    assert_equal "94030fffcc", ISIS::Tlv::BfdEnabled.new([4095, 0xcc]).to_shex
    assert_raises(ArgumentError) { ISIS::Tlv::BfdEnabled.new([4096, :ipv4]) }
  end

  def test_unknown_nlpid_name_is_refused
    assert_raises(ArgumentError) { ISIS::Tlv::BfdEnabled.new([0, :appletalk]) }
    assert_raises(ArgumentError) { ISIS::Tlv::BfdEnabled.new([0, 256]) }
  end

  # The reserved bits arrive set in f002: kept, echoed, and in the hash.
  def test_reserved_bits_are_kept_and_echoed
    tlv = ISIS::Tlv::BfdEnabled.new(octets("9403f002cc"))
    assert_equal [{ mtid: 2, nlpid: :ipv4, reserved: 15 }], tlv.to_hash
    assert_equal "9403f002cc", tlv.to_shex
    assert_equal "9403f002cc", ISIS::Tlv::BfdEnabled.new(tlv.to_hash).to_shex
  end

  # Four octets: one entry, and one octet over, kept as a tail.
  def test_tail
    tlv = ISIS::Tlv::BfdEnabled.new(octets("94040000cc07"))
    assert_equal [[0, 0xcc]], tlv.pairs
    assert_equal({ entries: [{ mtid: 0, nlpid: :ipv4 }], tail: "07" }, tlv.to_hash)
    assert_equal "94040000cc07", ISIS::Tlv::BfdEnabled.new(tlv.to_hash).to_shex
  end

  def test_parse_and_hash
    tlv = ISIS::Tlv::BfdEnabled.new(octets("94060000cc000007"))
    assert_equal [[0, 0xcc], [0, 7]], tlv.pairs
    assert_equal [{ mtid: 0, nlpid: :ipv4 }, { mtid: 0, nlpid: 7 }], tlv.to_hash
    assert_equal "94060000cc000007", ISIS::Tlv::BfdEnabled.new(tlv.to_hash).to_shex
  end

  def test_factory_builds_this_class
    assert_instance_of ISIS::Tlv::BfdEnabled, ISIS::Tlv.factory(octets("94030000cc"))
  end

  def test_copy_constructor
    tlv = ISIS::Tlv::BfdEnabled.new([0, :ipv4], [0, :ipv6])
    assert_equal "94060000cc00008e", ISIS::Tlv::BfdEnabled.new(tlv).to_shex
  end

  def test_to_s
    assert_equal "BFD Enabled MTID 0 ipv4, MTID 0 0x07", ISIS::Tlv::BfdEnabled.new([0, :ipv4], [0, 7]).to_s
  end
end
