# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 137, RFC 5301 section 3: type 137, the length of the value, then the
# name in 7-bit ASCII. The expected hex is our own arithmetic.
class TestTlvDynamicHostname < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # 89 is 137, 02 the length, 7231 "r1".
  def test_name
    assert_equal "89027231", ISIS::Tlv::DynamicHostname.new("r1").to_shex
  end

  # 0a is ten octets: "isis4r-one".
  def test_longer_name
    assert_equal "890a" + "isis4r-one".unpack1("H*"), ISIS::Tlv::DynamicHostname.new("isis4r-one").to_shex
  end

  # The length counts octets, not characters: "é" is two octets in UTF-8.
  def test_length_counts_octets
    tlv = ISIS::Tlv::DynamicHostname.new("ré")
    assert_equal "890372c3a9", tlv.to_shex
    assert_equal Encoding::BINARY, tlv.name.encoding
  end

  # An empty name is outside RFC 5301's 1 to 255, and still builds.
  def test_empty_name_builds
    assert_equal "8900", ISIS::Tlv::DynamicHostname.new("").to_shex
  end

  def test_name_over_255_octets_is_refused
    assert_raises(ArgumentError) { ISIS::Tlv::DynamicHostname.new("a" * 256).to_shex }
  end

  def test_parse_and_hash
    tlv = ISIS::Tlv::DynamicHostname.new(octets("8903667272"))
    assert_equal "frr", tlv.to_hash
    assert_equal "8903667272", ISIS::Tlv::DynamicHostname.new(tlv.to_hash).to_shex
  end

  def test_parse_keeps_octets_that_are_not_ascii
    assert_equal "8902ff00", ISIS::Tlv::DynamicHostname.new(octets("8902ff00")).to_shex
  end

  # A declared length past the PDU's end is clamped and written back as
  # declared (parse rules 1 and 2).
  def test_overrunning_length_replays
    tlv = ISIS::Tlv.factory(octets("89057231"))
    assert tlv.clamped?
    assert_equal "r1", tlv.to_hash
    assert_equal "89057231", tlv.to_shex
  end

  def test_factory_builds_this_class
    assert_instance_of ISIS::Tlv::DynamicHostname, ISIS::Tlv.factory(octets("89027231"))
  end

  def test_copy_constructor
    assert_equal "89027231", ISIS::Tlv::DynamicHostname.new(ISIS::Tlv::DynamicHostname.new("r1")).to_shex
  end

  def test_to_s
    assert_equal "Hostname r1", ISIS::Tlv::DynamicHostname.new("r1").to_s
  end
end
