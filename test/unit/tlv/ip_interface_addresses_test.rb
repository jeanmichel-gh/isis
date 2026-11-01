# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 132, RFC 1195 section 5.3.1: code 132, four octets per address.
# Expected hex is our own arithmetic.
class TestTlvIpInterfaceAddresses < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # 84 is 132, 04 length, 0a000001 is 10.0.0.1.
  def test_one_address
    assert_equal "84040a000001", ISIS::Tlv::IpInterfaceAddresses.new("10.0.0.1").to_shex
  end

  # c0a80101 is 192.168.1.1.
  def test_two_addresses
    assert_equal "84080a000001c0a80101",
                 ISIS::Tlv::IpInterfaceAddresses.new("10.0.0.1", "192.168.1.1").to_shex
  end

  def test_parse
    tlv = ISIS::Tlv::IpInterfaceAddresses.new(octets("84080a000001c0a80101"))
    assert_equal ["10.0.0.1", "192.168.1.1"], tlv.to_hash
  end

  # Five octets: one address and one left over, kept as a tail.
  def test_part_address_is_a_tail
    tlv = ISIS::Tlv::IpInterfaceAddresses.new(octets("84050a000001ff"))
    assert_equal({ addresses: ["10.0.0.1"], tail: "ff" }, tlv.to_hash)
    assert_equal "84050a000001ff", tlv.to_shex
    assert_equal "84050a000001ff", ISIS::Tlv::IpInterfaceAddresses.new(tlv.to_hash).to_shex
  end

  def test_hash_rebuilds
    tlv = ISIS::Tlv::IpInterfaceAddresses.new("10.0.0.1", "192.168.1.1")
    assert_equal tlv.to_shex, ISIS::Tlv::IpInterfaceAddresses.new(tlv.to_hash).to_shex
  end

  def test_prefix_and_ipv6_are_refused
    assert_raises(ArgumentError) { ISIS::Tlv::IpInterfaceAddresses.new("10.0.0.0/24") }
    assert_raises(ArgumentError) { ISIS::Tlv::IpInterfaceAddresses.new("2001:db8::1") }
  end

  def test_factory_builds_this_class
    assert_instance_of ISIS::Tlv::IpInterfaceAddresses, ISIS::Tlv.factory(octets("84040a000001"))
  end

  def test_copy_constructor
    tlv = ISIS::Tlv::IpInterfaceAddresses.new("10.0.0.1")
    assert_equal "84040a000001", ISIS::Tlv::IpInterfaceAddresses.new(tlv).to_shex
  end

  def test_to_s
    assert_equal "IP Interface Addresses 10.0.0.1", ISIS::Tlv::IpInterfaceAddresses.new("10.0.0.1").to_s
  end
end
