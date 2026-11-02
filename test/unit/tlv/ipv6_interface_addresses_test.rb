# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 232, RFC 5308 section 3: TLV 132's shape with 16 octet IPv6
# addresses. Expected hex is our own arithmetic.
class TestTlvIpv6InterfaceAddresses < Minitest::Test
  LINK_LOCAL = "fe800000000000000000000000000001" # fe80::1
  GLOBAL = "20010db8000000000000000000000001"     # 2001:db8::1

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # e8 is 232, 10 is 16 octets.
  def test_one_address
    assert_equal "e810#{LINK_LOCAL}", ISIS::Tlv::Ipv6InterfaceAddresses.new("fe80::1").to_shex
  end

  def test_two_addresses_parse
    tlv = ISIS::Tlv::Ipv6InterfaceAddresses.new(octets("e820#{LINK_LOCAL}#{GLOBAL}"))
    assert_equal ["fe80::1", "2001:db8::1"], tlv.to_hash
  end

  # Seventeen octets: one address and one left over, kept as a tail.
  def test_part_address_is_a_tail
    tlv = ISIS::Tlv::Ipv6InterfaceAddresses.new(octets("e811#{LINK_LOCAL}ff"))
    assert_equal({ addresses: ["fe80::1"], tail: "ff" }, tlv.to_hash)
    assert_equal "e811#{LINK_LOCAL}ff", tlv.to_shex
    assert_equal "e811#{LINK_LOCAL}ff", ISIS::Tlv::Ipv6InterfaceAddresses.new(tlv.to_hash).to_shex
  end

  def test_hash_rebuilds
    tlv = ISIS::Tlv::Ipv6InterfaceAddresses.new("fe80::1", "2001:db8::1")
    assert_equal tlv.to_shex, ISIS::Tlv::Ipv6InterfaceAddresses.new(tlv.to_hash).to_shex
  end

  def test_prefix_and_ipv4_are_refused
    assert_raises(ArgumentError) { ISIS::Tlv::Ipv6InterfaceAddresses.new("2001:db8::/64") }
    assert_raises(ArgumentError) { ISIS::Tlv::Ipv6InterfaceAddresses.new("10.0.0.1") }
  end

  def test_factory_builds_this_class
    assert_instance_of ISIS::Tlv::Ipv6InterfaceAddresses, ISIS::Tlv.factory(octets("e810#{LINK_LOCAL}"))
  end

  def test_copy_constructor
    tlv = ISIS::Tlv::Ipv6InterfaceAddresses.new("fe80::1")
    assert_equal "e810#{LINK_LOCAL}", ISIS::Tlv::Ipv6InterfaceAddresses.new(tlv).to_shex
  end

  def test_to_s
    assert_equal "IPv6 Interface Addresses fe80::1", ISIS::Tlv::Ipv6InterfaceAddresses.new("fe80::1").to_s
  end
end
