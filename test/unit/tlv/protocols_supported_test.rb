# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 129, RFC 1195 section 5.3.1: code 129, one octet per protocol, each an
# ISO/TR 9577 NLPID. The NLPID numbers are second hand (see the class), and
# the expected hex is our own arithmetic.
class TestTlvProtocolsSupported < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # 81 is 129, 01 length, cc IPv4.
  def test_ipv4
    assert_equal "8101cc", ISIS::Tlv::ProtocolsSupported.new(:ipv4).to_shex
  end

  # cc IPv4, 8e IPv6, in the order given.
  def test_dual_stack_keeps_order
    assert_equal "8102cc8e", ISIS::Tlv::ProtocolsSupported.new(:ipv4, :ipv6).to_shex
    assert_equal "81028ecc", ISIS::Tlv::ProtocolsSupported.new(:ipv6, :ipv4).to_shex
  end

  def test_clnp
    assert_equal "810181", ISIS::Tlv::ProtocolsSupported.new(:clnp).to_shex
  end

  def test_numbers_are_accepted
    assert_equal "8102cc07", ISIS::Tlv::ProtocolsSupported.new(0xcc, 7).to_shex
  end

  def test_parse_names_what_it_knows
    tlv = ISIS::Tlv::ProtocolsSupported.new(octets("8103cc8e07"))
    assert_equal [:ipv4, :ipv6, 7], tlv.to_hash
    assert_equal "8103cc8e07", ISIS::Tlv::ProtocolsSupported.new(tlv.to_hash).to_shex
  end

  def test_unknown_name_is_refused
    assert_raises(ArgumentError) { ISIS::Tlv::ProtocolsSupported.new(:appletalk) }
  end

  def test_number_outside_an_octet_is_refused
    assert_raises(ArgumentError) { ISIS::Tlv::ProtocolsSupported.new(256) }
  end

  def test_factory_builds_this_class
    assert_instance_of ISIS::Tlv::ProtocolsSupported, ISIS::Tlv.factory(octets("8101cc"))
  end

  def test_copy_constructor
    tlv = ISIS::Tlv::ProtocolsSupported.new(:ipv4, :ipv6)
    assert_equal "8102cc8e", ISIS::Tlv::ProtocolsSupported.new(tlv).to_shex
  end

  def test_to_s
    assert_equal "Protocols Supported ipv4, 0x07", ISIS::Tlv::ProtocolsSupported.new(:ipv4, 7).to_s
  end
end
