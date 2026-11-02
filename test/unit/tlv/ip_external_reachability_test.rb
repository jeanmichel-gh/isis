# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 130, RFC 1195 section 5.3.5, laid out as TLV 128. Our own arithmetic,
# field by field.
class TestTlvIpExternalReachability < Minitest::Test
  # 82 type 130, 0c length 12, 0a default metric 10, 80 80 80 delay,
  # expense and error unsupported (S set), c6120500 the address 198.18.5.0,
  # ffffff00 the mask.
  HEX = "820c" "0a808080" "c6120500" "ffffff00"

  def octets(hex) = ISIS::Octets.from_hex(hex)

  def test_parses_and_replays
    t = ISIS::Tlv.factory(octets(HEX))
    assert_instance_of ISIS::Tlv::IpExternalReachability, t
    assert_equal [{ prefix: "198.18.5.0/24", metric: 10 }], t.to_hash
    assert_equal HEX, t.to_shex
  end

  def test_built_from_fields_and_hash
    t = ISIS::Tlv::IpExternalReachability.new(prefix: "198.18.5.0/24", metric: 10)
    assert_equal HEX, t.to_shex
    assert_equal HEX, ISIS::Tlv::IpExternalReachability.new(t.to_hash).to_shex
  end

  # The external metric type is I/E, bit 7 of the default octet: 0x40, so
  # 4a for 10.
  def test_external_metric_type
    t = ISIS::Tlv::IpExternalReachability.new(prefix: "198.18.5.0/24", metric: 10, external: true)
    assert_equal "820c" "4a808080" "c6120500" "ffffff00", t.to_shex
    assert t.entries.first.metrics.external?
  end

  # The up/down bit is bit 8 of the default octet, 0x80 (RFC 5302 section
  # 2). Arrived set, it is read, the metric is still 10, and it replays.
  def test_up_down_bit
    hex = "820c" "8a808080" "c6120500" "ffffff00"
    t = ISIS::Tlv.factory(octets(hex))
    assert t.entries.first.up_down?
    refute ISIS::Tlv.factory(octets(HEX)).entries.first.up_down?
    assert_equal 10, t.entries.first.metrics.default
    assert_equal hex, t.to_shex
    assert_equal hex, ISIS::Tlv::IpExternalReachability.new(t.to_hash).to_shex
  end

  def test_to_s_names_it
    assert_match(/\AIP External Reachability 198\.18\.5\.0\/24 metric 10/, ISIS::Tlv.factory(octets(HEX)).to_s)
  end

  def test_copy_constructor
    t = ISIS::Tlv.factory(octets(HEX))
    assert_equal HEX, ISIS::Tlv::IpExternalReachability.new(t).to_shex
  end
end
