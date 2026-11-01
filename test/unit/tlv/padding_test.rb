# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 8, RFC 1142 clause 9.5: code 8, a length that "may be zero", then
# "LENGTH octets of arbitrary value". Expected hex is our own arithmetic.
class TestTlvPadding < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # 08 type, 03 length, three zero octets.
  def test_built_from_a_length_is_zeros
    assert_equal "0803000000", ISIS::Tlv::Padding.new(3).to_shex
  end

  def test_zero_length
    assert_equal "0800", ISIS::Tlv::Padding.new.to_shex
  end

  def test_arbitrary_value_is_kept
    tlv = ISIS::Tlv::Padding.new(octets("0802abcd"))
    assert_equal "0802abcd", tlv.to_shex
    assert_equal({ value: "abcd" }, tlv.to_hash)
    assert_equal "0802abcd", ISIS::Tlv::Padding.new(tlv.to_hash).to_shex
  end

  def test_zero_padding_hashes_as_a_length
    tlv = ISIS::Tlv::Padding.new(octets("08020000"))
    assert_equal({ length: 2 }, tlv.to_hash)
    assert_equal "08020000", ISIS::Tlv::Padding.new(tlv.to_hash).to_shex
  end

  def test_value_keyword
    assert_equal "0801ff", ISIS::Tlv::Padding.new(value: "\xff".b).to_shex
  end

  def test_factory_builds_this_class
    assert_instance_of ISIS::Tlv::Padding, ISIS::Tlv.factory(octets("0800"))
  end

  def test_copy_constructor
    assert_equal "0802abcd", ISIS::Tlv::Padding.new(ISIS::Tlv::Padding.new(octets("0802abcd"))).to_shex
  end

  def test_to_s
    assert_equal "Padding, 3 octets", ISIS::Tlv::Padding.new(3).to_s
  end
end
