# frozen_string_literal: true

require_relative "../../test_helper"

# The four original metric octets. Each mask is asserted against the bit
# the clauses give, bit 1 the least significant (RFC 1142 clause 9.1):
# bit 8 is 0x80, bit 7 is 0x40, the value the low six bits.
class TestNarrowMetrics < Minitest::Test
  M = ISIS::Tlv::NarrowMetrics

  def test_masks
    assert_equal 0x80, M::S
    assert_equal 0x40, M::IE
    assert_equal 0x3f, M::VALUE
  end

  def test_masks_tile_the_octet
    masks = [M::S, M::IE, M::VALUE]
    assert_equal 0xff, masks.reduce(:|)
    masks.combination(2).each { |a, b| assert_equal 0, a & b }
  end

  # S set means not supported, so an unsupported metric reads as nil and a
  # supported one of 0 reads as 0.
  def test_s_set_means_unsupported
    m = M.new(["0a800080"].pack("H*"))
    assert_nil m.value(:delay)
    assert_equal 0, m.value(:expense)
    assert_nil m.value(:error)
  end

  def test_build
    assert_equal "0a808080", M.build(metric: 10, ie_octets: [0]).octets.unpack1("H*")
    assert_equal "3f010203", M.build(metric: 63, delay: 1, expense: 2, error: 3, ie_octets: [0]).octets.unpack1("H*")
  end

  def test_the_default_is_never_unsupported
    assert_equal 0x0a, M.new(["8a808080"].pack("H*")).default
    assert_raises(ArgumentError) { M.build(metric: nil, ie_octets: [0]) }
  end

  def test_canonical
    assert M.new(["0a808080"].pack("H*")).canonical?([0])
    refute M.new(["8a808080"].pack("H*")).canonical?([0])
    refute M.new(["0ac08080"].pack("H*")).canonical?([0]), "bit 7 of delay is reserved in TLV 128"
    refute M.new(["4ac08080"].pack("H*")).canonical?([0, 1, 2, 3]), "TLV 2 has I/E in all four"
    assert M.new(["4ac0c0c0"].pack("H*")).canonical?([0, 1, 2, 3])
  end
end
