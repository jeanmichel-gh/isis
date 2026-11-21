# frozen_string_literal: true

require_relative "../../test_helper"

# ISIS::Mpls::LabelStack, RFC 3032 section 2.1, built the four ways of
# docs/building-objects.md, right and wrong.
class TestMplsLabelStack < Minitest::Test
  LS = ISIS::Mpls::LabelStack

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # 16005 is 0x03e85: shifted 12 is 0x03e85000; 16007 with S, 0x03e87100.
  def test_from_labels
    s = LS.new(16_005, 16_007)
    assert_equal "03e8500003e87100", s.to_shex
    assert_equal [16_005, 16_007], s.labels
    assert_equal [false, true], s.entries.map(&:bottom)
  end

  # Exp in bits 9 to 11, S at 8, TTL in the low octet: 16005, Exp 5, S,
  # TTL 64 is 0x03e85000 | 0xa00 | 0x100 | 0x40.
  def test_every_field_on_the_wire
    s = LS.new(entries: [{ label: 16_005, exp: 5, bottom: true, ttl: 64 }])
    assert_equal "03e85b40", s.to_shex
    back = LS.new(octets("03e85b40"))
    assert_equal [16_005, 5, true, 64], back.entries.first.to_a
  end

  # The four ways give the same object.
  def test_four_ways
    hex = "03e85a4003e87bff"
    parsed = LS.new(octets(hex))
    assert_equal hex, parsed.to_shex
    assert_equal hex, LS.new(parsed.to_hash).to_shex
    assert_equal hex, LS.new(parsed).to_shex
    assert_equal hex, LS.new(entries: parsed.entries.map(&:to_hash)).to_shex
  end

  # Parsing stops after the entry with S and leaves the packet behind it.
  def test_parsing_leaves_the_packet
    o = octets("03e85000" "03e87140" "4500")
    s = LS.new(o)
    assert_equal [16_005, 16_007], s.labels
    assert_equal "4500", o.unpack1("H*")
  end

  # Building never validates: S on the top entry, or on none. Reading the
  # first stops at the top: RFC 3032 section 2.1, "The network layer
  # packet immediately follows the label stack entry which has the S bit
  # set".
  def test_wrong_on_purpose
    s = LS.new(entries: [{ label: 3, bottom: true }, { label: 16_007, bottom: false }])
    assert_equal "0000310003e87000", s.to_shex
    o = octets(s.to_shex)
    assert_equal [3], LS.new(o).labels
    assert_equal "03e87000", o.unpack1("H*")
    none = LS.new(octets("03e8500003e87000"))
    assert_equal [false, false], none.entries.map(&:bottom)
  end

  # Octets that end mid-entry with no S are a stack cut short, kept and
  # written back.
  def test_cut_short
    s = LS.new(octets("03e8500003e8"))
    assert_equal [16_005], s.labels
    assert_equal "03e8", s.tail.unpack1("H*")
    assert_equal "03e8500003e8", s.to_shex
    assert_equal({ entries: [{ label: 16_005, exp: 0, bottom: false, ttl: 0 }], tail: "03e8" }, s.to_hash)
    assert_equal "(label 16005, exp 0, ttl 0) (2 octets cut short)", s.to_s
  end

  # What cannot be represented is refused.
  def test_what_does_not_fit
    assert_raises(ArgumentError) { LS.new(0x100000) }
    assert_raises(ArgumentError) { LS.new(entries: [{ label: 1, exp: 8 }]) }
    assert_raises(ArgumentError) { LS.new(entries: [{ label: 1, ttl: 256 }]) }
  end

  def test_tcpdumps_form
    s = LS.new(entries: [{ label: 16_005, ttl: 64 }, { label: 16_007, bottom: true, ttl: 64 }])
    assert_equal "(label 16005, exp 0, ttl 64) (label 16007, exp 0, [S], ttl 64)", s.to_s
  end

  def test_empty
    assert_equal "", LS.new.encode
    assert_equal({ entries: [] }, LS.new.to_hash)
  end
end
