# frozen_string_literal: true

require_relative "../../test_helper"

# Expected hex here is our own arithmetic from the field layout in
# lib/isis/pdu/pdu.rb and psnp.rb, which is itself second hand (Wireshark
# and FRR, not ISO 10589). When one of these fails, check the expectation
# and the source of the layout as well as the code.
#
# The reference PDU, an L1 PSNP from 1921.6800.1001.00 with one empty
# TLV 9, 19 octets:
#   83 IRPD | 11 Length Indicator, 8 + 9 = 17 | 01 version/PID ext
#   00 ID Length (6) | 1a type 26, L1 PSNP | 01 version | 00 reserved
#   00 max area addresses | 0013 PDU Length 19 | 192168001001 00 Source ID
#   0900 TLV 9, length 0
module PduFixtures
  PSNP = "8311 0100 1a01 0000 0013 1921 6800 1001 00 0900".delete(" ")

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def factory(hex, **kw)
    ISIS::Pdu.factory(octets(hex), **kw)
  end
end

class TestPduIdLength < Minitest::Test
  def test_zero_means_six
    assert_equal 6, ISIS::Pdu.id_width(0)
  end

  def test_255_means_null
    assert_equal 0, ISIS::Pdu.id_width(255)
  end

  def test_other_values_are_the_width
    assert_equal 3, ISIS::Pdu.id_width(3)
    assert_equal 8, ISIS::Pdu.id_width(8)
  end

  def test_width_to_octet
    assert_equal 0, ISIS::Pdu.id_length_for(6)
    assert_equal 255, ISIS::Pdu.id_length_for(0)
    assert_equal 3, ISIS::Pdu.id_length_for(3)
  end
end

class TestPduFactory < Minitest::Test
  include PduFixtures

  def test_implemented_type_parses_into_its_layout_and_replays
    pdu = factory(PSNP)
    assert_instance_of ISIS::Pdu::Psnp, pdu
    assert_equal [9], pdu.tlvs.map(&:type)
    assert_equal PSNP, pdu.to_shex
  end

  def test_level_2_shares_the_layout
    l2 = PSNP.sub(/\A(.{8})1a/, '\11b')
    pdu = factory(l2)
    assert_instance_of ISIS::Pdu::Psnp, pdu
    assert_equal 2, pdu.level
    assert_equal l2, pdu.to_shex
  end

  # Type 19 sits between the two LSP types and is no PDU type at all, so
  # it has no layout and never will. Its body is not framed into TLVs,
  # because nothing establishes that it is TLVs or where they start.
  def test_unimplemented_type_is_opaque_and_replays
    hex = "831b 0100 1301 0000 001d 04b0 1921 6800 1001 0000 0000 0001 0000 03 0800".delete(" ")
    pdu = factory(hex)
    assert_instance_of ISIS::Pdu::Unknown, pdu
    assert_equal 19, pdu.type
    refute_respond_to pdu, :tlvs
    assert_equal hex, pdu.to_shex
    assert_equal "PDU type 19, 29 octets, no layout", pdu.to_s
  end

  # The top three bits of the type octet are reserved. Set, they are kept
  # and echoed: 0xfa is type 26 with all three set.
  def test_reserved_type_bits_are_kept_and_echoed
    hex = PSNP.sub(/\A(.{8})1a/, '\1fa')
    pdu = factory(hex)
    assert_instance_of ISIS::Pdu::Psnp, pdu
    assert_equal 0xe0, pdu.header.reserved_type_bits
    assert_equal hex, pdu.to_shex
  end

  def test_unusual_header_fields_survive_the_hash
    hex = PSNP.sub(/\A(.{8})1a01 00/.source.delete(" ").then { |s| Regexp.new(s) }, '\1fa0207')
    pdu = factory(hex)
    h = pdu.to_hash
    assert_equal({ type_bits: 0xe0, version: 2, reserved: 7 }, h.slice(:type_bits, :version, :reserved))
    assert_equal hex, ISIS::Pdu::Psnp.new(h).to_shex
  end

  # ID Length 3: the Source ID is 3 + 1 octets, so the fixed header is
  # 2 + 4 = 6 octets and the Length Indicator 14 (0e). PDU Length 16.
  def test_id_length_threads_into_the_layout
    hex = "830e 0103 1a01 0000 0010 aabbcc 01 0900".delete(" ")
    pdu = factory(hex)
    assert_equal "aabbcc01", pdu.source_id.unpack1("H*")
    assert_equal hex, pdu.to_shex
  end

  # ID Length 255, a null System ID: the Source ID is the circuit octet
  # alone, and the fixed header is 3 octets.
  def test_null_id
    hex = "830b 01ff 1a01 0000 000d 07 0900".delete(" ")
    pdu = factory(hex)
    assert_equal "07", pdu.source_id.unpack1("H*")
    assert_equal hex, pdu.to_shex
  end
end

# Parse rules 5, 6 and 7 at the PDU level. Every case replays its input.
class TestPduParsePolicy < Minitest::Test
  include PduFixtures

  # Rule 5: the capture stops inside the common header.
  def test_cut_inside_the_common_header
    pdu = factory("8311 0100 1a")
    assert_instance_of ISIS::Pdu::Truncated, pdu
    assert_equal 26, pdu.type
    assert_equal "831101001a", pdu.to_shex
  end

  def test_cut_before_the_type_octet
    pdu = factory("8311")
    assert_instance_of ISIS::Pdu::Truncated, pdu
    assert_nil pdu.type
    assert_equal "8311", pdu.to_shex
  end

  # Rule 5: the common header arrived, the PSNP fixed header did not. No
  # layout is built, because it would invent the missing Source ID octets.
  def test_cut_inside_the_layout_fixed_header
    hex = PSNP[0, 2 * 13]
    pdu = factory(hex)
    assert_instance_of ISIS::Pdu::Truncated, pdu
    assert_equal hex, pdu.to_shex
  end

  # Rule 6: the header is complete and the declared PDU Length, 32 (0020),
  # runs past the capture, which stops after 20 octets, mid-TLV. The layout
  # is built, the TLV is clamped, and the declared 32 is written back.
  def test_declared_length_runs_past_the_capture
    hex = PSNP.sub(/0900\z/, "0905aa").sub(/\A(.{16})0013/, '\10020')
    pdu = factory(hex)
    assert_instance_of ISIS::Pdu::Psnp, pdu
    assert_equal 32, pdu.declared_pdu_length
    assert pdu.tlvs.first.clamped?
    assert_equal hex, pdu.to_shex
  end

  # Rule 6 and 7: the declared PDU Length is shorter than the capture.
  # The PDU consumes its declared 19 octets and no more.
  def test_declared_length_shorter_than_the_capture
    input = octets("#{PSNP}eeff")
    pdu = ISIS::Pdu.factory(input)
    assert_equal PSNP, pdu.to_shex
    assert_equal "eeff", input.to_shex, "the rest is left for the level above"
  end

  # Rule 6: a declared PDU Length below the fixed header, here 5 and 0.
  # There is no honest reading, so the PDU is Malformed and kept whole.
  def test_declared_length_below_the_fixed_header
    [5, 0].each do |declared|
      hex = PSNP.sub(/\A(.{16})0013/, format('\1%04x', declared))
      pdu = factory(hex)
      assert_instance_of ISIS::Pdu::Malformed, pdu
      assert_equal hex, pdu.to_shex
    end
  end

  # Rule 1: a boundary handed to the factory wins over the octets after
  # it. With a boundary of 18 the PSNP has its 17 octet fixed header and
  # one octet of body, 09, which cannot be a TLV and is the body's tail.
  # The declared 19 is kept, and the octets past the boundary are left.
  def test_the_boundary_wins
    input = octets("#{PSNP}0800")
    pdu = ISIS::Pdu.factory(input, boundary: 18)
    assert_instance_of ISIS::Pdu::Psnp, pdu
    assert_equal "09", pdu.tlvs.tail.unpack1("H*")
    assert_equal PSNP[0, 36], pdu.to_shex
    assert_equal "000800", input.to_shex
  end

  # A boundary shorter than the fixed header leaves no room for the
  # layout, so the PDU is Truncated even though more octets follow.
  def test_a_boundary_inside_the_fixed_header_truncates
    pdu = ISIS::Pdu.factory(octets(PSNP), boundary: 15)
    assert_instance_of ISIS::Pdu::Truncated, pdu
    assert_equal PSNP[0, 30], pdu.to_shex
  end

  def test_a_layout_refuses_octets_it_cannot_hold
    assert_raises(ArgumentError) { ISIS::Pdu::Psnp.new(octets(PSNP[0, 20])) }
    assert_raises(ArgumentError) { ISIS::Pdu::Psnp.new(octets(PSNP.sub(/\A(.{16})0013/, '\10005'))) }
  end
end
