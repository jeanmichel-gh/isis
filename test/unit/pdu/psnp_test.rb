# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "pdu_test"

# The PSNP layout and the computed length fields: computed on build,
# replayed on parse, recomputed once something moves. CLAUDE.md, "Computed
# fields". Expected hex is our own arithmetic; see pdu_test.rb.
class TestPsnp < Minitest::Test
  include PduFixtures

  def built
    ISIS::Pdu::Psnp.new(level: 1, source_id: "1921.6800.1001.00", tlvs: [ISIS::Tlv::Unknown.new(9, "")])
  end

  def test_built_from_fields
    assert_equal PSNP, built.to_shex
  end

  def test_level_2_writes_type_27
    psnp = ISIS::Pdu::Psnp.new(level: 2, source_id: "1921.6800.1001.00")
    assert_equal "1b", psnp.to_shex[8, 2]
  end

  def test_level_must_be_1_or_2
    assert_raises(ArgumentError) { ISIS::Pdu::Psnp.new(level: 3, source_id: "1921.6800.1001.00") }
  end

  # The Length Indicator is the fixed header, 17. The PDU Length is the
  # whole PDU, 19. Swapping the two fails this test.
  def test_length_indicator_and_pdu_length_are_different_fields
    o = built.encode
    assert_equal 17, o.getbyte(1), "Length Indicator"
    assert_equal 19, o.byteslice(8, 2).unpack1("n"), "PDU Length"
  end

  def test_buffer_is_binary
    assert_equal Encoding::BINARY, built.encode.encoding
  end

  def test_hash_round_trip
    h = built.to_hash
    assert_equal({ type: :l1_psnp, source_id: "1921.6800.1001.00", tlvs: [{ unknown: { type: 9, value: "" } }] }, h)
    assert_equal PSNP, ISIS::Pdu::Psnp.new(h).to_shex
  end

  def test_copy_constructor
    assert_equal PSNP, ISIS::Pdu::Psnp.new(built).to_shex
  end

  def test_to_s
    assert_equal "L1 PSNP from 1921.6800.1001.00, 1 TLVs", built.to_s
  end

  def test_built_pdu_is_not_preserved
    refute built.preserved?
  end

  # A capture whose lengths lie, here a Length Indicator of 0xee and a PDU
  # Length that matches, replays them exactly. It does so because it kept
  # them, not because recomputing happened to agree: recomputing would
  # write 0x11.
  def test_parsed_lies_are_replayed
    hex = PSNP.sub(/\A83 ?11/, "83ee")
    pdu = factory(hex)
    assert pdu.preserved?
    assert_equal hex, pdu.to_shex
  end

  # A same size edit several levels down: the TLV's value changes, its
  # length does not. The lengths still describe what exists, but the
  # octets moved, so the lie is no longer replayed and both are computed.
  def test_a_same_size_edit_below_recomputes
    hex = PSNP.sub(/0900\z/, "0901aa").sub(/0013/, "0014").sub(/\A8311/, "83ee")
    pdu = factory(hex)
    # TLV 9 with one octet holds no whole entry, so the octet is its tail.
    pdu.tlvs.first.tail = "\xbb".b
    refute pdu.preserved?
    assert_equal "8311", pdu.to_shex[0, 4]
    assert_equal "0014", pdu.to_shex[16, 4]
  end

  def test_an_edit_that_changes_size_recomputes_the_pdu_length
    pdu = factory(PSNP)
    pdu.tlvs << ISIS::Tlv::Unknown.new(9, "\x01\x02")
    refute pdu.preserved?
    assert_equal 23, pdu.encode.byteslice(8, 2).unpack1("n")
  end

  def test_a_header_edit_recomputes
    pdu = factory(PSNP.sub(/\A8311/, "83ee"))
    pdu.header.max_area_addresses = 3
    refute pdu.preserved?
    assert_equal "8311", pdu.to_shex[0, 4]
  end

  def test_recompute_bang_forces_the_issue
    pdu = factory(PSNP.sub(/\A8311/, "83ee"))
    pdu.recompute!
    refute pdu.preserved?
    assert_equal PSNP, pdu.to_shex
  end

  # A self triggering pair of computed fields passes the tests above and
  # fails this one.
  def test_two_consecutive_encodes_are_identical
    pdu = factory(PSNP.sub(/\A8311/, "83ee"))
    assert_equal pdu.to_shex, pdu.to_shex
    pdu.tlvs << ISIS::Tlv::Unknown.new(8, "")
    assert_equal pdu.to_shex, pdu.to_shex
  end

  # A deliberately wrong PDU built from scratch lies through a singleton
  # override on the one object, not through an option in the library.
  def test_a_lie_from_scratch_is_a_singleton_override
    pdu = built
    pdu.define_singleton_method(:encode) do
      s = super()
      s[8, 2] = [9999].pack("n")
      s
    end
    assert_equal "270f", pdu.to_shex[16, 4]
    assert_equal "0013", built.to_shex[16, 4], "the class is unchanged"
  end
end
