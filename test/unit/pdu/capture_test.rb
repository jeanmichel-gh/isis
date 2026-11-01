# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "pdu_test"

# Parse rule 7: a PDU replays its consumed slice, and the capture above it
# owns what came after and replays the whole input.
class TestCapture < Minitest::Test
  include PduFixtures

  def capture(hex)
    ISIS::Capture.new(octets(hex))
  end

  def test_exact_pdu_has_no_tail
    c = capture(PSNP)
    assert_instance_of ISIS::Pdu::Psnp, c.pdu
    assert_empty c.tail
    assert_equal PSNP, c.to_shex
  end

  # Link padding after a PDU whose declared length is shorter than the
  # frame: the PDU takes its 19 octets, the capture keeps the rest.
  def test_padding_after_the_pdu_is_the_capture_tail
    c = capture("#{PSNP}000000")
    assert_equal PSNP, c.pdu.to_shex
    assert_equal "000000", c.tail.unpack1("H*")
    assert_equal "#{PSNP}000000", c.to_shex
    assert_equal "L1 PSNP from 1921.6800.1001.00, 1 TLVs, then 3 octets after it", c.to_s
  end

  def test_every_kind_of_pdu_replays_through_a_capture
    ["8311", PSNP[0, 26], PSNP.sub(/\A(.{16})0013/, '\10000'), "831b01001201#{'00' * 20}"].each do |hex|
      assert_equal hex, capture(hex).to_shex
    end
  end

  def test_hash_round_trip
    c = capture("#{PSNP}0000")
    assert_equal "#{PSNP}0000", ISIS::Capture.new(c.to_hash).to_shex
  end

  def test_hash_refuses_a_class_that_is_not_a_pdu
    assert_raises(ArgumentError) { ISIS::Capture.new({ pdu: {}, pdu_class: "String" }) }
  end

  def test_from_fields
    pdu = ISIS::Pdu.factory(octets(PSNP))
    assert_equal "#{PSNP}ff", ISIS::Capture.new(pdu, "\xff".b).to_shex
  end
end
