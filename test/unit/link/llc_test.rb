# frozen_string_literal: true

require_relative "../../test_helper"

class TestLinkLlc < Minitest::Test
  # The IS-IS LLC header is DSAP 0xFE, SSAP 0xFE, control 0x03 (UI).
  # Expected hex is our arithmetic from that, not a spec worked example.
  def test_llc_header_bytes
    assert_equal "fefe03", ISIS::Link.llc.wrap("".b).unpack1("H*")
  end

  def test_isis_llc_recognised
    assert ISIS::Link.isis_llc?("\xFE\xFE\x03\x83".b)
  end

  def test_other_sap_rejected
    refute ISIS::Link.isis_llc?("\xAA\xAA\x03".b)
  end

  # DSAP right, SSAP wrong: both octets must be the IS-IS SAP.
  def test_wrong_ssap_rejected
    refute ISIS::Link.isis_llc?("\xFE\xAA\x03".b)
  end

  def test_short_sdu_rejected
    refute ISIS::Link.isis_llc?("\xFE".b)
  end

  def test_all_iss_per_level
    assert_equal Datalink::MAC.new("01:80:c2:00:00:14"), ISIS::Link.all_iss(1)
    assert_equal Datalink::MAC.new("01:80:c2:00:00:15"), ISIS::Link.all_iss(2)
  end
end
