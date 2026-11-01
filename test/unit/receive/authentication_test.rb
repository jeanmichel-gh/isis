# frozen_string_literal: true

require_relative "../../test_helper"

# The receive policy's authentication step, on built hellos: each reason a
# PDU is refused, and nothing checked without a key.
class TestReceiveAuthentication < Minitest::Test
  A = ISIS::Receive::Authentication

  def hello(tlvs, key: nil)
    h = ISIS::Pdu::P2pHello.new(circuit_type: :l1, source_id: "0000.0000.0001", holding_time: 30,
                                local_circuit_id: 1, tlvs: tlvs)
    h.key = key
    ISIS::Pdu.factory(ISIS::Octets.new(h.encode))
  end

  def areas
    [ISIS::Tlv::AreaAddresses.new(["49.0001"])]
  end

  def test_keyed_puts_tlv_10_first_only_with_a_key
    assert_equal [10, 1], A.keyed(areas, "k").map(&:type)
    assert_equal [1], A.keyed(areas, nil).map(&:type)
  end

  def test_no_key_checks_nothing
    assert_nil A.refusal(hello(areas), nil, "clause")
  end

  def test_each_refusal
    assert_match(/no Authentication Information.*clause i/, A.refusal(hello(areas), "k", "clause"))
    cleartext = hello([ISIS::Tlv::Authentication.new(password: "k")] + areas)
    assert_match(/not HMAC-MD5.*clause ii/, A.refusal(cleartext, "k", "clause"))
    wrong = hello(A.keyed(areas, "other"), key: "other")
    assert_match(/digest is wrong.*RFC 5304/, A.refusal(wrong, "k", "clause"))
    assert_nil A.refusal(hello(A.keyed(areas, "k"), key: "k"), "k", "clause")
  end
end
