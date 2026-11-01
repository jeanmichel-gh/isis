# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 10, RFC 1142 clause 9.5 and RFC 5304 section 2. The first
# expectation is FRR's: the TLV 10 in
# test/fixtures/frr-8.4.4-l1-lsp-hmac-md5.hex. The rest is our own
# arithmetic.
class TestTlvAuthentication < Minitest::Test
  # 0a type 10, 11 length 17, 36 type 54 HMAC-MD5, then the 16 octets of
  # FRR's digest.
  FRR = "0a11" "36" "73307044833e1740d9c6589364c6f36d"

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def test_frr_tlv_parses_and_replays
    t = ISIS::Tlv.factory(octets(FRR))
    assert_instance_of ISIS::Tlv::Authentication, t
    assert t.hmac_md5?
    assert_equal FRR, t.to_shex
  end

  # The digest is computed, so the hash leaves it out and rebuilds zeros
  # for the PDU to fill.
  def test_hmac_md5_hash_has_no_digest
    t = ISIS::Tlv.factory(octets(FRR))
    assert_equal({ auth_type: 54 }, t.to_hash)
    assert_equal "0a1136" + "00" * 16, ISIS::Tlv::Authentication.new(t.to_hash).to_shex
    assert_equal "0a1136" + "00" * 16, ISIS::Tlv::Authentication.new(:hmac_md5).to_shex
  end

  # Clause 9.5: type 1 is a cleartext password, an octet string. 0a 07, 01,
  # then "secret" as six octets.
  def test_cleartext_password
    t = ISIS::Tlv::Authentication.new(password: "secret")
    assert_equal "0a07" "01" "736563726574", t.to_shex
    assert_equal({ auth_type: 1, password: "secret" }, t.to_hash)
    assert_equal t.to_shex, ISIS::Tlv::Authentication.new(t.to_hash).to_shex
    refute t.hmac_md5?
  end

  # Type 54 with a value that is not 16 octets is not one the PDU can
  # fill, so it is kept and hashed as it arrived.
  def test_hmac_md5_of_the_wrong_size_is_kept
    hex = "0a05" "36" "01020304"
    t = ISIS::Tlv.factory(octets(hex))
    refute t.hmac_md5?
    assert_equal({ auth_type: 54, value: "01020304" }, t.to_hash)
    assert_equal hex, ISIS::Tlv::Authentication.new(t.to_hash).to_shex
  end

  def test_other_types_and_empty_values_replay
    %w[0a03ff0102 0a00].each do |hex|
      t = ISIS::Tlv.factory(octets(hex))
      assert_equal hex, t.to_shex
      assert_equal hex, ISIS::Tlv::Authentication.new(t.to_hash).to_shex
    end
  end

  def test_copy_constructor
    assert_equal FRR, ISIS::Tlv::Authentication.new(ISIS::Tlv.factory(octets(FRR))).to_shex
  end

  def test_type_that_does_not_fit_is_refused
    assert_raises(ArgumentError) { ISIS::Tlv::Authentication.new(auth_type: 256, value: "") }
  end
end
