# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 27, the SRv6 Locator TLV, RFC 9352 section 7.1. Expected hex is our
# own arithmetic from the section's figures; FRR 10.7.1's TLV 27 is in
# test/unit/pdu/lsp_srv6_test.rb.
class TestSrv6Locator < Minitest::Test
  def octets(hex) = ISIS::Octets.from_hex(hex)

  def tlv(hex) = ISIS::Tlv::Srv6Locator.new(octets(hex))

  # Type 27 (1b), length 16 (10): R bits and MTID 0 (0000), then one
  # entry: metric 10 (0000000a), flags 0, algorithm 0, Loc-Size 48 (30),
  # the locator in the fewest octets, six (fc00 0000 0001), and a
  # Sub-TLV-length of 0, written although there are none.
  ONE = "1b10" "0000" "0000000a" "00" "00" "30" "fc0000000001" "00"

  def test_one_locator_from_fields
    t = ISIS::Tlv::Srv6Locator.new(entries: [{ locator: "fc00:0:1::/48", metric: 10 }])
    assert_equal ONE, t.to_shex
    assert_equal({ entries: [{ locator: "fc00:0:1::/48", metric: 10, algorithm: 0 }] }, t.to_hash)
    assert_equal "SRv6 Locator fc00:0:1::/48, metric 10, algorithm 0", t.to_s
  end

  def test_four_ways
    t = tlv(ONE)
    assert_equal ONE, t.to_shex
    assert_equal ONE, ISIS::Tlv::Srv6Locator.new(t.to_hash).to_shex
    assert_equal ONE, ISIS::Tlv::Srv6Locator.new(t).to_shex
    assert_equal ONE, ISIS::Tlv.factory(octets(ONE)).to_shex
    assert_instance_of ISIS::Tlv::Srv6Locator, ISIS::Tlv.factory(octets(ONE))
  end

  # The fewest octets for Loc-Size: (size + 7) / 8. A /20 is three
  # octets, a /128 sixteen, a /1 one.
  def test_fewest_octets
    { "fc00:1000::/20" => "fc0010", "2001:db8::1/128" => "20010db8000000000000000000000001", "8000::/1" => "80" }
      .each do |prefix, wire|
        e = ISIS::Tlv::Srv6Locator::Entry.new(locator: prefix)
        assert_equal "00000000" "0000" + format("%02x", prefix.split("/").last.to_i) + wire + "00", e.encode.unpack1("H*")
      end
  end

  # D, the up/down bit, is the flags octet's high bit (the section's
  # "|D|    Reserved |"); algorithm 128; MTID 2 and a reserved R bit.
  # Value 2 + 4 + 3 + 4 + 1 = 14 (0e).
  def test_flags_algorithm_mtid
    t = ISIS::Tlv::Srv6Locator.new(mtid: 2, reserved: 8,
                                   entries: [{ locator: "fc00:0:1::/32", metric: 0, algorithm: 128, flags: %w[D], reserved: 1 }])
    assert_equal "1b0e" "8002" "00000000" "81" "80" "20" "fc000000" "00", t.to_shex
    e = t.entries.first
    assert e.up_down?
    assert_equal({ mtid: 2, reserved: 8,
                   entries: [{ locator: "fc00::/32", metric: 0, algorithm: 128, flags: %w[D], reserved: 1 }] },
                 tlv(t.to_shex).to_hash)
    assert_equal "SRv6 Locator MTID 2 fc00::/32, metric 0, algorithm 128, down", t.to_s
  end

  # Section 7.1: "The entire TLV MUST be ignored if the Loc-Size is
  # outside this range", the receiver's decision. The codec keeps it:
  # Loc-Size 0 reads no locator octets, 129 and 200 read 16, the most
  # there are, and the entry goes on from there.
  def test_bad_loc_size_kept_and_replayed
    zero = "1b0a" "0000" "00000000" "00" "00" "00" "" "00"
    assert_equal zero, tlv(zero).to_shex
    assert_equal({ size: 0, octets: "", metric: 0, algorithm: 0 }, tlv(zero).entries.first.to_hash)
    sixteen = "fc000000000100000000000000000000"
    [129, 200].each do |size|
      hex = "1b1a" "0000" "00000000" "00" "00" + format("%02x", size) + sixteen + "00"
      t = tlv(hex)
      assert_equal hex, t.to_shex
      assert_nil t.entries.first.locator
      assert_equal hex, ISIS::Tlv::Srv6Locator.new(t.to_hash).to_shex
      assert_empty t.tail
    end
  end

  # "Trailing bits MUST be set to zero and ignored when received": one
  # set, past bit 47, is kept and echoed, so the entry is not a canonical
  # prefix and hashes by its octets.
  def test_trailing_bits_kept
    hex = "1b10" "0000" "00000000" "00" "00" "2f" "fc0000000001" "00"
    t = tlv(hex)
    assert_equal hex, t.to_shex
    assert_equal({ size: 47, octets: "fc0000000001", metric: 0, algorithm: 0 }, t.entries.first.to_hash)
    assert_equal hex, ISIS::Tlv::Srv6Locator.new(t.to_hash).to_shex
  end

  # A Sub-TLV-length past the TLV is clamped to what is left, kept, and
  # written back while the sub-TLVs do not change (parse rules 1 and 2).
  # Once they change, it is computed.
  def test_sub_tlv_length_clamped
    hex = "1b13" "0000" "00000000" "00" "00" "30" "fc0000000001" "10" "040100"
    t = tlv(hex)
    assert_equal hex, t.to_shex
    assert_equal 16, t.entries.first.subtlv_length_clamped
    assert_instance_of ISIS::SubTlv::PrefixAttributeFlags, t.entries.first.subtlvs.first
    t.entries.first.subtlvs.tlvs.clear
    assert_equal "1b10" "0000" "00000000" "00" "00" "30" "fc0000000001" "00", t.to_shex
  end

  # Octets that are not a whole entry are a tail; a value under two
  # octets is short.
  def test_tail_and_short
    hex = ONE.sub("1b10", "1b13") + "000000"
    t = tlv(hex)
    assert_equal hex, t.to_shex
    assert_equal "000000", t.to_hash[:tail]
    assert_equal hex, ISIS::Tlv::Srv6Locator.new(t.to_hash).to_shex
    s = tlv("1b0100")
    assert_equal({ short: "00" }, s.to_hash)
    assert_equal "1b0100", ISIS::Tlv::Srv6Locator.new(s.to_hash).to_shex
  end

  # Its sub-TLVs come from the prefix registry it shares (section 7):
  # the End SID, 5, which only TLV 27 has; Prefix Attribute Flags, 4; and
  # the FAPM, 6, which RFC 9350 section 8 has ignored there, read so that
  # it can be reported. An unknown number stays an Unknown.
  def test_sub_tlvs_from_the_prefix_registry
    t = ISIS::Tlv::Srv6Locator.new(entries: [{ locator: "fc00:0:1::/48", subtlvs: [
                                     { prefix_attribute_flags: { flags: %w[A] } },
                                     { end_sid: { behavior: "End", sid: "fc00:0:1::" } },
                                     { fapm: { algorithm: 128, metric: 5 } },
                                     { unknown: { type: 99, value: "ab" } }
                                   ] }])
    back = tlv(t.to_shex).entries.first.subtlvs.map(&:class)
    assert_equal [ISIS::SubTlv::PrefixAttributeFlags, ISIS::SubTlv::Srv6EndSid, ISIS::SubTlv::Fapm,
                  ISIS::SubTlv::Unknown], back
    assert_equal [ISIS::SubTlv::Unknown],
                 ISIS::Tlv::Ipv6Reachability.new([{ prefix: "fc00::/48", metric: 0,
                                                    subtlvs: [{ unknown: { type: 5, value: "00" } }] }])
                                             .then { ISIS::Tlv::Ipv6Reachability.new(octets(_1.to_shex)) }
                                             .entries.first.subtlvs.map(&:class)
  end

  # Building never validates: Loc-Size 0 by field values, a reserved
  # flag, the same locator twice at two algorithms.
  def test_building_never_validates
    t = ISIS::Tlv::Srv6Locator.new(entries: [{ size: 0, octets: "" }, { locator: "fc00::/48", algorithm: 0 },
                                             { locator: "fc00::/48", algorithm: 128, reserved: 0x7f }])
    assert_equal t.to_shex, tlv(t.to_shex).to_shex
    assert_raises(ArgumentError) { ISIS::Tlv::Srv6Locator::Entry.new(locator: "10.0.0.0/8") }
    assert_raises(ArgumentError) { ISIS::Tlv::Srv6Locator.new(mtid: 4096) }
  end
end
