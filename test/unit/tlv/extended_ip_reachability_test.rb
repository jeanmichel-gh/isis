# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 135, RFC 5305 section 4. The first expectation is FRR's: the TLV 135
# in test/fixtures/frr-8.4.4-l1-lsp-reachability.hex. The rest is our own
# arithmetic, laid out field by field.
class TestTlvExtendedIpReachability < Minitest::Test
  # 87 type 135, 08 length, 0000000a metric 10, 18 control (no flags,
  # length 24), 0a000c the three octets a /24 needs.
  FRR = "8708" "0000000a" "18" "0a000c"

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def tlv(*entries)
    ISIS::Tlv::ExtendedIpReachability.new(*entries)
  end

  def test_frr_entry_parses_and_replays
    t = ISIS::Tlv.factory(octets(FRR))
    assert_instance_of ISIS::Tlv::ExtendedIpReachability, t
    assert_equal [{ prefix: "10.0.12.0/24", metric: 10 }], t.to_hash
    assert_equal FRR, t.to_shex
  end

  def test_built_from_fields
    assert_equal FRR, tlv(prefix: "10.0.12.0/24", metric: 10).to_shex
  end

  # The prefix takes (length + 7) / 8 octets: none for /0, one for /8,
  # four for /25 and /32. Each entry is 5 octets plus the prefix.
  def test_prefix_is_packed_to_the_minimal_octets
    { "0.0.0.0/0" => "00", "10.0.0.0/8" => "080a", "10.0.12.128/25" => "190a000c80",
      "10.0.12.2/32" => "200a000c02" }.each do |prefix, tail|
      assert_equal "00000001" + tail, tlv(prefix: prefix, metric: 1).to_shex[4..], prefix
    end
  end

  # The control octet, field by field from the order section 4 lists them
  # in: up/down 0x80, sub-TLVs present 0x40, length in the low six bits.
  def test_control_octet
    assert_equal 0x98, tlv(prefix: "10.0.12.0/24", metric: 1, up_down: true).entries.first.control
    assert_equal 0x58, tlv(prefix: "10.0.12.0/24", metric: 1, subtlvs: []).entries.first.control
    assert_equal 0x20, tlv(prefix: "10.0.12.2/32", metric: 1).entries.first.control
  end

  def test_up_down_round_trips
    t = ISIS::Tlv.factory(octets("8708" "0000000a" "98" "0a000c"))
    assert t.entries.first.up_down
    assert_equal [{ prefix: "10.0.12.0/24", metric: 10, up_down: true }], t.to_hash
  end

  # Presence set with no sub-TLVs still writes the length octet, 00. Only
  # the bit decides, not whether there is anything to frame.
  def test_presence_bit_with_an_empty_list_writes_the_length
    assert_equal "8709" "0000000a" "58" "0a000c" "00", tlv(prefix: "10.0.12.0/24", metric: 10, subtlvs: []).to_shex
  end

  # A sub-TLV under 135 that isis4r does not know: 01 type, 04 length,
  # 0000002a. The entry's sub-TLV length is 06, and the TLV is 4 + 1 + 3 +
  # 1 + 6 = 15 octets (0f).
  def test_unknown_sub_tlv_is_kept
    hex = "870f" "0000000a" "58" "0a000c" "06" "01040000002a"
    t = ISIS::Tlv.factory(octets(hex))
    sub = t.entries.first.subtlvs.first
    assert_instance_of ISIS::SubTlv::Unknown, sub
    assert_equal [1, "0000002a"], [sub.type, sub.value.unpack1("H*")]
    assert_equal hex, t.to_shex
    assert_equal hex, ISIS::Tlv::ExtendedIpReachability.new(t.to_hash).to_shex
  end

  # A sub-TLV whose own length runs past the entry's sub-TLV length is
  # clamped to it, and replayed as declared.
  def test_sub_tlv_overrunning_its_entry_is_clamped
    hex = "870d" "0000000a" "58" "0a000c" "04" "01090000"
    t = ISIS::Tlv.factory(octets(hex))
    sub = t.entries.first.subtlvs.first
    assert sub.clamped?
    assert_equal 9, sub.declared_length
    assert_equal hex, t.to_shex
  end

  # A sub-TLV length past the TLV's value cannot be a whole entry, so the
  # entry and the rest are a tail.
  def test_sub_tlv_length_past_the_value_is_a_tail
    hex = "870a" "0000000a" "58" "0a000c" "09" "01"
    t = ISIS::Tlv.factory(octets(hex))
    assert_empty t.entries
    assert_equal hex[4..], t.tail.unpack1("H*")
    assert_equal hex, t.to_shex
  end

  def test_part_entry_is_a_tail
    hex = FRR.sub(/\A8708/, "870b") + "000000"
    t = ISIS::Tlv.factory(octets(hex))
    assert_equal 1, t.entries.size
    assert_equal "000000", t.tail.unpack1("H*")
    assert_equal hex, t.to_shex
  end

  # Bits past the length are kept: 0a000c05 with length 24 is not packed,
  # and replays as it came.
  def test_octets_that_are_not_a_minimal_prefix_are_kept
    hex = "8709" "0000000a" "18" "0a000c" "05"
    t = ISIS::Tlv.factory(octets(hex))
    # The /24 takes three octets, so the fourth starts a second entry that
    # cannot be whole: it is the tail.
    assert_equal "05", t.tail.unpack1("H*")
    hex2 = "8708" "0000000a" "14" "0a000f"
    e = ISIS::Tlv.factory(octets(hex2)).entries.first
    assert e.unusual?, "a /20 with bits set past 20 is not its presentation form"
    assert_equal({ length: 20, octets: "0a000f", metric: 10 }, e.to_hash)
    assert_equal hex2, ISIS::Tlv::ExtendedIpReachability.new([e.to_hash]).to_shex
  end

  # Six bits can say 63. Eight octets of prefix follow, and it replays.
  def test_length_over_32_is_kept
    hex = "870d" "0000000a" "3f" "0102030405060708"
    t = ISIS::Tlv.factory(octets(hex))
    assert_nil t.entries.first.prefix
    assert_equal hex, t.to_shex
  end

  def test_two_entries
    hex = FRR.sub(/\A8708/, "8711") + "00000014" "20" "0a000101"
    assert_equal hex, tlv({ prefix: "10.0.12.0/24", metric: 10 }, { prefix: "10.0.1.1/32", metric: 20 }).to_shex
  end

  def test_hash_rebuilds
    t = tlv({ prefix: "10.0.12.0/24", metric: 10, up_down: true },
            { prefix: "10.0.1.1/32", metric: 20, subtlvs: [{ unknown: { type: 1, value: "0000002a" } }] })
    assert_equal t.to_shex, ISIS::Tlv::ExtendedIpReachability.new(t.to_hash).to_shex
  end

  def test_copy_constructor
    t = ISIS::Tlv.factory(octets("870f" "0000000a" "58" "0a000c" "06" "01040000002a"))
    assert_equal t.to_shex, ISIS::Tlv::ExtendedIpReachability.new(t).to_shex
  end

  def test_fields_that_do_not_fit_are_refused
    assert_raises(ArgumentError) { tlv(prefix: "10.0.0.0/8", metric: 2**32) }
    assert_raises(ArgumentError) { tlv(length: 64, octets: "00", metric: 1) }
    assert_raises(ArgumentError) { tlv(prefix: "2001:db8::/32", metric: 1) }
  end

  def test_max_path_metric_is_section_3s
    assert_equal 4_261_412_864, ISIS::Tlv::ExtendedIpReachability::MAX_PATH_METRIC
  end

  def test_to_s
    assert_equal "Extended IP Reachability 10.0.12.0/24 metric 10", ISIS::Tlv.factory(octets(FRR)).to_s
  end
end
