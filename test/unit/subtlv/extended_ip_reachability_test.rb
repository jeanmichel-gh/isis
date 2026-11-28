# frozen_string_literal: true

require_relative "../../test_helper"

# The Prefix-SID sub-TLV of TLVs 135 and 236, RFC 8667 section 2.1.
# Expected hex is our own arithmetic from the section's figure; index 1
# with N is also what FRR 10.2.1 sent (test/fixtures/frr-10.2.1-l2-lsp-sr.hex).
class TestSubTlvExtendedIpReachability < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def replays(klass, hex)
    s = klass.new(octets(hex))
    assert_equal hex, s.to_shex, "#{klass} replays"
    assert_equal hex, klass.new(s.to_hash).to_shex, "#{klass} rebuilds from its hash"
    assert_equal hex, klass.new(s).to_shex, "#{klass} copies"
    s
  end

  # Prefix-SID, section 2.1: 03 type, 06 length, flags, algorithm, then a
  # 4-octet index. N is the second bit, 0x40. This is FRR's, for index 1.
  def test_prefix_sid_index
    s = ISIS::SubTlv::PrefixSid.new(index: 1, flags: %w[N])
    assert_equal "030640" "00" "00000001", s.to_shex
    assert s.flag?(:n)
    refute s.flag?(:p)
    assert_equal({ flags: ["N"], algorithm: 0, index: 1 }, replays(ISIS::SubTlv::PrefixSid, s.to_shex).to_hash)
  end

  # V and L set, 0x08 and 0x04, and a 3-octet label (section 2.1.1.1).
  def test_prefix_sid_label_sets_v_and_l
    s = ISIS::SubTlv::PrefixSid.new(label: 16001)
    assert_equal "03050c00003e81", s.to_shex
    assert_equal %w[V L], s.flag_letters
  end

  # Every flag in its place: R 0x80, N 0x40, P 0x20, E 0x10, V 0x08, L 0x04.
  def test_prefix_sid_flag_bits
    %w[R N P E V L].each_with_index do |letter, i|
      s = ISIS::SubTlv::PrefixSid.new(index: 0, flags: [letter])
      assert_equal format("%02x", 0x80 >> i), s.to_shex[4, 2], letter
    end
  end

  # An invalid V and L pair "MUST be ignored" (2.1.1.1), which is the
  # receiver's decision: the octets replay, read by their length.
  def test_an_invalid_v_and_l_pair_replays
    s = replays(ISIS::SubTlv::PrefixSid, "03060800" "00000005")
    assert_equal({ flags: ["V"], algorithm: 0, index: 5 }, s.to_hash)
  end

  # Reserved bits that arrive set are echoed, and the hash names them.
  def test_reserved_bits_replay
    s = replays(ISIS::SubTlv::PrefixSid, "03064100" "00000001")
    assert_equal({ flags: ["N"], reserved: 1, algorithm: 0, index: 1 }, s.to_hash)
  end

  # Past the SID, the rest is a tail. Too short for flags and algorithm,
  # the value is kept whole.
  def test_odd_lengths_replay
    assert_equal({ flags: ["N"], algorithm: 0, index: 1, tail: "ff" },
                 replays(ISIS::SubTlv::PrefixSid, "0307400000000001ff").to_hash)
    assert_equal({ short: "40" }, replays(ISIS::SubTlv::PrefixSid, "030140").to_hash)
    assert_equal({ flags: ["N"], algorithm: 0, tail: "0001" }, replays(ISIS::SubTlv::PrefixSid, "030440000001").to_hash)
  end

  # Under 135 and 236, where RFC 8667 section 2.1 puts it and isis4r has
  # classes. Under 22 the same number is another sub-TLV, the Admin Group
  # (RFC 5305 section 3.1).
  def test_registered_under_135_and_236
    prefix = octets("0306400000000001")
    assert_instance_of ISIS::SubTlv::PrefixSid, ISIS::SubTlv::List.parse_under(135, prefix.dup).first
    assert_instance_of ISIS::SubTlv::PrefixSid, ISIS::SubTlv::List.parse_under(236, prefix.dup).first
    assert_instance_of ISIS::SubTlv::AdminGroup, ISIS::SubTlv::List.parse_under(22, prefix.dup).first
  end

  # In a TLV 135 entry, as FRR sent it for 10.255.0.1/32: metric 10,
  # control 0x60 (sub-TLVs present, length 32), the prefix, a sub-TLV length
  # of 8, then the Prefix-SID: 4 + 1 + 4 + 1 + 8 is 18, 12.
  def test_in_a_tlv_135_entry
    tlv = ISIS::Tlv::ExtendedIpReachability.new(
      [{ prefix: "10.255.0.1/32", metric: 10, subtlvs: [{ prefix_sid: { flags: ["N"], algorithm: 0, index: 1 } }] }]
    )
    assert_equal "8712" "0000000a" "60" "0aff0001" "08" "0306400000000001", tlv.to_shex
  end

  # Prefix Attribute Flags, RFC 7794 section 2.1: type 4, the bits from
  # bit 0, the high bit of the first octet: X 0x80, R 0x40, N 0x20, and
  # A, bit 4, 0x08 (RFC 9352 section 6). Our own arithmetic.
  def test_prefix_attribute_flags_masks
    { "X" => "040180", "R" => "040140", "N" => "040120", "E" => "040110", "A" => "040108" }.each do |letter, hex|
      f = ISIS::SubTlv::PrefixAttributeFlags.new(flags: [letter])
      assert_equal hex, f.to_shex, letter
      assert_equal [letter], replays(ISIS::SubTlv::PrefixAttributeFlags, hex).flag_letters
    end
    assert_equal "040128", ISIS::SubTlv::PrefixAttributeFlags.new(flags: %w[N A]).to_shex
  end

  # Unnamed bits are kept as reserved:, by number; a value with more
  # octets than its bits need, or none, keeps its length.
  def test_prefix_attribute_flags_reserved_and_length
    f = replays(ISIS::SubTlv::PrefixAttributeFlags, "04022040")
    assert_equal({ flags: %w[N], reserved: [9] }, f.to_hash)
    assert_equal "Prefix Attribute Flags N, bit 9", f.to_s
    assert_equal({ flags: %w[X], length: 2 }, replays(ISIS::SubTlv::PrefixAttributeFlags, "04028000").to_hash)
    assert_equal({ length: 0 }, replays(ISIS::SubTlv::PrefixAttributeFlags, "0400").to_hash)
    assert ISIS::SubTlv::PrefixAttributeFlags.new(flags: %w[A]).flag?("A")
    assert_raises(ArgumentError) { ISIS::SubTlv::PrefixAttributeFlags.new(flags: %w[Z]) }
  end

  # Under 135, 236 and 27, which share the prefix sub-TLV registry (RFC
  # 9352 section 7).
  def test_prefix_attribute_flags_registered
    [135, 236, 27].each do |parent|
      assert_equal ISIS::SubTlv::PrefixAttributeFlags, ISIS::SubTlv.class_under(parent, 4), parent
    end
  end
end
