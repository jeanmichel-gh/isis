# frozen_string_literal: true

require_relative "../../test_helper"

# Expected hex in this file is our own arithmetic from the TLV framing: one
# type octet, one length octet, then that many value octets. No worked
# example from a specification is used yet, so when one of these fails,
# check the expectation as well as the code.
class TestTlvFraming < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # type 199 (c7), length 3, value 616263 ("abc")
  def test_unknown_from_fields
    assert_equal "c703616263", ISIS::Tlv::Unknown.new(199, "abc").to_shex
  end

  def test_zero_length_value
    assert_equal "0800", ISIS::Tlv::Unknown.new(8, "").to_shex
  end

  def test_value_of_255_frames
    assert_equal "08ff#{'00' * 255}", ISIS::Tlv::Unknown.new(8, "\x00" * 255).to_shex
  end

  # One octet of length cannot say 256, and writing it truncated would send
  # a different TLV, so this is the one refusal.
  def test_value_over_255_is_refused_at_encode
    tlv = ISIS::Tlv::Unknown.new(8, "\x00" * 256)
    assert_raises(ArgumentError) { tlv.encode }
  end

  def test_type_outside_one_octet_is_refused
    assert_raises(ArgumentError) { ISIS::Tlv::Unknown.new(256, "") }
  end

  def test_encoding_is_binary
    assert_equal Encoding::BINARY, ISIS::Tlv::Unknown.new(137, "réseau").encode.encoding
  end

  # A subclass that hands the framing a UTF-8 value, the way a Dynamic
  # Hostname TLV built from a name would. Unknown stores its value as
  # binary already, so only a subclass like this can show the bug.
  class Utf8Value < ISIS::Tlv
    def type
      137
    end

    def encode
      super(+"réseau")
    end
  end

  # "réseau" in UTF-8 is r, then é as two octets c3 a9, then seau: 7
  # octets. A length written from String#size would say 6.
  def test_length_counts_octets_not_characters
    assert_equal "8907" + "72c3a973656175", Utf8Value.allocate.to_shex
  end

  def test_parse_round_trip
    assert_equal "c703616263", ISIS::Tlv::Unknown.new(octets("c703616263")).to_shex
  end

  def test_parse_consumes_exactly_its_own_octets
    input = octets("c703616263 0800")
    tlv = ISIS::Tlv::Unknown.new(input)
    assert_equal "c703616263", tlv.to_shex
    assert_equal "0800", input.to_shex, "the rest is left for the next TLV"
  end

  def test_copy_constructor
    original = ISIS::Tlv::Unknown.new(199, "abc")
    assert_equal original.to_shex, ISIS::Tlv::Unknown.new(original).to_shex
  end

  def test_hash_round_trip
    original = ISIS::Tlv::Unknown.new(199, "abc")
    assert_equal({ type: 199, value: "616263" }, original.to_hash)
    assert_equal original.to_shex, ISIS::Tlv::Unknown.new(original.to_hash).to_shex
  end

  # A field value String is never mistaken for wire octets: only Octets
  # are parsed.
  def test_a_plain_string_is_a_field_value_not_octets
    assert_raises(ArgumentError) { ISIS::Tlv::Unknown.new("c703616263") }
  end

  def test_to_s_says_type_and_size
    assert_equal "TLV 199, 3 octets", ISIS::Tlv::Unknown.new(199, "abc").to_s
  end

  def test_unregistered_type_is_unknown
    assert_equal ISIS::Tlv::Unknown, ISIS::Tlv.class_for(199)
  end
end

# The parse policy, rules 1 to 4 in CLAUDE.md, at the TLV level. Every case
# must replay its input exactly.
class TestTlvListParsePolicy < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def list(hex)
    ISIS::Tlv::List.new(octets(hex))
  end

  def test_two_tlvs
    l = list("c703616263 0800")
    assert_equal [199, 8], l.map(&:type)
    assert_equal "c7036162630800", l.to_shex
    assert_empty l.tail
  end

  def test_repeated_type_is_kept_in_order
    l = list("1601aa 1601bb 1601cc")
    assert_equal %w[aa bb cc], l.map { |t| t.value.unpack1("H*") }
  end

  def test_empty_input_is_an_empty_list
    l = list("")
    assert_equal 0, l.size
    assert_equal "", l.to_shex
  end

  # Rule 1 and 2: type 1, declared length 5, but only 2 value octets
  # arrived. The TLV is clamped to what arrived, keeps the declared 5, and
  # replays it.
  def test_tlv_overrunning_its_boundary_is_clamped_and_replayed
    l = list("0105 abcd")
    tlv = l.first
    assert tlv.clamped?
    assert_equal 5, tlv.declared_length
    assert_equal "abcd", tlv.value.unpack1("H*")
    assert_equal "0105abcd", l.to_shex
  end

  # Rule 1: the boundary handed down wins over the octets that follow it.
  # A TLV inside a 4 octet boundary declares 5; the octets after the
  # boundary belong to someone else and are not read.
  def test_boundary_wins_over_the_buffer
    input = octets("0105 abcd eeff")
    l = ISIS::Tlv::List.parse(input, boundary: 4)
    assert_equal "abcd", l.first.value.unpack1("H*")
    assert_equal "0105abcd", l.to_shex
    assert_equal "eeff", input.to_shex, "octets past the boundary are left alone"
  end

  # Rule 3 and 4: a remainder of one octet cannot be a TLV, so it is a tail.
  def test_one_octet_remainder_is_a_tail
    l = list("0800 ff")
    assert_equal 1, l.size
    assert_equal "ff", l.tail.unpack1("H*")
    assert_equal "0800ff", l.to_shex
  end

  def test_a_single_octet_is_all_tail
    l = list("ff")
    assert_equal 0, l.size
    assert_equal "ff", l.to_shex
  end

  # Rule 3: a zero length TLV still consumes its two header octets, so a
  # run of them makes progress and ends.
  def test_zero_length_tlvs_make_progress
    l = list("0800 0800 0800")
    assert_equal 3, l.size
    assert_equal "080008000800", l.to_shex
  end

  def test_clamped_tlv_after_a_good_one
    l = list("0800 89ff 41")
    assert_equal [false, true], l.map(&:clamped?)
    assert_equal "080089ff41", l.to_shex
  end

  def test_list_from_fields_and_hash
    l = ISIS::Tlv::List.new([ISIS::Tlv::Unknown.new(199, "abc"), ISIS::Tlv::Unknown.new(8, "")])
    assert_equal "c7036162630800", l.to_shex
    assert_equal({ tlvs: [{ unknown: { type: 199, value: "616263" } }, { unknown: { type: 8, value: "" } }] },
                 l.to_hash)
    assert_equal l.to_shex, ISIS::Tlv::List.new(l.to_hash).to_shex
  end

  def test_tail_survives_the_hash
    l = list("0800 ff")
    assert_equal "ff", l.to_hash[:tail]
    assert_equal "0800ff", ISIS::Tlv::List.new(l.to_hash).to_shex
  end

  def test_copy_constructor
    l = list("0105 abcd")
    assert_equal "0105abcd", ISIS::Tlv::List.new(l).to_shex
  end

  def test_to_s_lists_every_tlv_and_the_tail
    assert_equal "Padding, 0 octets\nTLV 137, 1 octets, declared 255\n",
                 list("0800 89ff 41").to_s + "\n"
    assert_equal "Padding, 0 octets\ntail, 1 octets", list("0800 ff").to_s
  end
end
