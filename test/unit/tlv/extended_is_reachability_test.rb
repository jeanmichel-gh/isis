# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 22, RFC 5305 section 3. The first expectation is FRR's: the TLV 22 in
# test/fixtures/frr-8.4.4-l1-lsp-reachability.hex. The rest is our own
# arithmetic, laid out field by field.
class TestTlvExtendedIsReachability < Minitest::Test
  # 16 type 22, 0b length 11, 00000000000100 neighbor 0000.0000.0001.00,
  # 00000a metric 10, 00 no sub-TLVs.
  FRR = "160b" "00000000000100" "00000a" "00"

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def tlv(*entries)
    ISIS::Tlv::ExtendedIsReachability.new(*entries)
  end

  def test_frr_entry_parses_and_replays
    t = ISIS::Tlv.factory(octets(FRR))
    assert_instance_of ISIS::Tlv::ExtendedIsReachability, t
    assert_equal [{ neighbor: "0000.0000.0001.00", metric: 10 }], t.to_hash
    assert_equal FRR, t.to_shex
  end

  def test_built_from_fields
    assert_equal FRR, tlv(neighbor: "0000.0000.0001.00", metric: 10).to_shex
  end

  # The metric is three octets, not four: 0x123456 is 123456 on the wire.
  def test_metric_is_three_octets
    assert_equal "160b" "19216800100101" "123456" "00",
                 tlv(neighbor: "1921.6800.1001.01", metric: 0x123456).to_shex
  end

  # The sub-TLV length is always written. With one unknown sub-TLV, 01
  # type, 04 length, 0000002a, it is 06 and the TLV is 11 + 6 = 17 (11).
  def test_sub_tlv_length_is_always_written
    hex = "1611" "00000000000100" "00000a" "06" "01040000002a"
    t = ISIS::Tlv.factory(octets(hex))
    sub = t.entries.first.subtlvs.first
    assert_instance_of ISIS::SubTlv::Unknown, sub
    assert_equal hex, t.to_shex
    assert_equal hex, ISIS::Tlv::ExtendedIsReachability.new(t.to_hash).to_shex
  end

  # The ID is seven octets whatever the PDU's ID Length: the same 22 octets
  # are two entries, never read at another width.
  def test_neighbor_is_seven_octets
    hex = "1616" "00000000000100" "00000a" "00" "00000000000200" "000014" "00"
    t = ISIS::Tlv.factory(octets(hex), id_width: 2)
    assert_equal ["0000.0000.0001.00", "0000.0000.0002.00"], t.entries.map(&:neighbor_s)
    assert_equal [10, 20], t.entries.map(&:metric)
  end

  def test_sub_tlv_overrunning_its_entry_is_clamped
    hex = "160f" "00000000000100" "00000a" "04" "01090000"
    t = ISIS::Tlv.factory(octets(hex))
    sub = t.entries.first.subtlvs.first
    assert sub.clamped?
    assert_equal 9, sub.declared_length
    assert_equal hex, t.to_shex
  end

  # A sub-TLV length past the value cannot be a whole entry: a tail.
  def test_sub_tlv_length_past_the_value_is_a_tail
    hex = "160c" "00000000000100" "00000a" "09" "01"
    t = ISIS::Tlv.factory(octets(hex))
    assert_empty t.entries
    assert_equal hex[4..], t.tail.unpack1("H*")
    assert_equal hex, t.to_shex
    assert_equal hex, ISIS::Tlv::ExtendedIsReachability.new(t.to_hash).to_shex
  end

  def test_part_entry_is_a_tail
    hex = FRR.sub(/\A160b/, "160e") + "000000"
    t = ISIS::Tlv.factory(octets(hex))
    assert_equal 1, t.entries.size
    assert_equal "000000", t.tail.unpack1("H*")
    assert_equal hex, t.to_shex
  end

  # One octet in the sub-TLV area cannot be a sub-TLV, so the list keeps it
  # as a tail, and the hash carries it.
  def test_sub_tlv_tail_survives_the_hash
    hex = "160c" "00000000000100" "00000a" "01" "ee"
    t = ISIS::Tlv.factory(octets(hex))
    assert_equal "ee", t.entries.first.subtlvs.tail.unpack1("H*")
    assert_equal [{ neighbor: "0000.0000.0001.00", metric: 10, subtlv_tail: "ee" }], t.to_hash
    assert_equal hex, ISIS::Tlv::ExtendedIsReachability.new(t.to_hash).to_shex
  end

  def test_hash_rebuilds
    t = tlv({ neighbor: "0000.0000.0001.00", metric: 10 },
            { neighbor: "1921.6800.1001.02", metric: 0xffffff, subtlvs: [{ unknown: { type: 6, value: "0a000c01" } }] })
    assert_equal t.to_shex, ISIS::Tlv::ExtendedIsReachability.new(t.to_hash).to_shex
  end

  def test_copy_constructor
    t = ISIS::Tlv.factory(octets("1611" "00000000000100" "00000a" "06" "01040000002a"))
    assert_equal t.to_shex, ISIS::Tlv::ExtendedIsReachability.new(t).to_shex
  end

  def test_fields_that_do_not_fit_are_refused
    assert_raises(ArgumentError) { tlv(neighbor: "0000.0000.0001.00", metric: 2**24) }
    assert_raises(ArgumentError) { tlv(neighbor: "0000.0000.0001", metric: 1) }
  end

  def test_max_link_metric_is_section_3s
    assert_equal 2**24 - 1, ISIS::Tlv::ExtendedIsReachability::MAX_LINK_METRIC
  end

  def test_neighbor_presentation_round_trips
    assert_equal "1921.6800.1001.02",
                 ISIS::Tlv::ExtendedIsReachability::Entry.new(
                   neighbor: ISIS::Tlv::ExtendedIsReachability::Entry.neighbor_octets("1921.6800.1001.02"), metric: 1
                 ).neighbor_s
  end

  def test_to_s
    assert_equal "Extended IS Reachability 0000.0000.0001.00 metric 10", ISIS::Tlv.factory(octets(FRR)).to_s
  end
end
