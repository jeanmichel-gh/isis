# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 2, RFC 1142 clause 9.8. The first expectation is FRR's: the TLV 2 in
# test/fixtures/frr-8.4.4-l1-lsp-narrow.hex. The rest is our own
# arithmetic, laid out field by field.
class TestTlvIsReachability < Minitest::Test
  # 02 type 2, 0c length 12, 00 virtual flag, 0a default metric 10, 80 80
  # 80 delay, expense and error unsupported (S set), 00000000000100 the
  # neighbour 0000.0000.0001.00.
  FRR = "020c" "00" "0a808080" "00000000000100"

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def tlv(*entries)
    ISIS::Tlv::IsReachability.new(*entries)
  end

  def test_frr_entry_parses_and_replays
    t = ISIS::Tlv.factory(octets(FRR))
    assert_instance_of ISIS::Tlv::IsReachability, t
    assert_equal [{ neighbor: "0000.0000.0001.00", metric: 10 }], t.to_hash
    assert_equal FRR, t.to_shex
  end

  def test_built_from_fields
    assert_equal FRR, tlv(neighbor: "0000.0000.0001.00", metric: 10).to_shex
  end

  # A supported delay metric of 5 clears S: 05. Expense and error stay 80.
  def test_a_supported_metric_clears_s
    assert_equal "020c" "00" "0a058080" "00000000000100", tlv(neighbor: "0000.0000.0001.00", metric: 10, delay: 5).to_shex
  end

  # Clause 9.8 gives every one of the four octets an I/E bit at bit 7,
  # 0x40. External on all four: 4a, and c0 for the unsupported ones (S and
  # I/E).
  def test_external_sets_ie_in_all_four
    assert_equal "020c" "00" "4ac0c0c0" "00000000000100",
                 tlv(neighbor: "0000.0000.0001.00", metric: 10, external: true).to_shex
  end

  # The Neighbour ID is ID Length + 1 octets. At an ID Length of 2 the
  # same 15 octets of value are two entries of 7.
  def test_neighbor_width_follows_id_length
    hex = "020f" "00" "0a808080" "000100" "14808080" "000200"
    t = ISIS::Tlv.factory(octets(hex), id_width: 2)
    assert_equal ["0001.00", "0002.00"], t.entries.map(&:neighbor_s)
    assert_equal [10, 20], t.entries.map { |e| e.metrics.default }
    assert_equal hex, t.to_shex
    at_six = ISIS::Tlv.factory(octets(hex))
    assert_equal 1, at_six.entries.size
  end

  # The default octet's bit 8 is reserved. Set, it replays and the hash
  # carries the octets, since the fields cannot say it.
  def test_reserved_bit_replays
    hex = "020c" "00" "8a808080" "00000000000100"
    t = ISIS::Tlv.factory(octets(hex))
    assert_equal 10, t.entries.first.metrics.default
    assert_equal [{ neighbor: "0000.0000.0001.00", metric: 10, metric_octets: "8a808080" }], t.to_hash
    assert_equal hex, ISIS::Tlv::IsReachability.new(t.to_hash).to_shex
  end

  def test_virtual_flag_is_kept
    hex = "020c" "01" "0a808080" "00000000000100"
    t = ISIS::Tlv.factory(octets(hex))
    assert_equal 1, t.virtual_flag
    assert_equal hex, ISIS::Tlv::IsReachability.new(t.to_hash).to_shex
  end

  # A zero length value has no flag at all, and replays as none.
  def test_no_virtual_flag
    t = ISIS::Tlv.factory(octets("0200"))
    assert_nil t.virtual_flag
    assert_equal "0200", t.to_shex
    assert_equal "0200", ISIS::Tlv::IsReachability.new(t.to_hash).to_shex
  end

  def test_part_entry_is_a_tail
    hex = FRR.sub(/\A020c/, "020f") + "0a8080"
    t = ISIS::Tlv.factory(octets(hex))
    assert_equal 1, t.entries.size
    assert_equal "0a8080", t.tail.unpack1("H*")
    assert_equal hex, t.to_shex
    assert_equal hex, ISIS::Tlv::IsReachability.new(t.to_hash).to_shex
  end

  def test_hash_rebuilds
    t = tlv({ neighbor: "0000.0000.0001.00", metric: 10, delay: 3, expense: 4, error: 5 },
            { neighbor: "1921.6800.1001.02", metric: 63, external: true })
    assert_equal t.to_shex, ISIS::Tlv::IsReachability.new(t.to_hash).to_shex
  end

  def test_copy_constructor
    t = ISIS::Tlv.factory(octets(FRR))
    assert_equal FRR, ISIS::Tlv::IsReachability.new(t).to_shex
  end

  def test_fields_that_do_not_fit_are_refused
    assert_raises(ArgumentError) { tlv(neighbor: "0000.0000.0001.00", metric: 64) }
    assert_raises(ArgumentError) { tlv(neighbor: "0000.0000.0001.00", metric: 1, error: 64) }
    assert_raises(ArgumentError) { tlv(neighbor: "00", metric: 1) }
  end

  def test_to_s
    assert_equal "IS Reachability 0000.0000.0001.00 metric 10", ISIS::Tlv.factory(octets(FRR)).to_s
  end
end
