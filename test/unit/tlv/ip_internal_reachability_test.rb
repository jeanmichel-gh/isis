# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 128, RFC 1195 section 5.3.4. The first expectation is FRR's: the TLV
# 128 in test/fixtures/frr-8.4.4-l1-lsp-narrow.hex. The rest is our own
# arithmetic, laid out field by field.
class TestTlvIpInternalReachability < Minitest::Test
  # 80 type 128, 0c length 12, 0a default metric 10, 80 80 80 delay,
  # expense and error unsupported (S set), 0a000c00 the address,
  # ffffff00 the mask.
  FRR = "800c" "0a808080" "0a000c00" "ffffff00"

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def tlv(*entries)
    ISIS::Tlv::IpInternalReachability.new(*entries)
  end

  def test_frr_entry_parses_and_replays
    t = ISIS::Tlv.factory(octets(FRR))
    assert_instance_of ISIS::Tlv::IpInternalReachability, t
    assert_equal [{ prefix: "10.0.12.0/24", metric: 10 }], t.to_hash
    assert_equal FRR, t.to_shex
  end

  def test_built_from_fields
    assert_equal FRR, tlv(prefix: "10.0.12.0/24", metric: 10).to_shex
  end

  # Section 5.3.4 puts I/E only in the default octet: external is 4a, and
  # the other three stay 80, their bit 7 reserved.
  def test_external_sets_ie_in_the_default_only
    assert_equal "800c" "4a808080" "0a000c00" "ffffff00", tlv(prefix: "10.0.12.0/24", metric: 10, external: true).to_shex
  end

  # Bit 7 of the delay octet is reserved here, unlike TLV 2. Arrived set,
  # it replays and the hash keeps the octets.
  def test_reserved_bit_in_delay_replays
    hex = "800c" "0ac08080" "0a000c00" "ffffff00"
    t = ISIS::Tlv.factory(octets(hex))
    assert_nil t.entries.first.metrics.value(:delay)
    assert_equal "0ac08080", t.to_hash.first[:metric_octets]
    assert_equal hex, ISIS::Tlv::IpInternalReachability.new(t.to_hash).to_shex
  end

  # A mask that is not contiguous, or an address with bits past it, is not
  # a prefix: it hashes as address and mask, and replays.
  def test_odd_masks_and_host_bits_replay
    { "0a000c01ffffff00" => { address: "10.0.12.1", mask: "255.255.255.0" },
      "0a000c00ff00ff00" => { address: "10.0.12.0", mask: "255.0.255.0" } }.each do |tail, where|
      hex = "800c" "0a808080" + tail
      t = ISIS::Tlv.factory(octets(hex))
      assert_nil t.entries.first.prefix
      assert_equal [where.merge(metric: 10)], t.to_hash
      assert_equal hex, ISIS::Tlv::IpInternalReachability.new(t.to_hash).to_shex
    end
  end

  def test_host_and_default_routes
    assert_equal "800c" "01808080" "c0000201" "ffffffff", tlv(prefix: "192.0.2.1/32", metric: 1).to_shex
    assert_equal "800c" "01808080" "00000000" "00000000", tlv(prefix: "0.0.0.0/0", metric: 1).to_shex
  end

  def test_part_entry_is_a_tail
    hex = FRR.sub(/\A800c/, "800f") + "0a8080"
    t = ISIS::Tlv.factory(octets(hex))
    assert_equal 1, t.entries.size
    assert_equal "0a8080", t.tail.unpack1("H*")
    assert_equal hex, ISIS::Tlv::IpInternalReachability.new(t.to_hash).to_shex
  end

  def test_hash_rebuilds
    t = tlv({ prefix: "10.0.12.0/24", metric: 10, delay: 1, expense: 2, error: 3 },
            { prefix: "192.0.2.1/32", metric: 63, external: true })
    assert_equal t.to_shex, ISIS::Tlv::IpInternalReachability.new(t.to_hash).to_shex
  end

  def test_copy_constructor
    assert_equal FRR, ISIS::Tlv::IpInternalReachability.new(ISIS::Tlv.factory(octets(FRR))).to_shex
  end

  def test_fields_that_do_not_fit_are_refused
    assert_raises(ArgumentError) { tlv(prefix: "10.0.12.0/24", metric: 64) }
    assert_raises(ArgumentError) { tlv(prefix: "2001:db8::/32", metric: 1) }
  end

  def test_to_s
    assert_equal "IP Internal Reachability 10.0.12.0/24 metric 10", ISIS::Tlv.factory(octets(FRR)).to_s
  end
end
