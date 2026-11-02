# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 236, RFC 5308 section 2. Expected hex is our own arithmetic, laid out
# field by field: metric, control, prefix length, packed prefix.
class TestTlvIpv6Reachability < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  #   ec 0e          type 236, 14 octets
  #   0000000a       metric 10
  #   00             U, X, S clear
  #   40             /64
  #   20010db800010000  the 8 octets of 2001:db8:1::/64
  def test_one_entry
    tlv = ISIS::Tlv::Ipv6Reachability.new(prefix: "2001:db8:1::/64", metric: 10)
    assert_equal "ec0e" "0000000a" "00" "40" "20010db800010000", tlv.to_shex
  end

  # A /128 is all 16 octets; a /0 none.
  def test_prefix_is_packed
    host = ISIS::Tlv::Ipv6Reachability.new(prefix: "2001:db8::1/128", metric: 1)
    assert_equal "ec16" "00000001" "00" "80" "20010db8000000000000000000000001", host.to_shex
    default = ISIS::Tlv::Ipv6Reachability.new(prefix: "::/0", metric: 1)
    assert_equal "ec06" "00000001" "00" "00", default.to_shex
  end

  # The control octet: U 0x80, X 0x40, S 0x20, the figure's order from the
  # most significant bit. Asserted mask by mask.
  def test_control_octet
    e = ISIS::Tlv::Ipv6Reachability::Entry.new(metric: 0, length: 0, prefix_octets: "")
    e.up_down = true
    assert_equal 0x80, e.control
    e.up_down = false
    e.external = true
    assert_equal 0x40, e.control
    e.external = false
    e.subtlvs = ISIS::SubTlv::List.new(236, [])
    assert_equal 0x20, e.control
  end

  # S set writes the sub-TLV length, zero for an empty list.
  def test_subtlv_bit_writes_the_length
    tlv = ISIS::Tlv::Ipv6Reachability.new(prefix: "::/0", metric: 1, subtlvs: [])
    assert_equal "ec07" "00000001" "20" "00" "00", tlv.to_shex
  end

  # Reserved bits that arrive set are echoed, and say so in the hash.
  def test_reserved_bits_are_kept
    hex = "ec06" "00000001" "1f" "00"
    tlv = ISIS::Tlv::Ipv6Reachability.new(octets(hex))
    assert_equal hex, tlv.to_shex
    assert_equal [{ prefix: "::/0", metric: 1, reserved: 31 }], tlv.to_hash
    assert_equal hex, ISIS::Tlv::Ipv6Reachability.new(tlv.to_hash).to_shex
  end

  # Host bits past the length are kept and replayed.
  def test_host_bits_are_kept
    hex = "ec07" "00000001" "00" "07" "ff"
    tlv = ISIS::Tlv::Ipv6Reachability.new(octets(hex))
    assert_equal hex, tlv.to_shex
    assert_equal [{ length: 7, octets: "ff", metric: 1 }], tlv.to_hash
    assert_equal hex, ISIS::Tlv::Ipv6Reachability.new(tlv.to_hash).to_shex
  end

  # A part entry is a tail.
  def test_part_entry_is_a_tail
    hex = "ec08" "00000001" "00" "40" "2001"
    tlv = ISIS::Tlv::Ipv6Reachability.new(octets(hex))
    assert_empty tlv.entries
    assert_equal hex, tlv.to_shex
  end

  def test_two_entries_and_flags_round_trip
    tlv = ISIS::Tlv::Ipv6Reachability.new([{ prefix: "2001:db8:1::/64", metric: 10, up_down: true },
                                           { prefix: "2001:db8:2::/48", metric: 20, external: true }])
    again = ISIS::Tlv::Ipv6Reachability.new(octets(tlv.to_shex))
    assert_equal tlv.to_hash, again.to_hash
    assert_equal tlv.to_shex, ISIS::Tlv::Ipv6Reachability.new(tlv.to_hash).to_shex
  end

  def test_ipv4_is_refused
    assert_raises(ArgumentError) { ISIS::Tlv::Ipv6Reachability.new(prefix: "10.0.0.0/8", metric: 1) }
  end

  def test_factory_and_copy
    tlv = ISIS::Tlv::Ipv6Reachability.new(prefix: "2001:db8:1::/64", metric: 10)
    assert_instance_of ISIS::Tlv::Ipv6Reachability, ISIS::Tlv.factory(octets(tlv.to_shex))
    assert_equal tlv.to_shex, ISIS::Tlv::Ipv6Reachability.new(tlv).to_shex
  end

  def test_to_s
    tlv = ISIS::Tlv::Ipv6Reachability.new(prefix: "2001:db8:1::/64", metric: 10, external: true)
    assert_equal "IPv6 Reachability 2001:db8:1::/64 metric 10 external", tlv.to_s
  end
end
