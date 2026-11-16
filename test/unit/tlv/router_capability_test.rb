# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 242, Router Capability (RFC 7981 section 2), and the SR sub-TLVs RFC
# 8667 section 3 puts in it. Expected hex is our own arithmetic from the
# figures, and FRR_242 is what FRR 10.2.1 sent
# (test/fixtures/frr-10.2.1-l2-lsp-sr.hex).
class TestTlvRouterCapability < Minitest::Test
  # f2 type, 1e length (30):
  #   0aff0001          Router ID 10.255.0.1
  #   00                flags, S and D clear
  #   02 09 c0          SR-Capabilities, 9 octets, flags I and V
  #     001f40            range 8000
  #     01 03 003e80      SID/Label, the label 16000
  #   13 01 00          SR-Algorithm, algorithm 0
  #   16 09 00          SR Local Block, 9 octets, no flags
  #     0003e8            range 1000
  #     01 03 003a98      SID/Label, the label 15000
  FRR_242 = "f21e0aff000100" "0209c0001f400103003e80" "13010" "0" "160900" "0003e8" "0103003a98"

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def replays(hex)
    t = ISIS::Tlv::RouterCapability.new(octets(hex))
    assert_equal hex, t.to_shex, "replays"
    assert_equal hex, ISIS::Tlv::RouterCapability.new(t.to_hash).to_shex, "rebuilds from its hash"
    assert_equal hex, ISIS::Tlv::RouterCapability.new(t).to_shex, "copies"
    t
  end

  def frr_hash
    { router_id: "10.255.0.1",
      subtlvs: [{ sr_capabilities: { flags: %w[I V], descriptors: [{ range: 8000, label: 16000 }] } },
                { sr_algorithm: [0] },
                { sr_local_block: { descriptors: [{ range: 1000, label: 15000 }] } }] }
  end

  def test_frr_parses_and_replays
    t = replays(FRR_242)
    assert_equal frr_hash, t.to_hash
    assert_equal "10.255.0.1", t.router_id.to_s
    refute t.s?
    refute t.d?
  end

  def test_built_from_fields_is_frr
    t = ISIS::Tlv::RouterCapability.new(
      router_id: "10.255.0.1",
      subtlvs: [ISIS::SubTlv::SrCapabilities.new(flags: %w[I V], descriptors: [{ range: 8000, label: 16000 }]),
                ISIS::SubTlv::SrAlgorithm.new(0),
                ISIS::SubTlv::SrLocalBlock.new(descriptors: [{ range: 1000, label: 15000 }])]
    )
    assert_equal FRR_242, t.to_shex
    assert_equal FRR_242, ISIS::Tlv::RouterCapability.new(frr_hash).to_shex
  end

  # The blocks as RFC 8660 section 2.3 writes them, [Ll(i), Lh(i)].
  def test_ranges
    t = ISIS::Tlv::RouterCapability.new(octets(FRR_242))
    gb, _, lb = t.subtlvs.to_a
    assert_equal [[16000, 23999]], gb.ranges
    assert_equal [[15000, 15999]], lb.ranges
    assert gb.flag?(:i)
  end

  # S is 0x01 and D 0x02 ("S bit (0x01)", "D bit (0x02)"); the other six
  # bits are reserved, kept and echoed.
  def test_flags
    t = replays("f2050aff000183")
    assert t.s?
    assert t.d?
    assert_equal({ router_id: "10.255.0.1", s: true, d: true, reserved: 0x80 }, t.to_hash)
    assert_equal "f2050aff000101", ISIS::Tlv::RouterCapability.new(router_id: "10.255.0.1", s: true).to_shex
  end

  # Fewer than five octets is no Router ID and flags: kept whole.
  def test_a_short_value_replays
    assert_equal({ tail: "0aff00" }, replays("f2030aff00").to_hash)
  end

  # A descriptor cut short is a tail inside its sub-TLV, and an unknown
  # sub-TLV under 242 stays unknown. Both replay.
  def test_odd_sub_tlvs_replay
    replays("f20d0aff000100" "0206c0001f400103")
    t = replays("f2090aff000100" "630201ff")
    assert_instance_of ISIS::SubTlv::Unknown, t.subtlvs.first
  end

  def test_to_s
    text = ISIS::Tlv::RouterCapability.new(octets(FRR_242)).to_s
    assert_match(/Router Capability 10.255.0.1/, text)
    assert_match(/SR-Capabilities 16000-23999 flags IV/, text)
    assert_match(/SR-Algorithm 0/, text)
    assert_match(/SR Local Block 15000-15999/, text)
  end

  def test_registered
    assert_equal ISIS::Tlv::RouterCapability, ISIS::Tlv.class_for(242)
    list = ISIS::SubTlv::List.parse_under(242, octets("0209c0001f400103003e80" "13010" "0" "160900" "0003e8" "0103003a98"))
    assert_equal [ISIS::SubTlv::SrCapabilities, ISIS::SubTlv::SrAlgorithm, ISIS::SubTlv::SrLocalBlock], list.map(&:class)
  end
end
