# frozen_string_literal: true

require_relative "../../test_helper"

# An LSP from FRR 10.2.1 running SR-MPLS, router a of routescope's frr-sr
# lab, captured on its link to b on 2026-11-16 (routescope
# labs/frr-sr/ABOUT.md). SRGB 16000 to 23999, SRLB 15000 to 15999, the
# Node-SID index 1 on 10.255.0.1/32, and an Adj-SID of 15000 toward b.
#
#   f21e...   TLV 242, Router Capability (RFC 7981, RFC 8667 section 3)
#   8604...   TLV 134, TE Router ID, not implemented: kept whole
#   1612...   TLV 22, b at metric 10, with an Adj-SID
#   8704...   TLV 132
#   871b...   TLV 135, 10.255.0.1/32 with a Prefix-SID, and 10.0.12.0/30
class TestLspSegmentRouting < Minitest::Test
  FRR = File.read(File.expand_path("../../fixtures/frr-10.2.1-l2-lsp-sr.hex", __dir__)).strip

  def lsp
    ISIS::Pdu.factory(ISIS::Octets.from_hex(FRR))
  end

  def test_parses_and_replays
    assert_instance_of ISIS::Pdu::Lsp, lsp
    assert_equal FRR, lsp.to_shex
    assert_equal FRR, ISIS::Pdu::Lsp.new(lsp.to_hash).to_shex, "rebuilds from its hash"
  end

  def test_every_sr_sub_tlv_is_read
    tlvs = lsp.tlvs.to_a
    cap = tlvs.find { _1.is_a?(ISIS::Tlv::RouterCapability) }
    assert_equal "10.255.0.1", cap.router_id.to_s
    assert_equal [[16000, 23999]], cap.subtlvs.find { _1.is_a?(ISIS::SubTlv::SrCapabilities) }.ranges
    assert_equal [[15000, 15999]], cap.subtlvs.find { _1.is_a?(ISIS::SubTlv::SrLocalBlock) }.ranges

    adj = tlvs.find { _1.is_a?(ISIS::Tlv::ExtendedIsReachability) }.entries.first.subtlvs.first
    assert_equal [15000, %w[V L]], [adj.label, adj.flag_letters]

    sid = tlvs.find { _1.is_a?(ISIS::Tlv::ExtendedIpReachability) }.entries.first.subtlvs.first
    assert_equal [1, 0, %w[N]], [sid.index, sid.algorithm, sid.flag_letters]
  end

  # Nothing SR is left as an unknown sub-TLV. TLV 134 is the one unknown.
  def test_nothing_sr_is_unknown
    unknown = lsp.tlvs.select { _1.is_a?(ISIS::Tlv::Unknown) }.map(&:type)
    assert_equal [134], unknown
    subs = lsp.tlvs.flat_map { |t| t.respond_to?(:entries) ? t.entries.filter_map(&:subtlvs).flat_map(&:to_a) : [] }
    assert_empty subs.grep(ISIS::SubTlv::Unknown)
  end
end
