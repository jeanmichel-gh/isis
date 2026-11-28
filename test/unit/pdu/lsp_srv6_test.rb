# frozen_string_literal: true

require_relative "../../test_helper"

# Two L2 LSPs from FRR 10.7.1 with SRv6, captured on ospflab on
# 2026-11-28 at f2's end of a point to point link between two FRR
# containers, each with a locator fc00:0:N::/48, block-len 32 node-len
# 16 func-bits 16. f1's locator is uSID (behavior usid), f2's is not
# (docs/design/srv6.md, "Measured on FRR 10.7.1"). Each is the LSP sent
# once the adjacency was up, so its TLV 22 carries the End.X SID.
#
#   f2...   TLV 242: SRv6 Capabilities 25, SR-Algorithm 0, Node MSD 23
#   16...   TLV 22: the addresses, then the End.X SID 43
#   ec...   TLV 236, the locator in it at metric 0
#   1b...   TLV 27: the locator, its End SID 5 with a SID Structure
class TestLspSrv6 < Minitest::Test
  def self.fixture(name) = File.read(File.expand_path("../../fixtures/#{name}", __dir__)).strip

  USID = fixture("frr-10.7.1-l2-lsp-srv6-usid.hex")
  CLASSIC = fixture("frr-10.7.1-l2-lsp-srv6.hex")

  def lsp(hex) = ISIS::Pdu.factory(ISIS::Octets.from_hex(hex))

  def tlv(hex, klass) = lsp(hex).tlvs.find { _1.is_a?(klass) }

  def test_parses_and_replays
    [USID, CLASSIC].each do |hex|
      assert_instance_of ISIS::Pdu::Lsp, lsp(hex)
      assert_equal hex, lsp(hex).to_shex
      assert_equal hex, ISIS::Pdu::Lsp.new(lsp(hex).to_hash).to_shex, "rebuilds from its hash"
    end
  end

  # Nothing SRv6 is left as an Unknown. TLV 134, the TE Router ID, has
  # no class.
  def test_no_unknown_srv6
    [USID, CLASSIC].each do |hex|
      unknown = lsp(hex).tlvs.select { _1.is_a?(ISIS::Tlv::Unknown) }.map(&:type)
      assert_equal [134], unknown
      [ISIS::Tlv::RouterCapability, ISIS::Tlv::ExtendedIsReachability].each do |klass|
        subs = klass == ISIS::Tlv::RouterCapability ? tlv(hex, klass).subtlvs : tlv(hex, klass).entries.first.subtlvs
        assert_empty subs.select { _1.is_a?(ISIS::SubTlv::Unknown) }, klass
      end
    end
  end

  # f1, uSID: its End SID is behaviour 43, End with NEXT-CSID, its End.X
  # 52, End.X with NEXT-CSID, function 1. f2's are End, 1, and End.X, 5.
  # Both carry a SID Structure of 32, 16, 16 and 0, though RFC 9800
  # section 8's example has the argument cover the rest of the SID.
  def test_sids
    { USID => ["fc00:0:1::/48", "fc00:0:1::", 43, "fc00:0:1:1::", 52],
      CLASSIC => ["fc00:0:2::/48", "fc00:0:2::", 1, "fc00:0:2:1::", 5] }.each do |hex, (loc, end_sid, end_b, x_sid, x_b)|
      entry = tlv(hex, ISIS::Tlv::Srv6Locator).entries.first
      assert_equal [loc, 0, 0], [entry.locator, entry.metric, entry.algorithm]
      e = entry.subtlvs_of(ISIS::SubTlv::Srv6EndSid).first
      assert_equal [end_sid, end_b], [e.sid, e.behavior]
      x = tlv(hex, ISIS::Tlv::ExtendedIsReachability).entries.first.subtlvs.find { _1.is_a?(ISIS::SubTlv::Srv6EndXSid) }
      assert_equal [x_sid, x_b, 0, 0, []], [x.sid, x.behavior, x.algorithm, x.weight, x.flag_letters]
      [e, x].each { assert_equal [32, 16, 16, 0], _1.structure.to_hash.values_at(:block, :node, :function, :argument) }
      assert_empty entry.subtlvs_of(ISIS::SubTlv::PrefixAttributeFlags), "FRR sends no Prefix Attribute Flags"
    end
  end

  # TLV 242: SRv6 Capabilities with O clear, and FRR's Node MSDs, SRH
  # Max SL 3, Max End Pop 3, Max H.encaps 2, Max End D 5.
  def test_capabilities_and_msds
    cap = tlv(USID, ISIS::Tlv::RouterCapability).subtlvs
    refute cap.find { _1.is_a?(ISIS::SubTlv::Srv6Capabilities) }.o?
    msd = cap.find { _1.is_a?(ISIS::SubTlv::NodeMsd) }
    assert_equal [[41, 3], [42, 3], [44, 2], [45, 5]], msd.msds
  end

  # The locator is in TLV 236 too, at metric 0 (RFC 9352 section 5's
  # SHOULD).
  def test_locator_in_tlv_236
    assert_includes tlv(USID, ISIS::Tlv::Ipv6Reachability).entries.map(&:prefix), "fc00:0:1::/48"
  end

  # An edit four levels down, the End SID's behaviour inside TLV 27,
  # recomputes the LSP's checksum.
  def test_an_edit_deep_down_recomputes
    l = lsp(CLASSIC)
    entry = l.tlvs.find { _1.is_a?(ISIS::Tlv::Srv6Locator) }.entries.first
    entry.subtlvs_of(ISIS::SubTlv::Srv6EndSid).first.instance_variable_set(:@behavior, 2)
    refute_equal CLASSIC, l.to_shex
    assert ISIS.fletcher_ok?(l.encode.byteslice(12..)), "checksum recomputed"
  end
end
