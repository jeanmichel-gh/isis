# frozen_string_literal: true

require_relative "../../test_helper"

# An LSP from FRR 10.7.1 with flex-algo 128 and link-params on its link,
# captured on ospflab on 2026-11-25 between two FRR containers
# (docs/design/flex-algo.md, "Measured on FRR 10.7.1"). Its link carried
# affinity bit positions 1, 32 and 40, TE metric 77 and delay 5000 us.
#
#   f2...   TLV 242, with the FAD sub-TLV 26, not implemented yet: kept
#   16...   TLV 22: EAG 14, TE Default Metric 18, Unidirectional Link
#           Delay 33, an Adj-SID, and the ASLA sub-TLV 16 with the X bit
class TestLspFlexAlgo < Minitest::Test
  FRR = File.read(File.expand_path("../../fixtures/frr-10.7.1-l2-lsp-flex-algo.hex", __dir__)).strip

  def lsp
    ISIS::Pdu.factory(ISIS::Octets.from_hex(FRR))
  end

  def link
    lsp.tlvs.find { _1.is_a?(ISIS::Tlv::ExtendedIsReachability) }.entries.first.subtlvs
  end

  def test_parses_and_replays
    assert_instance_of ISIS::Pdu::Lsp, lsp
    assert_equal FRR, lsp.to_shex
    assert_equal FRR, ISIS::Pdu::Lsp.new(lsp.to_hash).to_shex, "rebuilds from its hash"
  end

  # FRR numbers the groups by word, as GroupWords does: its own "Bit
  # positions: 1, 32, 40".
  def test_legacy_attributes
    assert_equal [1, 32, 40], link.find { _1.is_a?(ISIS::SubTlv::ExtendedAdminGroup) }.groups
    assert_equal 77, link.find { _1.is_a?(ISIS::SubTlv::TeDefaultMetric) }.metric
    assert_equal 5000, link.find { _1.is_a?(ISIS::SubTlv::LinkDelay) }.delay
  end

  # FRR sets X in the SABM, and the same 0x10 in a UDABM; it sends the
  # average delay, sub-TLV 33, not the Min/Max of sub-TLV 34 that RFC 9350
  # section 5.1's metric type 1 reads.
  def test_asla
    asla = link.find { _1.is_a?(ISIS::SubTlv::Asla) }
    assert_equal %w[X], asla.applications
    refute asla.legacy?
    assert_equal [3], asla.udabm_bits
    assert_equal [1, 32, 40], asla.attribute(ISIS::SubTlv::ExtendedAdminGroup).groups
    assert_equal 77, asla.attribute(ISIS::SubTlv::TeDefaultMetric).metric
    assert_equal 5000, asla.attribute(ISIS::SubTlv::LinkDelay).delay
    assert_nil asla.attribute(ISIS::SubTlv::MinMaxLinkDelay)
  end
end
