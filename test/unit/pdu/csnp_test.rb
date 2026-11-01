# frozen_string_literal: true

require_relative "../../test_helper"

# The CSNP, RFC 1142 clauses 9.10 and 9.11. The main expectation is a CSNP
# captured from FRR 8.4.4; the others are our own arithmetic, laid out
# field by field.
class TestCsnp < Minitest::Test
  # Captured on a veth pair here on 2026-10-31. Field by field:
  #   8321010018010000    common header: LI 33 (8 + 25), PDU type 24
  #   0033                PDU Length 51
  #   00000000000200      Source ID 0000.0000.0002.00
  #   0000000000000000    Start LSP ID, the bottom of the range
  #   ffffffffffffffff    End LSP ID, the top
  #   0910 ...            TLV 9, one entry of 16 octets
  FRR = File.read(File.expand_path("../../fixtures/frr-8.4.4-l1-csnp.hex", __dir__)).strip

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def frr
    ISIS::Pdu.factory(octets(FRR))
  end

  def test_frr_csnp_parses_and_replays
    csnp = frr
    assert_instance_of ISIS::Pdu::Csnp, csnp
    assert_equal [1, "0000.0000.0002.00", "0000.0000.0000.00-00", "ffff.ffff.ffff.ff-ff"],
                 [csnp.level, csnp.source_id_s, csnp.start_lsp_id_s, csnp.end_lsp_id_s]
    assert_equal ["0000.0000.0002.00-00"], csnp.entries.map(&:lsp_id_s)
    assert_equal FRR, csnp.to_shex
  end

  # The whole range is the default, so FRR's CSNP is rebuilt from its
  # Source ID and its entry alone.
  def test_frr_csnp_built_from_values
    built = ISIS::Pdu::Csnp.new(level: 1, source_id: "0000.0000.0002.00", tlvs: frr.tlvs)
    assert_equal FRR, built.to_shex
  end

  # 33 and 51 are both in the PDU and mean different things.
  def test_length_indicator_and_pdu_length_are_different_fields
    o = frr.encode
    assert_equal 33, o.getbyte(1), "Length Indicator"
    assert_equal 51, o.byteslice(8, 2).unpack1("n"), "PDU Length"
  end

  def test_level_2_is_type_25
    l2 = ISIS::Pdu::Csnp.new(level: 2, source_id: "0000.0000.0002.00", tlvs: frr.tlvs)
    assert_equal "19", l2.to_shex[8, 2]
    assert_equal FRR[10..], l2.to_shex[10..]
  end

  # ID Length 2: LI 8 + 2 + 3 + 4 + 4 = 21 (15), an empty body, so the PDU
  # Length is 21 (0015) too.
  def test_two_octet_ids
    hex = "831501021801 0000".delete(" ") + "0015" "010200" "01020000" "0102ffff"
    csnp = ISIS::Pdu.factory(octets(hex))
    assert_equal ["0102.00", "0102.00-00", "0102.ff-ff"], [csnp.source_id_s, csnp.start_lsp_id_s, csnp.end_lsp_id_s]
    assert_equal hex, csnp.to_shex
    assert_equal hex, ISIS::Pdu::Csnp.new(level: 1, source_id: "0102.00", start_lsp_id: "0102.00-00",
                                          end_lsp_id: "0102.ff-ff").to_shex
  end

  # The ID Length reaches the entries: with 2 octet IDs an entry is 12
  # octets.
  def test_id_length_reaches_the_entries
    hex = "831501021801 0000".delete(" ") + "0023" "010200" "01020000" "0102ffff" "090c" "0001" "01020000" "00000001" "abcd"
    csnp = ISIS::Pdu.factory(octets(hex))
    assert_equal ["0102.00-00"], csnp.entries.map(&:lsp_id_s)
    assert_equal hex, csnp.to_shex
  end

  def test_lsp_ids_must_match_the_source_id_width
    assert_raises(ArgumentError) do
      ISIS::Pdu::Csnp.new(level: 1, source_id: "0000.0000.0002.00", start_lsp_id: "0102.00-00")
    end
  end

  def test_entries_from_every_tlv_9
    entry = { lifetime: 1, lsp_id: "0000.0000.0002.00-00", sequence: 1, checksum: 1 }
    csnp = ISIS::Pdu::Csnp.new(level: 1, source_id: "0000.0000.0002.00",
                               tlvs: [ISIS::Tlv::LspEntries.new(entry),
                                      ISIS::Tlv::LspEntries.new(entry.merge(lsp_id: "0000.0000.0003.00-00"))])
    assert_equal %w[0000.0000.0002.00-00 0000.0000.0003.00-00], csnp.entries.map(&:lsp_id_s)
  end

  # A PDU Length that claims more than arrived is replayed, until an
  # entry changes.
  def test_declared_length_replays_until_edited
    hex = FRR.sub("00330000", "00400000")
    csnp = ISIS::Pdu.factory(octets(hex))
    assert csnp.preserved?
    assert_equal hex, csnp.to_shex
    csnp.entries.first.sequence = 3
    refute csnp.preserved?
    assert_equal "0033", csnp.to_shex[16, 4]
  end

  def test_hash_rebuilds
    assert_equal FRR, ISIS::Pdu::Csnp.new(frr.to_hash).to_shex
  end

  def test_copy_constructor
    assert_equal FRR, ISIS::Pdu::Csnp.new(frr).to_shex
  end

  def test_cut_inside_the_fixed_header_is_truncated
    assert_instance_of ISIS::Pdu::Truncated, ISIS::Pdu.factory(octets(FRR[0, 40]))
  end

  def test_pdu_length_below_the_fixed_header_is_malformed
    hex = FRR.sub("00330000", "00050000")
    assert_instance_of ISIS::Pdu::Malformed, ISIS::Pdu.factory(octets(hex))
  end

  def test_to_s
    assert_equal "L1 CSNP from 0000.0000.0002.00, 0000.0000.0000.00-00 to ffff.ffff.ffff.ff-ff, 1 entries", frr.to_s
  end

  # FRR 8.4.4 with HMAC-MD5 (RFC 5304), key "isis4r-key": it replays, and with
  # every computed field thrown away and the key given, isis4r writes
  # FRR's octets again, digest included. A wrong key gives another digest.
  HMAC_MD5 = File.read(File.expand_path("../../fixtures/frr-8.4.4-l1-csnp-hmac-md5.hex", __dir__)).strip

  def test_frr_hmac_md5_csnp_replays_and_rebuilds
    pdu = ISIS::Pdu.factory(ISIS::Octets.from_hex(HMAC_MD5))
    assert_instance_of ISIS::Pdu::Csnp, pdu
    assert_equal HMAC_MD5, pdu.to_shex
    assert pdu.authentication_preserved?
    pdu.key = "isis4r-key"
    pdu.recompute!
    assert_equal HMAC_MD5, pdu.to_shex
    pdu.key = "wrong"
    refute_equal HMAC_MD5, pdu.to_shex
  end
end
