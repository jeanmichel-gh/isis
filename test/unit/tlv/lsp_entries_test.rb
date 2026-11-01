# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 9, RFC 1142 clause 9.10: code 9, then entries of Remaining Lifetime
# (2), LSP ID (ID Length + 2), Sequence Number (4) and Checksum (2). The
# first expectation is FRR's: the entry in a CSNP captured from FRR 8.4.4,
# describing the LSP in test/fixtures/frr-8.4.4-l1-lsp.hex.
class TestTlvLspEntries < Minitest::Test
  # 09 type, 10 length 16, 046c lifetime 1132, 0000000000020000 LSP ID,
  # 00000002 sequence, 6c27 checksum.
  FRR = "0910" "046c" "0000000000020000" "00000002" "6c27"
  ENTRY = { lifetime: 1132, lsp_id: "0000.0000.0002.00-00", sequence: 2, checksum: 0x6c27 }.freeze

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def test_frr_entry_parses
    tlv = ISIS::Tlv.factory(octets(FRR))
    assert_instance_of ISIS::Tlv::LspEntries, tlv
    assert_equal [ENTRY], tlv.to_hash
    assert_equal FRR, tlv.to_shex
  end

  def test_built_from_fields
    assert_equal FRR, ISIS::Tlv::LspEntries.new(ENTRY).to_shex
  end

  # Two entries, 32 octets, length 20.
  def test_two_entries
    second = ENTRY.merge(lsp_id: "0000.0000.0003.00-01", sequence: 9)
    assert_equal "0920" + FRR[4..] + "046c" "0000000000030001" "00000009" "6c27",
                 ISIS::Tlv::LspEntries.new(ENTRY, second).to_shex
  end

  # With ID Length 8 an entry is 18 octets, and a 16 octet value is not a
  # whole one: the width has to come from the PDU, and here it does.
  def test_id_width_sets_the_entry_size
    hex = "0912" "0001" "01020304050607080001" "00000005" "abcd"
    tlv = ISIS::Tlv.factory(octets(hex), id_width: 8)
    assert_equal "0102.0304.0506.0708.00-01", tlv.entries.first.lsp_id_s
    assert_equal hex, tlv.to_shex
    assert_equal hex, ISIS::Tlv::LspEntries.new(tlv).to_shex
  end

  # Read with the default six, the same octets are one entry and a tail.
  def test_default_width_is_six
    tlv = ISIS::Tlv.factory(octets("0912" "0001" "01020304050607080001" "00000005" "abcd"))
    assert_equal 1, tlv.entries.size
    assert_equal "abcd", tlv.tail.unpack1("H*")
  end

  def test_part_entry_is_a_tail
    hex = FRR.sub(/\A0910/, "0913") + "ffffff"
    tlv = ISIS::Tlv.factory(octets(hex))
    assert_equal({ entries: [ENTRY], tail: "ffffff" }, tlv.to_hash)
    assert_equal hex, tlv.to_shex
    assert_equal hex, ISIS::Tlv::LspEntries.new(tlv.to_hash).to_shex
  end

  def test_hash_rebuilds
    tlv = ISIS::Tlv::LspEntries.new(ENTRY, ENTRY.merge(sequence: 3))
    assert_equal tlv.to_shex, ISIS::Tlv::LspEntries.new(tlv.to_hash).to_shex
  end

  def test_none_is_an_empty_value
    assert_equal "0900", ISIS::Tlv::LspEntries.new([]).to_shex
  end

  def test_fields_that_do_not_fit_are_refused
    assert_raises(ArgumentError) { ISIS::Tlv::LspEntries.new(ENTRY.merge(sequence: 2**32)) }
    assert_raises(ArgumentError) { ISIS::Tlv::LspEntries.new(ENTRY.merge(checksum: 65_536)) }
  end

  def test_to_s
    assert_equal "LSP Entries 0000.0000.0002.00-00 seq 0x00000002 lifetime 1132 checksum 0x6c27",
                 ISIS::Tlv::LspEntries.new(ENTRY).to_s
  end
end
