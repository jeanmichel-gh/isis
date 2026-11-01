# frozen_string_literal: true

require_relative "../../test_helper"

# The Link State PDU, RFC 1142 clauses 9.8 and 9.9. Two kinds of
# expectation: an LSP captured from FRR, and hex laid out field by field
# below, which is our own arithmetic from the clause.
class TestLsp < Minitest::Test
  # An L1 LSP from FRR 8.4.4's isisd, captured on a veth pair here on
  # 2026-10-31 by asking for it with a PSNP. Field by field:
  #   831b010012010000  common header: LI 27 (8 + 19), PDU type 18
  #   0029              PDU Length 41
  #   04a0              Remaining Lifetime 1184
  #   0000000000020000  LSP ID 0000.0000.0002.00-00
  #   00000002          Sequence Number 2
  #   6c27              Checksum, which FRR's database also shows
  #   01                flags: IS type 1, nothing else set
  #   0104034900 01     TLV 1, area 49.0001
  #   89066c7370636170  TLV 137, the hostname "lspcap", not implemented
  FRR = File.read(File.expand_path("../../fixtures/frr-8.4.4-l1-lsp.hex", __dir__)).strip

  # Our own: the same header shape with a TLV 1 only, for 1921.6800.1001.
  # PDU Length 27 + 6 = 33 (0021). The checksum is the library's arithmetic,
  # and test_checksum_sums_to_zero checks it independently.
  def built(**over)
    ISIS::Pdu::Lsp.new(level: 1, lsp_id: "1921.6800.1001.00-00", lifetime: 1200, sequence: 7,
                       tlvs: [ISIS::Tlv::AreaAddresses.new("49.0001")], **over)
  end

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def frr
    ISIS::Pdu.factory(octets(FRR))
  end

  def test_frr_lsp_parses_and_replays
    lsp = frr
    assert_instance_of ISIS::Pdu::Lsp, lsp
    assert_equal [1, "0000.0000.0002.00-00", 1184, 2, 0x6c27, 1],
                 [lsp.level, lsp.lsp_id_s, lsp.lifetime, lsp.sequence, lsp.checksum, lsp.is_type]
    assert_equal FRR, lsp.to_shex
    assert lsp.checksum_ok?
  end

  # Built from the same values, the library computes the checksum FRR did.
  def test_frr_lsp_built_from_values
    built = ISIS::Pdu::Lsp.new(level: 1, lsp_id: "0000.0000.0002.00-00", lifetime: 1184, sequence: 2,
                               tlvs: frr.tlvs)
    assert_equal FRR, built.to_shex
  end

  def test_built_from_fields
    assert_equal "831b010012010000" "0021" "04b0" "1921680010010000" "00000007",
                 built.to_shex[0, 48]
    assert_equal "01" "010403490001", built.to_shex[52..]
  end

  # The receiver's test, which the library's arithmetic did not write.
  def test_checksum_sums_to_zero
    assert ISIS.fletcher_ok?(built.encode.byteslice(12..))
  end

  # 27 and 33 are both in the PDU and mean different things.
  def test_length_indicator_and_pdu_length_are_different_fields
    o = built.encode
    assert_equal 27, o.getbyte(1), "Length Indicator"
    assert_equal 33, o.byteslice(8, 2).unpack1("n"), "PDU Length"
  end

  def test_level_2_is_type_20_and_is_type_3
    l2 = built(level: 2)
    assert_equal "14", l2.to_shex[8, 2]
    assert_equal 3, l2.is_type
  end

  # Each mask against the number RFC 1142 clause 9.8 gives, bit 1 being
  # the least significant: P bit 8 (0x80), ATT bits 7 to 4 with error 7
  # (0x40), expense 6 (0x20), delay 5 (0x10) and default 4 (0x08),
  # LSPDBOL bit 3 (0x04), IS Type bits 1 and 2 (0x03). From the clause, not
  # from the class: a reversed ATT writes 0x40 for default and fails here.
  def test_flag_masks_are_the_clauses
    flags = ->(**f) { built(is_type: 0, **f).encode.getbyte(26) }
    assert_equal 0x80, flags.call(partition: true)
    assert_equal 0x40, flags.call(attached: [:error])
    assert_equal 0x20, flags.call(attached: [:expense])
    assert_equal 0x10, flags.call(attached: [:delay])
    assert_equal 0x08, flags.call(attached: [:default])
    assert_equal 0x04, flags.call(overload: true)
    assert_equal 0x03, flags.call(is_type: 3)
  end

  # Structure only: every bit is claimed, and none twice. It cannot tell a
  # reversed ATT from the right one, which is why the test above exists.
  def test_flag_masks_tile_the_octet
    masks = [ISIS::Pdu::Lsp::PARTITION, *ISIS::Pdu::Lsp::ATTACHED.values, ISIS::Pdu::Lsp::OVERLOAD,
             ISIS::Pdu::Lsp::IS_TYPE]
    assert_equal 0xff, masks.reduce(:|)
    masks.combination(2).each { |a, b| assert_equal 0, a & b, format("0x%02x and 0x%02x overlap", a, b) }
  end

  # Last, the round trip, which passes when encoder and decoder share a
  # mistake and so is never the only test.
  def test_flags_round_trip
    lsp = built(partition: true, attached: %i[default delay], overload: true)
    back = ISIS::Pdu.factory(octets(lsp.to_shex))
    assert back.partition?
    assert_equal %i[delay default], back.attached
    assert back.overload?
    assert_equal 1, back.is_type
  end

  # A capture whose checksum is wrong replays wrong. It cannot pass by the
  # recomputation agreeing, since the right checksum is 6c27.
  def test_wrong_checksum_replays_wrong
    hex = FRR.sub("6c27", "dead")
    lsp = ISIS::Pdu.factory(octets(hex))
    assert lsp.checksum_preserved?
    assert_equal hex, lsp.to_shex
    refute lsp.checksum_ok?
  end

  # 1. An edit inside a TLV, one level down, recomputes the checksum.
  def test_edit_inside_a_tlv_recomputes_the_checksum
    lsp = ISIS::Pdu.factory(octets(FRR.sub("6c27", "dead")))
    lsp.tlvs.first.areas = [ISIS::AreaAddress.new("49.0002")]
    refute lsp.checksum_preserved?
    assert lsp.checksum_ok?
  end

  def test_sequence_edit_recomputes_the_checksum
    lsp = frr
    lsp.sequence = 3
    refute_equal 0x6c27, lsp.checksum
    assert lsp.checksum_ok?
  end

  # 2. The common header is outside the span, so an unauthenticated LSP
  # keeps its checksum, wrong or right.
  def test_common_header_edit_keeps_the_checksum
    lsp = ISIS::Pdu.factory(octets(FRR.sub("6c27", "dead")))
    lsp.header.max_area_addresses = 3
    assert lsp.checksum_preserved?
    assert_equal "dead", lsp.to_shex[48, 4]
  end

  # 4. Remaining Lifetime is outside the span, so aging keeps the checksum,
  # and does not count as an edit for the lengths either.
  def test_lifetime_edit_keeps_checksum_and_lengths
    hex = FRR.sub("6c27", "dead").sub("002904a0", "003004a0")
    lsp = ISIS::Pdu.factory(octets(hex))
    lsp.lifetime = 100
    assert lsp.checksum_preserved?
    assert lsp.preserved?
    assert_equal hex.sub("04a0", "0064"), lsp.to_shex
  end

  # 5. Two encodes in a row give the same octets, so the checksum does not
  # trigger itself.
  def test_encode_is_stable
    lsp = built
    assert_equal lsp.to_shex, lsp.to_shex
    edited = frr
    edited.sequence = 9
    assert_equal edited.to_shex, edited.to_shex
  end

  def test_recompute_drops_a_wrong_checksum
    lsp = ISIS::Pdu.factory(octets(FRR.sub("6c27", "dead")))
    lsp.recompute!
    assert_equal FRR, lsp.to_shex
  end

  # ID Length 8: LI 8 + 21 = 29 (1d), a ten octet LSP ID, and the checksum
  # still over the span from the LSP ID.
  def test_eight_octet_ids
    lsp = ISIS::Pdu::Lsp.new(level: 1, lsp_id: "0102.0304.0506.0708.00-01", lifetime: 60, sequence: 1)
    o = lsp.encode
    assert_equal [29, 8, 29], [o.getbyte(1), o.getbyte(3), o.byteslice(8, 2).unpack1("n")]
    assert_equal "0102.0304.0506.0708.00-01", ISIS::Pdu.factory(octets(lsp.to_shex)).lsp_id_s
    assert lsp.checksum_ok?
  end

  def test_lsp_id_presentation_parses_back
    lsp = built(lsp_id: "1921.6800.1001.01-02")
    assert_equal "1921.6800.1001.01-02", lsp.lsp_id_s
    assert_equal "1921680010010102", lsp.lsp_id.unpack1("H*")
  end

  def test_hash_rebuilds
    lsp = built(attached: [:default], overload: true)
    assert_equal lsp.to_shex, ISIS::Pdu::Lsp.new(lsp.to_hash).to_shex
    assert_equal FRR, ISIS::Pdu::Lsp.new(frr.to_hash).to_shex
  end

  # The hash carries no computed field, so a wrong checksum is lost through
  # it and recomputed. To replay the lie, replay the octets.
  def test_hash_does_not_carry_the_checksum
    lsp = ISIS::Pdu.factory(octets(FRR.sub("6c27", "dead")))
    refute lsp.to_hash.key?(:checksum)
    assert_equal FRR, ISIS::Pdu::Lsp.new(lsp.to_hash).to_shex
  end

  def test_copy_constructor
    assert_equal FRR, ISIS::Pdu::Lsp.new(frr).to_shex
  end

  def test_fields_that_do_not_fit_are_refused
    assert_raises(ArgumentError) { built(sequence: 2**32) }
    assert_raises(ArgumentError) { built(lifetime: 65_536) }
    assert_raises(ArgumentError) { built(attached: [:bogus]) }
  end

  def test_cut_inside_the_fixed_header_is_truncated
    assert_instance_of ISIS::Pdu::Truncated, ISIS::Pdu.factory(octets(FRR[0, 40]))
  end

  def test_pdu_length_below_the_fixed_header_is_malformed
    hex = FRR.sub("002904a0", "000504a0")
    pdu = ISIS::Pdu.factory(octets(hex))
    assert_instance_of ISIS::Pdu::Malformed, pdu
    assert_equal hex, pdu.to_shex
  end

  def test_to_s
    assert_equal "L1 LSP 0000.0000.0002.00-00, sequence 0x00000002, lifetime 1184, checksum 0x6c27, " \
                 "IS type 1, 2 TLVs", frr.to_s
  end
end
