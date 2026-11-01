# frozen_string_literal: true

require_relative "../../test_helper"

# The point to point hello, RFC 1142 clause 9.7, with the field order FRR
# and Wireshark use (see the class). The expected hex is our own arithmetic
# from that clause, laid out field by field below.
class TestP2pHello < Minitest::Test
  # Common header: 83 IRPD, 14 Length Indicator (8 + 12 = 20), 01, 00 ID
  # Length (six octets), 11 PDU type 17, 01 version, 00 reserved, 00 max
  # area addresses.
  COMMON = "8314010011010000"
  # Fixed header: 03 circuit type L1 and L2, 192168001001 Source ID, 001e
  # holding time 30, 002a PDU Length (20 + 22 = 42), 01 local circuit ID.
  FIXED = "03" "192168001001" "001e" "002a" "01"
  # TLVs, 22 octets: area 49.0001 (6), IPv4 (3), 10.0.0.1 (6), and TLV 240
  # Down with extended circuit 1 (7).
  TLVS = "010403490001" "8101cc" "84040a000001" "f0050200000001"
  HELLO = COMMON + FIXED + TLVS

  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def tlvs
    [ISIS::Tlv::AreaAddresses.new("49.0001"), ISIS::Tlv::ProtocolsSupported.new(:ipv4),
     ISIS::Tlv::IpInterfaceAddresses.new("10.0.0.1"),
     ISIS::Tlv::ThreeWayAdjacency.new(:down, extended_circuit_id: 1)]
  end

  def built
    ISIS::Pdu::P2pHello.new(circuit_type: :l1l2, source_id: "1921.6800.1001", holding_time: 30,
                            local_circuit_id: 1, tlvs: tlvs)
  end

  def test_built_from_fields
    assert_equal HELLO, built.to_shex
  end

  # 20 and 42 are both in the PDU and mean different things.
  def test_length_indicator_and_pdu_length_are_different_fields
    o = built.encode
    assert_equal 20, o.getbyte(1), "Length Indicator"
    assert_equal 42, o.byteslice(17, 2).unpack1("n"), "PDU Length"
  end

  # Circuit type numbers from clause 9.7: 1 L1 only, 2 L2 only, 3 both.
  def test_circuit_type_numbers
    { l1: "01", l2: "02", l1l2: "03" }.each do |sym, hex|
      hello = ISIS::Pdu::P2pHello.new(circuit_type: sym, source_id: "1921.6800.1001", holding_time: 30,
                                      local_circuit_id: 1)
      assert_equal hex, hello.to_shex[16, 2], sym.to_s
    end
  end

  def test_parse_through_the_factory
    pdu = ISIS::Pdu.factory(octets(HELLO))
    assert_instance_of ISIS::Pdu::P2pHello, pdu
    assert_equal :l1l2, pdu.circuit_type
    assert_equal "1921.6800.1001", pdu.source_id_s
    assert_equal 30, pdu.holding_time
    assert_equal 1, pdu.local_circuit_id
    assert_equal [ISIS::Tlv::AreaAddresses, ISIS::Tlv::ProtocolsSupported, ISIS::Tlv::IpInterfaceAddresses,
                  ISIS::Tlv::ThreeWayAdjacency], pdu.tlvs.map(&:class)
    assert_equal HELLO, pdu.to_shex
  end

  def test_level_is_not_a_field
    assert_raises(ArgumentError) do
      ISIS::Pdu::P2pHello.new(level: 1, source_id: "1921.6800.1001", holding_time: 30, local_circuit_id: 1)
    end
  end

  # ID Length 8: LI 8 + 14 = 22 (16), an eight octet Source ID, and TLV 240
  # with an eight octet neighbour ID read with that width. PDU Length 22 +
  # 21 = 43 (2b).
  def test_eight_octet_ids_reach_the_tlvs
    hex = "831601081101 0000".delete(" ") + "03" "0102030405060708" "001e" "002b" "01" \
          "f0130000000001" "1112131415161718" "00000002"
    pdu = ISIS::Pdu.factory(octets(hex))
    assert_equal 8, pdu.source_id.bytesize
    assert_equal "1112131415161718", pdu.tlvs.first.neighbor_system_id.unpack1("H*")
    assert_equal hex, pdu.to_shex
  end

  def test_built_with_eight_octet_ids_writes_id_length_8
    hello = ISIS::Pdu::P2pHello.new(circuit_type: :l1, source_id: "0102.0304.0506.0708", holding_time: 9,
                                    local_circuit_id: 2)
    assert_equal "08", hello.to_shex[6, 2]
    assert_equal 22, hello.encode.getbyte(1)
  end

  # Circuit Type octet ff: type 3, and six reserved bits set, which are
  # kept, echoed and carried by the hash.
  def test_reserved_circuit_bits_are_echoed
    hex = COMMON + "ff" + FIXED[2..] + TLVS
    pdu = ISIS::Pdu.factory(octets(hex))
    assert_equal :l1l2, pdu.circuit_type
    assert_equal 0xfc, pdu.circuit_reserved_bits
    assert_equal hex, pdu.to_shex
    assert_equal 0xfc, pdu.to_hash[:circuit_bits]
    assert_equal hex, ISIS::Pdu::P2pHello.new(pdu.to_hash).to_shex
  end

  def test_setting_the_circuit_type_keeps_reserved_bits
    pdu = ISIS::Pdu.factory(octets(COMMON + "fd" + FIXED[2..] + TLVS))
    pdu.circuit_type = :l2
    assert_equal "fe", pdu.to_shex[16, 2]
  end

  # 0 is reserved and the receive policy ignores such a PDU; the codec
  # keeps it.
  def test_circuit_type_zero_is_kept
    hex = COMMON + "00" + FIXED[2..] + TLVS
    assert_equal 0, ISIS::Pdu.factory(octets(hex)).circuit_type
    assert_equal hex, ISIS::Pdu.factory(octets(hex)).to_shex
  end

  # A PDU Length of 0x0030 claims more than arrived: replayed as declared,
  # computed again once a TLV is added (42 + 2 = 44, 0x002c).
  def test_declared_length_replays_until_edited
    hex = COMMON + FIXED.sub("002a", "0030") + TLVS
    pdu = ISIS::Pdu.factory(octets(hex))
    assert pdu.preserved?
    assert_equal hex, pdu.to_shex
    pdu.tlvs << ISIS::Tlv::Padding.new
    refute pdu.preserved?
    assert_equal "002c", pdu.to_shex[34, 4]
  end

  # A same size edit in a TLV moves the content, so a wrong length is
  # recomputed.
  def test_edit_inside_a_tlv_recomputes
    hex = COMMON + FIXED.sub("002a", "0030") + TLVS
    pdu = ISIS::Pdu.factory(octets(hex))
    pdu.tlvs.to_a.last.state = :up
    assert_equal "002a", pdu.to_shex[34, 4]
  end

  def test_cut_inside_the_fixed_header_is_truncated
    assert_instance_of ISIS::Pdu::Truncated, ISIS::Pdu.factory(octets(COMMON + "03" + "1921680010"))
  end

  def test_pdu_length_below_the_fixed_header_is_malformed
    hex = COMMON + FIXED.sub("002a", "0005") + TLVS
    pdu = ISIS::Pdu.factory(octets(hex))
    assert_instance_of ISIS::Pdu::Malformed, pdu
    assert_equal hex, pdu.to_shex
  end

  def test_octets_after_the_pdu_are_left
    input = octets(HELLO + "aabb")
    ISIS::Pdu.factory(input)
    assert_equal "aabb", input.unpack1("H*")
  end

  def test_hash_rebuilds
    h = built.to_hash
    assert_equal :p2p_hello, h[:type]
    assert_equal({ circuit_type: :l1l2, source_id: "1921.6800.1001", holding_time: 30, local_circuit_id: 1 },
                 h.slice(:circuit_type, :source_id, :holding_time, :local_circuit_id))
    assert_equal HELLO, ISIS::Pdu::P2pHello.new(h).to_shex
  end

  def test_copy_constructor
    assert_equal HELLO, ISIS::Pdu::P2pHello.new(built).to_shex
  end

  def test_refusals
    base = { circuit_type: :l1, source_id: "1921.6800.1001", holding_time: 30, local_circuit_id: 1 }
    assert_raises(ArgumentError) { ISIS::Pdu::P2pHello.new(**base, circuit_type: :both) }
    assert_raises(ArgumentError) { ISIS::Pdu::P2pHello.new(**base, holding_time: 65_536) }
    assert_raises(ArgumentError) { ISIS::Pdu::P2pHello.new(**base, local_circuit_id: 256) }
  end

  def test_to_s
    assert_equal "P2P hello l1l2 from 1921.6800.1001, holding 30, circuit 1, 4 TLVs", built.to_s
  end

  # FRR 8.4.4 with HMAC-MD5 (RFC 5304), key "isis4r-hello": it replays, and with
  # every computed field thrown away and the key given, isis4r writes
  # FRR's octets again, digest included. A wrong key gives another digest. FRR pads the hello to 1497
  # octets, and the digest covers the padding (RFC 5304 section 2).
  HMAC_MD5 = File.read(File.expand_path("../../fixtures/frr-8.4.4-p2p-hello-hmac-md5.hex", __dir__)).strip

  def test_frr_hmac_md5_hello_replays_and_rebuilds
    pdu = ISIS::Pdu.factory(ISIS::Octets.from_hex(HMAC_MD5))
    assert_instance_of ISIS::Pdu::P2pHello, pdu
    assert_equal HMAC_MD5, pdu.to_shex
    assert pdu.authentication_preserved?
    pdu.key = "isis4r-hello"
    pdu.recompute!
    assert_equal HMAC_MD5, pdu.to_shex
    pdu.key = "wrong"
    refute_equal HMAC_MD5, pdu.to_shex
  end
end
