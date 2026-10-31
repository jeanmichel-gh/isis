# frozen_string_literal: true

require_relative "test_helper"

class TestSystemId < Minitest::Test
  def test_parse_and_render
    assert_equal "1921.6800.1001", ISIS::SystemId.new("1921.6800.1001").to_s
  end

  def test_encode_is_six_bytes
    assert_equal "192168001001", ISIS::SystemId.new("1921.6800.1001").encode.unpack1("H*")
  end

  def test_from_bytes_roundtrip
    sid = ISIS::SystemId.new("0000.0000.0001")
    assert_equal sid, ISIS::SystemId.from_bytes(sid.encode)
  end

  def test_equality_and_hash
    a = ISIS::SystemId.new("0000.0000.0001")
    b = ISIS::SystemId.new("0000.0000.0001")
    assert_equal a, b
    assert_equal a.hash, b.hash
  end

  def test_rejects_bad
    assert_raises(ArgumentError) { ISIS::SystemId.new("12.34") }
  end
end

class TestLlc < Minitest::Test
  def test_wrap_unwrap
    pdu = "hello".b
    wrapped = ISIS::Llc.wrap(pdu)
    assert_equal "\xFE\xFE\x03".b, wrapped[0, 3]
    assert_equal pdu, ISIS::Llc.unwrap(wrapped)
  end

  def test_isis_predicate
    assert ISIS::Llc.isis?(ISIS::Llc.wrap("x"))
    refute ISIS::Llc.isis?("\x00\x00\x00abc".b)
  end

  def test_unwrap_rejects_non_isis
    assert_raises(ISIS::ParseError) { ISIS::Llc.unwrap("\xAA\xAA\x03".b) }
  end
end

class TestTlv < Minitest::Test
  def test_roundtrip
    entries = [[1, "\x03\x49\x00\x01".b], [129, "\xCC".b]]
    assert_equal entries, ISIS::Tlv.parse(ISIS::Tlv.encode(entries))
  end

  def test_truncated_tail_is_dropped
    # type 1, length 5, but only 2 value bytes present
    assert_equal [], ISIS::Tlv.parse("\x01\x05ab".b)
  end
end

class TestLanHello < Minitest::Test
  def build
    ISIS::LanHello.new(
      source_id: "0000.0000.0001",
      holding_time: 27,
      priority: 64,
      area_addresses: ["49.0001"],
      neighbors: ["00:00:00:00:00:02"],
      protocols: [ISIS::NLPID_IPV4]
    )
  end

  def test_roundtrip_fields
    h = ISIS::LanHello.parse(build.encode)
    assert_equal ISIS::L1_LAN_IIH, h.pdu_type
    assert_equal "0000.0000.0001", h.source_id.to_s
    assert_equal 27, h.holding_time
    assert_equal 64, h.priority
    assert_equal ["490001"], h.area_strings
    assert_equal [Datalink::MAC.new("00:00:00:00:00:02")], h.neighbors
    assert_equal [ISIS::NLPID_IPV4], h.protocols
  end

  def test_starts_with_irpd
    assert_equal ISIS::IRPD, build.encode.getbyte(0)
  end

  def test_header_length_indicator
    assert_equal ISIS::LanHello::HEADER_LEN, build.encode.getbyte(1)
  end

  def test_pdu_length_field_matches
    bytes = build.encode
    declared = bytes[17, 2].unpack1("n")
    assert_equal bytes.bytesize, declared
  end

  def test_empty_neighbor_list_roundtrips
    h = ISIS::LanHello.new(source_id: "0000.0000.0001", area_addresses: ["49.0001"], neighbors: [])
    parsed = ISIS::LanHello.parse(h.encode)
    assert_empty parsed.neighbors
  end

  def test_rejects_non_isis
    assert_raises(ISIS::ParseError) { ISIS::LanHello.parse("\x00" * 27) }
  end
end
