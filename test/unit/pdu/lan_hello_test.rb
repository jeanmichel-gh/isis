# frozen_string_literal: true

require_relative "../../test_helper"

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
