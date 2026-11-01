# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 1, RFC 1142 clause 9.5: code 1, the value length, then each area as
# an Address Length octet and that many octets. The expected hex is our own
# arithmetic from that clause, not a worked example.
class TestTlvAreaAddresses < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # 01 type, 04 length, 03 address length, 490001 the area.
  def test_one_area
    assert_equal "010403490001", ISIS::Tlv::AreaAddresses.new("49.0001").to_shex
  end

  # 01, 08, then 03 490001 and 03 490002.
  def test_two_areas
    assert_equal "01080349000103490002", ISIS::Tlv::AreaAddresses.new("49.0001", "49.0002").to_shex
  end

  # An area of a different length: 01, 05, 04 49000102.
  def test_areas_keep_their_own_length
    assert_equal "01050449000102", ISIS::Tlv::AreaAddresses.new("49.0001.02").to_shex
  end

  def test_no_areas
    assert_equal "0100", ISIS::Tlv::AreaAddresses.new.to_shex
  end

  def test_parse
    tlv = ISIS::Tlv::AreaAddresses.new(octets("01080349000103490002"))
    assert_equal ["49.0001", "49.0002"], tlv.areas.map(&:to_s)
    assert_equal "01080349000103490002", tlv.to_shex
  end

  def test_factory_builds_this_class
    tlv = ISIS::Tlv.factory(octets("010403490001"))
    assert_instance_of ISIS::Tlv::AreaAddresses, tlv
  end

  # 05 says five octets of area, and only abcd follow: not an area, so a
  # tail, replayed.
  def test_entry_that_overruns_is_a_tail
    tlv = ISIS::Tlv::AreaAddresses.new(octets("010305abcd"))
    assert_empty tlv.areas
    assert_equal "05abcd".b, tlv.tail.unpack1("H*").b
    assert_equal "010305abcd", tlv.to_shex
  end

  def test_tail_survives_the_hash
    h = ISIS::Tlv::AreaAddresses.new(octets("01070349000105abcd")).to_hash
    assert_equal({ areas: ["49.0001"], tail: "05abcd" }, h)
    assert_equal "01070349000105abcd", ISIS::Tlv::AreaAddresses.new(h).to_shex
  end

  # The TLV declares 9 octets and 4 arrived. The declared length is a
  # computed field: replayed while nothing moved, computed after an edit.
  def test_clamped_length_replays_until_edited
    tlv = ISIS::Tlv.factory(octets("010903490001"))
    assert tlv.clamped?
    assert_equal "010903490001", tlv.to_shex
    tlv.areas << ISIS::AreaAddress.new("49.0002")
    assert_equal "01080349000103490002", tlv.to_shex
  end

  def test_hash_is_a_list_and_rebuilds
    tlv = ISIS::Tlv::AreaAddresses.new("49.0001", "49.0002")
    assert_equal ["49.0001", "49.0002"], tlv.to_hash
    assert_equal tlv.to_shex, ISIS::Tlv::AreaAddresses.new(tlv.to_hash).to_shex
  end

  # Octets of another type handed to this class keep their type octet.
  def test_type_octet_is_kept
    tlv = ISIS::Tlv::AreaAddresses.new(octets("c70403490001"))
    assert_equal "c70403490001", tlv.to_shex
    assert_equal({ areas: ["49.0001"], type: 199 }, tlv.to_hash)
    assert_equal "c70403490001", ISIS::Tlv::AreaAddresses.new(tlv.to_hash).to_shex
  end

  def test_copy_constructor
    tlv = ISIS::Tlv::AreaAddresses.new("49.0001")
    assert_equal "010403490001", ISIS::Tlv::AreaAddresses.new(tlv).to_shex
  end

  def test_value_is_the_value_octets
    assert_equal "03490001", ISIS::Tlv::AreaAddresses.new("49.0001").value.unpack1("H*")
  end

  def test_in_a_list_hash
    list = ISIS::Tlv::List.new(octets("010403490001"))
    assert_equal({ tlvs: [{ area_addresses: ["49.0001"] }] }, list.to_hash)
  end

  def test_to_s
    assert_equal "Area Addresses 49.0001, 49.0002", ISIS::Tlv::AreaAddresses.new("49.0001", "49.0002").to_s
  end
end
