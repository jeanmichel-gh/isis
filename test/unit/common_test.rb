# frozen_string_literal: true

require_relative "../test_helper"

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

class TestOctets < Minitest::Test
  def test_from_hex_ignores_whitespace
    assert_equal "010403490001", ISIS::Octets.from_hex("01 04 03490001").to_shex
  end

  def test_from_hex_refuses_non_hex_and_odd_length
    assert_raises(ArgumentError) { ISIS::Octets.from_hex("0g") }
    assert_raises(ArgumentError) { ISIS::Octets.from_hex("010") }
  end

  def test_is_binary_even_from_utf8
    o = ISIS::Octets.new("é")
    assert_equal Encoding::BINARY, o.encoding
    assert_equal 2, o.bytesize
  end

  def test_is_a_string_and_carries_the_mark
    o = ISIS::Octets.new("ab")
    assert_kind_of String, o
    assert_kind_of ISIS::Octets, o
    refute_kind_of ISIS::Octets, "ab".b
  end
end

class TestBuffer < Minitest::Test
  # On a binary buffer, << with an Integer appends one octet. On a UTF-8
  # buffer it would append a codepoint, two octets for 0xe9.
  def test_buffer_appends_integers_as_single_octets
    buf = ISIS.buffer
    buf << 0xe9
    assert_equal Encoding::BINARY, buf.encoding
    assert_equal "e9", buf.unpack1("H*")
  end
end

# The presentation form is a convention (see the class), so ntop and pton
# are checked separately and then as a round trip.
class TestAreaAddress < Minitest::Test
  HEX = "490001"

  def test_ntop
    assert_equal "49.0001", ISIS::AreaAddress.new_ntop([HEX].pack("H*")).to_s
  end

  def test_pton
    assert_equal HEX, ISIS::AreaAddress.new("49.0001").to_shex
  end

  def test_round_trip
    assert_equal HEX, ISIS::AreaAddress.new(ISIS::AreaAddress.new_ntop([HEX].pack("H*")).to_s).to_shex
  end

  def test_groups_after_the_first_octet
    assert_equal "39.0f01.0002.0000.0c00.1111", ISIS::AreaAddress.new("390f0100020000 0c001111".delete(" ")).to_s
    assert_equal "49.0001.02", ISIS::AreaAddress.new("49000102").to_s
    assert_equal "49", ISIS::AreaAddress.new("49").to_s
  end

  def test_dots_are_separators_only
    assert_equal HEX, ISIS::AreaAddress.new("4900.01").to_shex
  end

  def test_odd_hex_is_refused
    assert_raises(ArgumentError) { ISIS::AreaAddress.new("49.001") }
  end

  def test_more_than_255_octets_is_refused
    assert_raises(ArgumentError) { ISIS::AreaAddress.new("00" * 256) }
  end
end

# The ISO 8473 checksum, checked against an LSP captured from FRR 8.4.4:
# FRR wrote 6c27 over the span from the LSP ID to the end.
class TestFletcher < Minitest::Test
  SPAN = "0000000000020000" "00000002" "6c27" "01" "010403490001" "89066c7370636170"

  def span(hex = SPAN)
    [hex].pack("H*")
  end

  def test_frr_checksum
    zeroed = span(SPAN.sub("6c27", "0000"))
    assert_equal "6c27", ISIS.fletcher(zeroed, 12).unpack1("H*")
  end

  def test_receiver_check
    assert ISIS.fletcher_ok?(span)
    refute ISIS.fletcher_ok?(span(SPAN.sub("6c27", "6c28")))
  end

  # A checksum octet that comes out 0 is written as 255, the same value
  # modulo 255, since zero would read as "not computed". Over 01 7e 00 00,
  # C0 runs 1, 127, 127, 127 and C1 runs 1, 128, 0, 127. With one octet
  # after X, X = (1 * 127 - 127) % 255 = 0, written ff, and Y = (127 - 2 *
  # 127) % 255 = 128, 80. The sums still check out with ff in place.
  def test_zero_octet_is_written_as_255
    assert_equal "ff80", ISIS.fletcher(["017e0000"].pack("H*"), 2).unpack1("H*")
    assert ISIS.fletcher_ok?(["017eff80"].pack("H*"))
  end

  # RFC 2202 section 2, HMAC-MD5 test cases 1, 2, 3, 6 and 7, the
  # document's own values. 6 and 7 have an 80 octet key, longer than the
  # 64 octet block, so they cover the hashing of the key first.
  def test_hmac_md5_rfc_2202
    long = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    [[["0b" * 16].pack("H*"), "Hi There", "9294727a3638bb1c13f48ef8158bfc9d"],
     ["Jefe", "what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738"],
     [["aa" * 16].pack("H*"), ["dd" * 50].pack("H*"), "56be34521d144c88dbb8c733f0e8b3f6"],
     [["aa" * 80].pack("H*"), "Test Using Larger Than Block-Size Key - Hash Key First", "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"],
     [["aa" * 80].pack("H*"), long, "6f630fad67cda0ee1fb1f562db3aa53e"]].each_with_index do |(key, data, digest), i|
      assert_equal digest, ISIS.hmac_md5(key, data).unpack1("H*"), "RFC 2202 HMAC-MD5 case #{[1, 2, 3, 6, 7][i]}"
    end
  end
end
