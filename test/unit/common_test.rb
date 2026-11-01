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
