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
