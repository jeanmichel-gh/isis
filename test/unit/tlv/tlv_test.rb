# frozen_string_literal: true

require_relative "../../test_helper"

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
