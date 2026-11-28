# frozen_string_literal: true

require_relative "../test_helper"

# ISIS::Srv6::BEHAVIORS, the "SRv6 Endpoint Behaviors" registry: RFC 8986
# section 10.2.2, Table 6, and RFC 9800 section 12.1. Each number and
# name asserted here is read off those tables, not off the code.
class TestSrv6 < Minitest::Test
  S = ISIS::Srv6

  def test_rfc_8986_codepoints
    { 1 => "End", 5 => "End.X", 9 => "End.T", 16 => "End.DX6", 17 => "End.DX4", 18 => "End.DT6", 19 => "End.DT4",
      20 => "End.DT46", 28 => "End with USD", 35 => "End.X with PSP, USP & USD", 32_767 => "The SID defined in RFC 8754",
      65_535 => "Opaque" }.each { |n, name| assert_equal name, S.behavior(n).name, n }
  end

  def test_rfc_9800_codepoints
    { 43 => "End with NEXT-CSID", 52 => "End.X with NEXT-CSID", 59 => "End.X with NEXT-CSID, PSP, USP & USD",
      101 => "End with REPLACE-CSID", 118 => "End.DT6 with REPLACE-CSID" }
      .each { |n, name| assert_equal name, S.behavior(n).name, n }
  end

  # The base and the flavors come apart at "with".
  def test_base_and_flavors
    b = S.behavior(57)
    assert_equal ["End.X", %w[NEXT-CSID PSP USD]], [b.base, b.flavors]
    assert_equal ["End", []], [S.behavior(1).base, S.behavior(1).flavors]
  end

  # Reserved and unassigned rows are left out: 0, 13, 25 and 26 in RFC
  # 8986's table, 51 between RFC 9800's End and End.X rows.
  def test_unknown_numbers
    [0, 13, 25, 26, 51, 40_000].each do |n|
      assert_nil S.behavior(n), n
      assert_equal n, S.behavior_name(n)
    end
  end

  def test_by_name_or_number
    assert_equal 5, S.behavior_number("End.X")
    assert_equal 999, S.behavior_number(999)
    assert_equal 999, S.behavior_number("999")
    assert_raises(ArgumentError) { S.behavior_number("End.Y") }
  end

  # One name per number, so a name in a hash rebuilds the number.
  def test_names_are_unique
    assert_equal S::BEHAVIORS.size, S::BY_NAME.size
  end
end
