# frozen_string_literal: true

require_relative "../test_helper"

# docs/protocol-testing.md lists every finding of ISIS::Validation, with
# its channel, every receive policy, and every entry of ISIS::Fault; the
# code is the measure.
class TestProtocolTestingDoc < Minitest::Test
  DOC = File.read(File.expand_path("../../docs/protocol-testing.md", __dir__))

  def test_every_finding_with_its_channel_and_no_other
    listed = DOC.scan(/^\| `(\w+)` \| (errors|gaps|inconclusive) \|/).to_h { |n, c| [n.to_sym, c.to_sym] }
    assert_equal ISIS::Validation::RULES.transform_values(&:channel), listed
  end

  def test_every_fault_with_its_finding_and_no_other
    listed = DOC.scan(/^\| `(\w+)` \| `(\w+)` \|/).to_h { |n, f| [n.to_sym, f.to_sym] }
    assert_equal ISIS::Fault.catalog.to_h { [_1[:name], _1[:finding]] }, listed
  end

  def test_each_fault_built_as_described
    ISIS::Fault.catalog.each do |e|
      assert_includes DOC, "| `#{e[:name]}` | `#{e[:finding]}` | #{e[:description]} |", e[:name]
    end
  end

  def test_every_policy
    listed = DOC.scan(/^\| `(rfc|strict|lenient)` \|/).flatten.map(&:to_sym)
    assert_equal ISIS::Validation::POLICIES, listed
  end
end
