# frozen_string_literal: true

require_relative "../test_helper"

# docs/protocol-testing.md lists every finding of ISIS::Validation, with
# its channel, and every receive policy; the code is the measure.
class TestProtocolTestingDoc < Minitest::Test
  DOC = File.read(File.expand_path("../../docs/protocol-testing.md", __dir__))

  def test_every_finding_with_its_channel_and_no_other
    listed = DOC.scan(/^\| `(\w+)` \| (errors|gaps|inconclusive) \|/).to_h { |n, c| [n.to_sym, c.to_sym] }
    assert_equal ISIS::Validation::RULES.transform_values(&:channel), listed
  end

  def test_every_policy
    listed = DOC.scan(/^\| `(rfc|strict|lenient)` \|/).flatten.map(&:to_sym)
    assert_equal ISIS::Validation::POLICIES, listed
  end
end
