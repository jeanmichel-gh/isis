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

  # The TI-LFA topologies: each with its section and the repair it
  # expects, written as the table writes it.
  def self.repair_text(expect)
    if expect[:unprotected] then "unprotected, `#{expect[:unprotected]}`"
    elsif expect[:ecmp] then "ECMP through #{expect[:ecmp].join(', ')}"
    else
      segs = expect[:segments].map { |k, *n| k == :node ? "Node-SID(#{n[0]})" : "Adj-SID(#{n.join('-')})" }
      "`#{expect[:case]}` via #{expect[:first_hop]}, P #{expect[:p]}, Q #{expect[:q]}: " \
        "#{segs.empty? ? 'no segment' : segs.join(', ')}"
    end
  end

  def self.topology_row(e)
    "| `#{e[:name]}` | #{e[:rfc]} | #{e[:failure][0]} #{e[:failure][1]} at #{e[:plr]}, to #{e[:destination]} | " \
      "#{repair_text(e[:expect])} |"
  end

  def test_every_topology_with_its_repair_and_no_other
    ISIS::Fault.topologies.each { |e| assert_includes DOC, self.class.topology_row(e), e[:name] }
    listed = DOC.scan(/^\| `(ti_lfa_\w+)` \|/).flatten.map(&:to_sym)
    assert_equal ISIS::Fault.topology_names, listed
  end

  def test_every_policy
    listed = DOC.scan(/^\| `(rfc|strict|lenient)` \|/).flatten.map(&:to_sym)
    assert_equal ISIS::Validation::POLICIES, listed
  end
end
