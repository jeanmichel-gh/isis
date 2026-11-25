# frozen_string_literal: true

require_relative "../test_helper"

# ISIS::Fault, the catalog of crafted inputs. Each entry is tested with
# the rule it is for: built as an LSP, stored in a database, and read by
# Spf::Labels, it makes exactly its own finding. So the catalog and
# validation.rb cannot drift apart (routescope
# docs/design/protocol-conventions.md, part 3).
#
# A computes, in a line a ---- b ---- c; b is correct, c is the entry.
class TestFault < Minitest::Test
  F = ISIS::Fault

  def setup
    @clock = ISIS::Runtime::ManualClock.new
  end

  def id(letter)
    (ISIS::Pdu.dotted_octets("0000.0000.000#{letter}") + "\x00".b).b
  end

  def store(db, pdu)
    db.entry(pdu.lsp_id.to_s.b).store(pdu)
  end

  # The findings Spf::Labels makes from A, with c built as +name+, or
  # correct when +name+ is nil.
  def findings(name)
    db = ISIS::Database.new(level: 1, clock: @clock)
    store(db, ISIS::Pdu::Lsp.new(level: 1, lsp_id: ISIS::Octets.new(id("a") + "\x00".b), lifetime: 1200, sequence: 1,
                                 tlvs: [ISIS::Tlv::ExtendedIsReachability.new(
                                   [ISIS::Tlv::ExtendedIsReachability::Entry.new(neighbor: id("b"), metric: 10)]
                                 )]))
    b = { system_id: "0000.0000.000b", loopback: "10.255.0.2/32", index: 2, srgb: [18_000, 8_000],
          neighbors: { "0000.0000.000a" => 10, "0000.0000.000c" => 10 } }
    store(db, F.lsp(F.sr(F.context(**b)), **b))
    c = { system_id: "0000.0000.000c", neighbors: { "0000.0000.000b" => 10 } }
    store(db, name ? F.build(name, **c) : F.lsp(F.sr(F.context(**c)), **c))
    adj = ISIS::Spf::Adjacency.new(circuit: "eth-b", neighbor: ISIS::Pdu.dotted_octets("0000.0000.000b"),
                                   circuit_id: 1, address: "10.0.0.11")
    calc = ISIS::Spf::Calculation.new(database: db, system_id: "0000.0000.000a", adjacencies: [[id("b"), 10, adj]]).run
    own = ISIS::SegmentRouting.new(router_id: "10.255.0.1", srgb: [[16_000, 8_000]])
    ISIS::Spf::Labels.new(own: own, database: db, paths: calc.paths).build(calc.routes, []).findings.map(&:name)
  end

  # A correct system makes no finding: the line with c correct too.
  def test_a_correct_system_makes_none
    assert_empty findings(nil)
  end

  def test_every_rule_has_an_entry_and_every_entry_a_rule
    assert_equal ISIS::Validation::RULES.keys.sort, (F.catalog + F.link_catalog).map { _1[:finding] }.sort
    assert_equal (F.names + F.link_names).uniq, F.names + F.link_names
  end

  # The findings Spf::LinkAttributes makes from c's LSP, built as +name+.
  def link_findings(name)
    ISIS::Spf::LinkAttributes.new([F.build(name, system_id: "0000.0000.000c")]).findings.map(&:name)
  end

  def test_each_link_entry_makes_its_finding_and_no_other
    F.link_catalog.each do |e|
      assert_equal [e[:finding]], link_findings(e[:name]), e[:name]
    end
  end

  # The same link, correct: an ASLA with X and a TE metric, a TLV 238
  # naming it.
  def test_a_correct_link_makes_none
    tlvs = F.link(F.context(neighbors: { "0000.0000.0002" => 10 }), [F.asla_te(100)],
                  [ISIS::Tlv::AslaSrlg.new(neighbor: "0000.0000.0002.00", applications: %w[X],
                                           links: [{ ipv4_interface_address: "10.0.0.1" }], srlgs: [10])])
    la = ISIS::Spf::LinkAttributes.new([F.lsp(tlvs)])
    assert_empty la.findings
    assert_equal [{ te_metric: 100, srlg: [10] }], la.links.map(&:to_hash)
  end

  def test_each_link_entry_round_trips
    F.link_names.each do |name|
      octets = F.wire(name, neighbors: { "0000.0000.0002" => 10 })
      assert_equal octets, ISIS::Pdu.factory(octets.dup).encode, name
    end
  end

  def test_each_entry_makes_its_finding_and_no_other
    F.catalog.each do |e|
      assert_equal [e[:finding]], findings(e[:name]), e[:name]
    end
  end

  # Building never validates: each entry encodes, and its octets parse
  # back to the same octets.
  def test_each_entry_round_trips
    F.names.each do |name|
      octets = F.wire(name, neighbors: { "0000.0000.0002" => 10 })
      assert_equal octets, ISIS::Pdu.factory(octets.dup).encode, name
    end
  end

  def test_an_entry_says_what_the_rfc_expects
    e = F.entry(:srgb_overlap)
    assert_equal [:errors, :ignore_srgb], e.values_at(:channel, :expect)
    assert_match(/\ARFC 8660 section 2.3/, e[:rfc])
  end

  def test_the_tlvs_alone
    cap, reach = F.tlvs(:sr_capabilities_twice)
    assert_equal 2, cap.subtlvs.count { _1.is_a?(ISIS::SubTlv::SrCapabilities) }
    assert_equal ["10.255.0.3/32"], reach.entries.map(&:prefix)
  end

  def test_an_unknown_fault
    e = assert_raises(ArgumentError) { F.entry(:nope) }
    assert_match(/\Aunknown fault :nope; the faults are srgb_range_zero, /, e.message)
  end
end
