# frozen_string_literal: true

require_relative "../test_helper"

# ISIS::Fault's SRv6 group, as far as the codec owns it
# (docs/design/srv6.md, step 1): each entry builds, round trips, and
# differs from a correct SRv6 system in the one thing it names. That it
# makes its finding is step 3's test, once validation.rb has the rules.
class TestFaultSrv6 < Minitest::Test
  F = ISIS::Fault

  # The findings of the design's validation table, but
  # locator_not_longest, which needs a second system.
  FINDINGS = %i[locator_size_invalid locator_algorithm_conflict end_sid_outside_locator end_x_sid_no_locator
                sid_structure_twice sid_structure_too_long behavior_not_allowed behavior_unknown anycast_and_node
                x_flag_mismatch fapm_in_locator].freeze

  def octets(tlv) = ISIS::Octets.new(tlv.encode)

  def correct = F.srv6(F.context)

  def test_one_entry_per_finding
    assert_equal FINDINGS, F.srv6_catalog.map { _1[:finding] }
    assert_equal F.srv6_names.uniq, F.srv6_names
    assert_empty F.srv6_names & (F.names + F.flex_algo_names)
  end

  # A correct system, as RFC 9352 asks: SRv6 Capabilities, the locator in
  # TLV 236 and TLV 27, an End SID from the locator and an End.X SID,
  # each with a SID Structure of 32/16/16/0.
  def test_a_correct_system
    cap, reach, locator, link = correct
    assert_equal [ISIS::SubTlv::Srv6Capabilities, ISIS::SubTlv::SrAlgorithm], cap.subtlvs.map(&:class)
    assert_equal ["fc00:0:3::/48"], reach.entries.map(&:prefix)
    entry = locator.entries.first
    assert_equal ["fc00:0:3::/48", 0, 0], [entry.locator, entry.metric, entry.algorithm]
    end_sid = entry.subtlvs_of(ISIS::SubTlv::Srv6EndSid).first
    assert_equal ["fc00:0:3::", 1, 64], [end_sid.sid, end_sid.behavior, end_sid.structure.total]
    x = link.entries.first.subtlvs.first
    assert_equal ["fc00:0:3:1::", 5], [x.sid, x.behavior]
    assert_equal "fc00:0:c::/48", F.context(system_id: "0000.0000.000c")[:locator]
  end

  # Building never validates: each entry encodes, and parses back to the
  # same octets.
  def test_each_entry_round_trips
    F.srv6_names.each do |name|
      wire = F.srv6_build(name, neighbors: { "0000.0000.0002" => 10 }).encode
      assert_equal wire, ISIS::Pdu.factory(ISIS::Octets.new(wire)).encode, name
      assert_equal 20, wire.getbyte(4) & 0x1f, "#{name}: a Level 2 LSP"
    end
  end

  # Each entry is the correct system with one TLV changed, or one added.
  def test_each_entry_changes_one_tlv
    good = correct.map(&:to_shex)
    F.srv6_names.each do |name|
      got = F.srv6_tlvs(name).map(&:to_shex)
      changed = got.each_index.reject { |i| got[i] == good[i] }
      assert_equal 1, changed.size, name
    end
  end

  # What each entry carries, read back from its octets.
  def test_what_each_entry_carries
    read = ->(name) { F.srv6_tlvs(name).map { ISIS::Tlv.factory(octets(_1)) } }
    loc = ->(name) { read[name][2].entries.first }
    end_sid = ->(name) { loc[name].subtlvs_of(ISIS::SubTlv::Srv6EndSid).first }
    flags = ->(name) { loc[name].subtlvs_of(ISIS::SubTlv::PrefixAttributeFlags).first.flag_letters }

    assert_equal [129, nil], [loc[:locator_size_invalid].size, loc[:locator_size_invalid].locator]
    assert_equal [0, 128], read[:locator_algorithm_conflict].grep(ISIS::Tlv::Srv6Locator).map { _1.entries.first.algorithm }
    assert_equal "fc00:0:99::", end_sid[:end_sid_outside_locator].sid
    assert_equal "fc00:0:99:1::", read[:end_x_sid_no_locator][3].entries.first.subtlvs.first.sid
    assert_equal 2, end_sid[:sid_structure_twice].subtlvs.count { _1.is_a?(ISIS::SubTlv::Srv6SidStructure) }
    assert_equal 144, end_sid[:sid_structure_too_long].structure.total
    assert_equal 5, end_sid[:behavior_not_allowed].behavior
    assert_nil ISIS::Srv6.behavior(end_sid[:behavior_unknown].behavior)
    assert_equal %w[N A], flags[:anycast_and_node]
    assert_equal %w[X], flags[:x_flag_mismatch]
    refute read[:x_flag_mismatch][1].entries.first.external
    assert_instance_of ISIS::SubTlv::Fapm, loc[:fapm_in_locator].subtlvs.to_a[1]
  end

  def test_an_unknown_srv6_fault
    e = assert_raises(ArgumentError) { F.srv6_entry(:nope) }
    assert_match(/\Aunknown SRv6 fault :nope; they are locator_size_invalid, /, e.message)
  end
end
