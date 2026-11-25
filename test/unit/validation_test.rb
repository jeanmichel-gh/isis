# frozen_string_literal: true

require_relative "../test_helper"

# ISIS::Validation's segment routing rules, each on the smallest input that
# breaks it. Spf::Labels runs them on a database; test/unit/spf/
# sr_findings_test.rb has that side.
class TestValidation < Minitest::Test
  V = ISIS::Validation

  def names(findings)
    findings.map(&:name)
  end

  def sid(**fields)
    ISIS::SubTlv::PrefixSid.new(**fields)
  end

  # Every rule has a channel, a clause, a description and an action for
  # each policy, all known ones.
  def test_every_rule_is_complete
    known = %i[ignore_srgb ignore_node use_first ignore_sid drop_both use ignore_subtlv ignore_values legacy
               ignore_attribute ignore_tlv use_ag]
    V::RULES.each_value do |r|
      assert_includes V::CHANNELS, r.channel, r.name
      refute_empty r.clause, r.name
      refute_empty r.description, r.name
      assert_equal V::POLICIES, r.actions.keys, r.name
      r.actions.each_value { |a| assert_includes known, a, r.name }
    end
  end

  # An errors finding quotes the RFC it comes from; a gaps one names what
  # isis4r lacks (CLAUDE.md, "A finding carries where it came from").
  def test_a_clause_says_where_it_comes_from
    V::RULES.each_value do |r|
      assert_match(/RFC \d+ section [\d.]+/, r.clause, r.name)
      assert_match(/\Aisis4r has no code/, r.clause, r.name) if r.channel == :gaps
    end
  end

  def test_a_good_srgb_has_no_finding
    assert_empty V.srgb([[16_000, 23_999], [30_000, 30_999]], "x")
  end

  def test_a_range_of_zero
    assert_equal [:srgb_range_zero], names(V.srgb([[16_000, 15_999]], "x"))
  end

  def test_overlapping_ranges
    f = V.srgb([[16_000, 16_999], [16_500, 17_499]], "0000.0000.000c")
    assert_equal [:srgb_overlap], names(f)
    assert_equal "0000.0000.000c: ranges 16000-16999 and 16500-17499 overlap " \
                 '(RFC 8660 section 2.3: "The list of ranges comprising the SRGB MUST NOT overlap")', f.first.to_s
  end

  def test_reserved_labels
    assert_equal [:srgb_reserved], names(V.srgb([[10, 99]], "x"))
    assert_equal [:srgb_reserved], names(V.srgb([[0xfff00, 0x100100]], "x"))
  end

  def test_sr_capabilities_twice
    assert_empty V.sr_capabilities(1, "x")
    assert_equal [:sr_capabilities_twice], names(V.sr_capabilities(2, "x"))
  end

  # RFC 8667 section 2.1.1.1: V and L both clear is an index, both set a
  # label; anything else is invalid.
  def test_v_and_l
    assert_empty V.prefix_sid(sid(index: 1), [0], "p")
    assert_equal [:prefix_sid_label], names(V.prefix_sid(sid(label: 16_001), [0], "p"))
    assert_equal [:prefix_sid_vl_invalid], names(V.prefix_sid(sid(index: 1, flags: %w[V]), [0], "p"))
    assert_equal [:prefix_sid_vl_invalid], names(V.prefix_sid(sid(index: 1, flags: %w[L]), [0], "p"))
  end

  def test_an_algorithm_not_advertised
    s = sid(index: 1, algorithm: 1)
    assert_equal [:algorithm_not_advertised], names(V.prefix_sid(s, [0], "p"))
    assert_empty V.prefix_sid(s, [0, 1], "p")
    assert_empty V.prefix_sid(s, nil, "p"), "an origin not known is not checked"
  end

  def test_a_duplicate
    f = V.prefix_sid_duplicate(7, ["10.255.0.3/32", "10.255.0.1/32"])
    assert_equal [:prefix_sid_duplicate, :errors], [f.name, f.channel]
    assert_match(/\Aindex 7: the Prefix-SID of 10.255.0.1\/32 and 10.255.0.3\/32; both left out/, f.to_s)
  end

  def test_actions_by_policy
    f = V.finding(:srgb_overlap, "x", "y")
    assert_equal %i[ignore_srgb ignore_node use], V::POLICIES.map { V.action(f, _1) }
  end

  def test_policy_names
    assert_equal :rfc, V.policy(nil)
    assert_equal :strict, V.policy("strict")
    e = assert_raises(ArgumentError) { V.policy("loose") }
    assert_equal "receive_policy is rfc, strict, lenient, not loose", e.message
  end

  def test_a_finding_as_a_hash
    h = V.finding(:sr_capabilities_twice, "0000.0000.000b", "2 SR-Capabilities").to_hash
    assert_equal %i[name channel clause subject detail], h.keys
    assert_equal %w[sr_capabilities_twice errors], h.values_at(:name, :channel)
  end

  def asla(**mask)
    ISIS::SubTlv::Asla.new(applications: %w[X], **mask)
  end

  def test_an_asla_mask_too_long
    assert_equal [:asla_mask_too_long], names(V.asla(asla(sabm_length: 9), [], "x"))
    assert_equal [:asla_mask_too_long], names(V.asla(asla(udabm_length: 9), [], "x"))
    assert_empty V.asla(asla(sabm_length: 8), [], "x")
  end

  def test_values_beside_the_l_flag
    assert_equal [:asla_l_flag_values], names(V.asla(asla(legacy: true), ["TE Default Metric 5"], "x"))
    assert_empty V.asla(asla(legacy: true), [], "x")
  end

  def test_tlv_238_link_identifiers
    v4 = ISIS::SubTlv::Ipv4InterfaceAddress.new("10.0.0.1")
    nb = ISIS::SubTlv::Ipv4NeighborAddress.new("10.0.0.2")
    assert_empty V.asla_srlg([v4, nb], "x")
    assert_equal "x: no link identifier", V.asla_srlg([], "x").first.then { "#{_1.subject}: #{_1.detail}" }
    assert_equal "sub-TLV 6 more than once", V.asla_srlg([v4, v4], "x").first.detail
  end

  def test_admin_group_against_the_eag
    assert_empty V.admin_groups([1], [1, 40], "x")
    assert_equal [:admin_group_mismatch], names(V.admin_groups([1], [2, 40], "x"))
  end
end
