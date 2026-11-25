# frozen_string_literal: true

require_relative "../../test_helper"

# Spf::Definitions, one system's FADs merged by RFC 9350 section 6, and
# Spf::PrefixMetrics, its FAPMs by section 8. test/unit/fault_test.rb has
# each finding from the fault catalog.
class TestDefinitions < Minitest::Test
  def lsp(tlvs, number: 0)
    ISIS::Pdu::Lsp.new(level: 1, lsp_id: ISIS::Octets.new(ISIS::Pdu.dotted_octets("0000.0000.0001") + "\x00".b + number.chr),
                       lifetime: 1200, sequence: 1, tlvs: tlvs)
  end

  def cap(*fads, s: false)
    ISIS::Tlv::RouterCapability.new(router_id: "10.255.0.1", s: s, subtlvs: fads.map { { fad: _1 } })
  end

  def exclude(*g) = { fad_exclude_admin_group: { groups: g } }

  def test_one_fad
    d = ISIS::Spf::Definitions.new([lsp([cap({ algorithm: 128, metric_type: "delay", priority: 200,
                                              subtlvs: [exclude(1), { fad_include_any_admin_group: { groups: [2] } },
                                                        { fad_exclude_srlg: { srlgs: [10] } }] })])])
    assert_empty d.findings
    assert_equal({ algorithm: 128, metric_type: "delay", calc_type: 0, priority: 200, exclude_any: [1],
                   include_any: [2], exclude_srlg: [10] }, d[128].to_hash)
    assert d[128].supported?
  end

  # Section 6: split across sub-TLVs and LSPs, the first of each rule
  # counts, and the excluded SRLGs join.
  def test_split_fads
    zero = lsp([cap({ algorithm: 128, subtlvs: [exclude(1), { fad_exclude_srlg: { srlgs: [10] } }] })])
    one = lsp([cap({ algorithm: 128, subtlvs: [{ fad_exclude_srlg: { srlgs: [20, 10] } }] })], number: 1)
    d = ISIS::Spf::Definitions.new([zero, one])
    assert_empty d.findings
    assert_equal [[1], [10, 20]], [d[128].exclude_any, d[128].exclude_srlg]
  end

  # Fixed parts that differ: the first, under rfc; nothing under strict.
  def test_split_differs
    lsps = [lsp([cap({ algorithm: 128, priority: 100 }, { algorithm: 128, priority: 200 })])]
    d = ISIS::Spf::Definitions.new(lsps)
    assert_equal [:fad_split_differs], d.findings.map(&:name)
    assert_equal 100, d[128].priority
    assert_nil ISIS::Spf::Definitions.new(lsps, policy: :strict)[128]
  end

  # A rule twice across split FADs: the first.
  def test_split_rule_twice
    d = ISIS::Spf::Definitions.new([lsp([cap({ algorithm: 128, subtlvs: [exclude(1)] },
                                              { algorithm: 128, subtlvs: [exclude(2)] })])])
    assert_equal [:fad_split_subtlv_twice], d.findings.map(&:name)
    assert_equal [1], d[128].exclude_any
  end

  # Within one FAD a rule twice: the FAD ignored under rfc, the first
  # used under lenient.
  def test_rule_twice_in_one_fad
    lsps = [lsp([cap({ algorithm: 128, subtlvs: [exclude(1), exclude(2)] })])]
    assert_nil ISIS::Spf::Definitions.new(lsps)[128]
    assert_equal [1], ISIS::Spf::Definitions.new(lsps, policy: :lenient)[128].exclude_any
  end

  # Decision 6: S set, or a length not a multiple of 4: ignored under
  # rfc and strict, used under lenient.
  def test_decision_6
    s = [lsp([cap({ algorithm: 128 }, s: true)])]
    assert_nil ISIS::Spf::Definitions.new(s)[128]
    assert_nil ISIS::Spf::Definitions.new(s, policy: :strict)[128]
    refute_nil ISIS::Spf::Definitions.new(s, policy: :lenient)[128]
    eag = [lsp([cap({ algorithm: 128, subtlvs: [{ fad_exclude_admin_group: { groups: [1], tail: "00" } }] })])]
    assert_nil ISIS::Spf::Definitions.new(eag)[128]
    assert_equal [1], ISIS::Spf::Definitions.new(eag, policy: :lenient)[128].exclude_any
  end

  def test_algorithm_out_of_range
    d = ISIS::Spf::Definitions.new([lsp([cap({ algorithm: 127 })])])
    assert_empty d.definitions
    assert_equal [:fad_algorithm_range], d.findings.map(&:name)
  end

  # What isis4r cannot run: kept, with why, for selection to stop taking
  # part. The M flag is one, until it is built.
  def test_unsupported
    d = ISIS::Spf::Definitions.new([lsp([cap({ algorithm: 128, calc_type: 1 },
                                              { algorithm: 129, subtlvs: [{ fad_flags: { flags: %w[M] } }] },
                                              { algorithm: 130, metric_type: 3, subtlvs: [{ unknown: { type: 9, value: "" } }] })])])
    assert_equal %i[fad_unsupported] * 3, d.findings.map(&:name)
    assert_equal ["FAD 128: calculation type 1", "FAD 129: flag bits 0", "FAD 130: metric type 3, sub-TLV 9"],
                 [128, 129, 130].map { d[_1].unsupported }
    refute d[129].supported?
  end

  # FRR 10.7.1's FAD, captured on ospflab: 128, delay, priority 200,
  # include-any group 32.
  def test_frr
    hex = File.read(File.expand_path("../../fixtures/frr-10.7.1-l2-lsp-flex-algo.hex", __dir__)).strip
    d = ISIS::Spf::Definitions.new([ISIS::Pdu.factory(ISIS::Octets.from_hex(hex))])
    assert_empty d.findings
    assert_equal({ algorithm: 128, metric_type: "delay", calc_type: 0, priority: 200, include_any: [32] }, d[128].to_hash)
  end

  def prefix(*subtlvs) = ISIS::Tlv::ExtendedIpReachability.new({ prefix: "10.255.0.1/32", metric: 0, subtlvs: subtlvs })

  # The first FAPM for an algorithm counts, under rfc; none under strict.
  def test_prefix_metrics
    lsps = [lsp([prefix({ fapm: { algorithm: 128, metric: 10 } }, { fapm: { algorithm: 129, metric: 30 } },
                        { fapm: { algorithm: 128, metric: 20 } })])]
    m = ISIS::Spf::PrefixMetrics.new(lsps)
    assert_equal({ "10.255.0.1/32" => { 128 => 10, 129 => 30 } }, m.metrics)
    assert_equal [:fapm_twice], m.findings.map(&:name)
    assert_equal({ "10.255.0.1/32" => { 129 => 30 } }, ISIS::Spf::PrefixMetrics.new(lsps, policy: :strict).metrics)
  end

  def test_prefix_metric_out_of_range_and_sids_twice
    lsps = [lsp([prefix({ fapm: { algorithm: 100, metric: 10 } },
                        { prefix_sid: { flags: %w[N], algorithm: 128, index: 101 } },
                        { prefix_sid: { flags: %w[N], algorithm: 128, index: 102 } })])]
    m = ISIS::Spf::PrefixMetrics.new(lsps)
    assert_empty m.metrics
    assert_equal %i[fapm_algorithm_range prefix_sid_algorithm_twice], m.findings.map(&:name)
  end
end
