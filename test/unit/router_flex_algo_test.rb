# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/sim_host"

# Flex-algo between two routers on a simulated wire (docs/design/
# flex-algo.md, step 4): A advertises the FAD for 128, B takes part
# without advertising. Each sends SR-Algorithm 0 and 128, and a Prefix-SID
# for 128 beside its algorithm 0 one, only while it takes part.
class TestRouterFlexAlgo < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @routers = []
  end

  def router(config, mac)
    r = ISIS::Router.new(config, clock: @clock, scheduler: @scheduler, log: @log, host: SimHost.new(@wires, { "ab" => mac }))
    @routers << r
    r
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @routers.each { |r| r.step(wait: 0) }
    end
  end

  def conf(n, flex)
    { system_id: "0000.0000.000#{n}", hostname: n, minimum_lsp_interval: 1, segment_routing: {},
      interfaces: [{ name: "ab", ip_addresses: ["10.0.12.#{n == 'a' ? 1 : 2}"], hello_interval: 1, hello_multiplier: 3 }],
      prefixes: [{ prefix: "10.255.0.#{n == 'a' ? 1 : 2}/32", metric: 0, sid: n == "a" ? 1 : 2,
                   algorithm_sids: { "128" => n == "a" ? 101 : 102 } }],
      flex_algo: [flex] }
  end

  def pair(a_flex = { algorithm: 128, priority: 100 }, b_flex = { algorithm: 128, advertise: false })
    a = router(conf("a", a_flex), "00:00:00:00:00:0a")
    b = router(conf("b", b_flex), "00:00:00:00:00:0b")
    @routers.each(&:start)
    run_for(15)
    [a, b]
  end

  # What +r+'s own Level 1 LSP says, as B's database holds it.
  def sent(r, by)
    lsp = by.databases[1][r.originators[1].lsp_id].lsp
    caps = lsp.tlvs.to_a.grep(ISIS::Tlv::RouterCapability)
    sids = lsp.tlvs.to_a.grep(ISIS::Tlv::ExtendedIpReachability).flat_map(&:entries)
              .flat_map { _1.subtlvs.to_a }.grep(ISIS::SubTlv::PrefixSid)
    { algorithms: caps.flat_map { _1.subtlvs.to_a }.grep(ISIS::SubTlv::SrAlgorithm).first.algorithms,
      fads: caps.flat_map { _1.subtlvs.to_a }.grep(ISIS::SubTlv::Fad).map(&:to_hash),
      sids: sids.map { [_1.algorithm, _1.to_hash[:index]] } }
  end

  def test_both_take_part_in_a_fad
    a, b = pair
    assert_equal [128], b.flex_algos[1].participating
    assert_equal({ algorithms: [0, 128], fads: [{ algorithm: 128, metric_type: "igp", calc_type: 0, priority: 100 }],
                   sids: [[0, 1], [128, 101]] }, sent(a, b))
    assert_equal({ algorithms: [0, 128], fads: [], sids: [[0, 2], [128, 102]] }, sent(b, a))
    assert_equal "0000.0000.000a", b.flex_algos[1].statuses[128].origin
  end

  # B alone, before A's LSP: no FAD, so it does not take part: no 128 in
  # SR-Algorithm, no Prefix-SID for 128.
  def test_without_a_fad_no_part
    b = router(conf("b", { algorithm: 128, advertise: false }), "00:00:00:00:00:0b")
    b.start
    run_for(3)
    lsp = b.databases[1][b.originators[1].lsp_id].lsp
    algos = lsp.tlvs.to_a.grep(ISIS::Tlv::RouterCapability).first.subtlvs.to_a.grep(ISIS::SubTlv::SrAlgorithm).first
    assert_equal [0], algos.algorithms
    sids = lsp.tlvs.to_a.grep(ISIS::Tlv::ExtendedIpReachability).flat_map(&:entries).flat_map { _1.subtlvs.to_a }
    assert_equal [0], sids.map(&:algorithm)
  end

  # policy.flex_algo: B's FAD at a higher priority, then advertised,
  # wins; A sees it and follows it.
  def test_policy_moves_the_winner
    a, b = pair
    b.set_flex_algo(128, { "advertise" => true, "priority" => 200, "metric_type" => "te" })
    run_for(10)
    assert_equal "0000.0000.000b", a.flex_algos[1].statuses[128].origin
    assert_equal "te", a.flex_algos[1].statuses[128].winner.metric_name
    assert_equal [128], a.flex_algos[1].participating
  end

  def test_refusals
    refuse = ->(c) { assert_raises(ArgumentError) { ISIS::Router.normalize(c) }.message }
    base = { segment_routing: {}, interfaces: [] }
    assert_equal "flex_algo needs segment_routing", refuse.({ flex_algo: [{ algorithm: 128 }] })
    assert_equal "flex_algo: algorithm 127 is not in 128 to 255", refuse.(base.merge(flex_algo: [{ algorithm: 127 }]))
    assert_equal "flex_algo: algorithm 128 more than once",
                 refuse.(base.merge(flex_algo: [{ algorithm: 128 }, { algorithm: 128 }]))
    assert_equal "flex_algo 128: color red is not in affinity_map",
                 refuse.(base.merge(flex_algo: [{ algorithm: 128, exclude_any: ["red"] }]))
    assert_equal "flex_algo 128: metric_type is igp, delay, te, not bandwidth",
                 refuse.(base.merge(flex_algo: [{ algorithm: 128, metric_type: "bandwidth" }]))
    assert_match(/\Aflex_algo: unknown key m_flag;/, refuse.(base.merge(flex_algo: [{ algorithm: 128, m_flag: true }])))
    assert_equal "prefix 10.255.0.1/32: algorithm_sids names 129, not in flex_algo",
                 refuse.(base.merge(flex_algo: [{ algorithm: 128 }],
                                    prefixes: [{ prefix: "10.255.0.1/32", sid: 1, algorithm_sids: { 129 => 5 } }]))
    e = assert_raises(ArgumentError) { pair.last.set_flex_algo(129, {}) }
    assert_equal "flex_algo has no algorithm 129; it has 128", e.message
  end
end
