# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"

# isis4r-sim's flex-algo keys (docs/design/flex-algo.md, step 7), against
# an ordinary Router, the DUT, that takes part in 128:
#
#   dut -- s1 -- p1 -- p3
#                 \\   /
#                   p2
#
# p3 advertises the FAD for 128, delay, excluding red; p1--p3 is red;
# every other link 2 ms but p1--p2--p3, 1 ms each, so 128 goes by p2.
# p1--p3 is in SRLG 10, so it gets addresses and a TLV 238.
class TestSimFlexAlgo < Minitest::Test
  HELLO = { hello_interval: 1, hello_multiplier: 3 }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
  end

  def router(name, id, lo, more = {})
    { "name" => name, "system_id" => id, "loopback" => lo, "sid" => lo.split(".").last.to_i,
      "flex_algo" => [{ "algorithm" => 128, "advertise" => false }],
      "algorithm_sids" => { 128 => 100 + lo.split(".").last.to_i } }.merge(more)
  end

  def topology_hash
    flex = [{ "algorithm" => 128, "advertise" => false }]
    { "simulator" => { "system_id" => "0000.0000.0009", "hostname" => "s1", "areas" => ["49.0001"], "level" => 1,
                       "minimum_lsp_interval" => 1, "segment_routing" => {}, "router_id" => "10.255.0.9",
                       "flex_algo" => flex,
                       "interfaces" => [{ "name" => "a", "ip_addresses" => ["10.0.14.2"], "delay" => 2000 }
                                          .merge(HELLO.transform_keys(&:to_s))] },
      "segment_routing" => { "srgb" => [{ "start" => 16_000, "size" => 1000 }] },
      "affinity_map" => { "red" => 1 },
      "routers" => [router("p1", "0000.0000.0101", "10.255.1.1"), router("p2", "0000.0000.0102", "10.255.1.2"),
                    router("p3", "0000.0000.0103", "10.255.1.3",
                           "flex_algo" => [{ "algorithm" => 128, "priority" => 200, "metric_type" => "delay",
                                             "exclude_any" => ["red"] }])],
      "links" => [{ "from" => "s1", "to" => "p1", "delay" => 2000 },
                  { "from" => "p1", "to" => "p3", "delay" => 2000, "affinity" => ["red"], "srlg" => [10] },
                  { "from" => "p1", "to" => "p2", "delay" => 1000 }, { "from" => "p2", "to" => "p3", "delay" => 1000 }] }
  end

  def start(hash = topology_hash)
    @topology = ISIS::Sim::Topology.from_hash(hash)
    @sim = ISIS::Sim::Simulator.new(@topology, clock: @clock, scheduler: @scheduler, log: @log,
                                               host: SimHost.new(@wires, { "a" => "00:00:00:00:00:09" }))
    @dut = ISIS::Router.new({ system_id: "0000.0000.0001", hostname: "dut", minimum_lsp_interval: 1,
                              segment_routing: {}, router_id: "10.255.0.1", flex_algo: [{ algorithm: 128, advertise: false }],
                              prefixes: [{ prefix: "10.255.0.1/32", metric: 0, sid: 1, algorithm_sids: { 128 => 101 } }],
                              interfaces: [{ name: "a", ip_addresses: ["10.0.14.1"], delay: 2000, **HELLO }] },
                            clock: @clock, scheduler: @scheduler, log: @log,
                            host: SimHost.new(@wires, { "a" => "00:00:00:00:00:01" }))
    @sim.start
    @dut.start
    run_for(15)
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @sim.step(wait: 0)
      @dut.step(wait: 0)
    end
  end

  def flex_route(prefix) = @dut.decisions[1].flex_routes.fetch(128, {})[prefix]

  # The DUT takes p3's FAD, and 128's path to p3 avoids the red link,
  # going by p2 at 2 + 2 + 1 + 1 ms; algorithm 0 takes the red link.
  def test_the_dut_follows_the_simulated_fad
    start
    s = @dut.flex_algos[1].statuses[128]
    assert s.participating, s.reason
    assert_equal "0000.0000.0103", s.origin
    assert_equal 6_000, flex_route("10.255.1.3/32")&.metric
    assert_equal 30, @dut.decisions[1].routes["10.255.1.3/32"].metric
    labels = ISIS::Daemon::Views.new(@dut).labels(level: 1).select { _1[:algorithm] == 128 }.map { _1[:label] }
    assert_includes labels, 16_103
  end

  # What p1 sends: its link to p3 with red, 2 ms, and SRLG 10 in a TLV
  # 238 naming it by its addresses; SR-Algorithm 0 and 128; a Prefix-SID
  # for each.
  def test_a_simulated_lsp_carries_the_attributes
    start
    p1 = ISIS::Daemon::Views.new(@dut).topology(level: 1)[:nodes].find { _1[:hostname] == "p1" }
    to_p3 = p1[:neighbors].find { _1[:id].start_with?("0000.0000.0103") }
    assert_equal({ affinity: [1], delay: { min: 2000, max: 2000, average: 2000 }, srlg: [10] },
                 to_p3.slice(:affinity, :delay, :srlg))
    assert_equal [0, 128], p1.dig(:sr, :algorithms)
    lsp = @dut.databases[1][ISIS::Pdu.lsp_id_octets("0000.0000.0101.00-00")].lsp
    sids = lsp.tlvs.to_a.grep(ISIS::Tlv::ExtendedIpReachability).flat_map(&:entries).flat_map { _1.subtlvs.to_a }
    assert_equal [[0, 1], [128, 101]], sids.grep(ISIS::SubTlv::PrefixSid).map { [_1.algorithm, _1.index] }
  end

  # fad_takeover: p2 advertises a FAD at 255, IGP, no exclusion; the DUT
  # follows it, so 128 takes the red link, IGP 20; after hold, p3's again.
  def test_fad_takeover
    start
    r = @sim.behave(:fad_takeover, router: "p2", hold: 20)
    assert_equal 20.0, r[:ends_in]
    run_for(10)
    assert_equal "0000.0000.0102", @dut.flex_algos[1].statuses[128].origin
    assert_equal 30, flex_route("10.255.1.3/32").metric
    run_for(20)
    assert_nil @sim.behaviour
    assert_equal "0000.0000.0103", @dut.flex_algos[1].statuses[128].origin
    assert_equal 6_000, flex_route("10.255.1.3/32").metric
  end

  # participation_flap: p2 leaves 128 out, so 128 prunes it, and p3, past
  # only the red link and p2, is unreachable in 128, with no label route;
  # then p2 lists 128 again and all come back.
  def test_participation_flap
    start
    @sim.behave(:participation_flap, router: "p2", count: 1, down: 10, up: 10)
    run_for(5)
    assert_equal [], @sim.state[:systems].find { _1[:name] == "p2" }[:algorithms]
    assert_nil flex_route("10.255.1.3/32")
    refute_includes ISIS::Daemon::Views.new(@dut).labels(level: 1).map { _1[:label] }, 16_103
    run_for(10)
    assert_nil @sim.behaviour
    assert_equal 6_000, flex_route("10.255.1.3/32").metric
  end

  # delay_change: p1--p2 at 100 ms for hold seconds; 128's path to p3,
  # still by p2, costs 2 + 2 + 100 + 1 ms, then 6 ms again.
  def test_delay_change
    start
    @sim.behave(:delay_change, link: "p1--p2", delay: 100_000, hold: 20)
    run_for(10)
    assert_equal 105_000, flex_route("10.255.1.3/32").metric
    run_for(20)
    assert_nil @sim.behaviour
    assert_equal 6_000, flex_route("10.255.1.3/32").metric
  end

  # A behaviour stopped early is undone.
  def test_a_stopped_behaviour_is_undone
    start
    @sim.behave(:delay_change, link: "p1--p2", delay: 100_000, hold: 60)
    run_for(10)
    @sim.behave_stop
    run_for(10)
    assert_equal 6_000, flex_route("10.255.1.3/32").metric
    e = assert_raises(ArgumentError) { @sim.behave(:fad_takeover, router: "p1", algorithm: 129) }
    assert_equal "p1 has no flex_algo algorithm 129", e.message
  end

  def test_refusals
    bad = topology_hash
    bad["links"][1]["affinity"] = ["blue"]
    bad["routers"][0]["algorithm_sids"] = { 129 => 5 }
    e = assert_raises(ISIS::Sim::Topology::Error) { ISIS::Sim::Topology.from_hash(bad) }
    assert_match(/links\[1\]: affinity blue is not in affinity_map/, e.message)
    assert_match(/routers\[0\]\.algorithm_sids: prefix 10\.255\.1\.1\/32: algorithm_sids names 129, not in flex_algo/, e.message)
  end

  # The file written out reads again to the same topology.
  def test_to_h_reads_again
    t = ISIS::Sim::Topology.from_hash(topology_hash)
    again = ISIS::Sim::Topology.from_hash(JSON.parse(JSON.generate(t.to_h)))
    assert_equal t.to_h, again.to_h
  end
end
