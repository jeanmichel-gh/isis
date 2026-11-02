# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"
require "tmpdir"

# The sim.* methods, answered when the API runs beside a simulator
# (isis4r-sim), and not otherwise. Called through Api#handle, as the
# socket calls it; the socket itself is api_test's.
class TestDaemonSimApi < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @log = ISIS::Runtime::Log.new(clock: @clock)
    wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    topology = ISIS::Sim::Topology.from_hash({
      "simulator" => { "system_id" => "0000.0000.0009", "hostname" => "s1", "interfaces" => ["a"] },
      "grid" => { "rows" => 2, "columns" => 2, "loopbacks" => "10.200.0.0/24" },
      "routers" => [{ "name" => "r2c2", "prefixes" => [{ "prefix" => "30.0.0.0/24", "count" => 2 }] }],
      "links" => [{ "from" => "s1", "to" => "r1c1" }]
    })
    @sim = ISIS::Sim::Simulator.new(topology, clock: @clock, scheduler: @scheduler, log: @log,
                                              host: SimHost.new(wires, { "a" => "00:00:00:00:00:09" }))
    @sim.start
    @api = ISIS::Daemon::Api.new(@sim.router, path: "/nonexistent", simulator: @sim)
  end

  def call(method, params = {})
    @api.handle("id" => 1, "method" => method, "params" => params)
  end

  def result(method, params = {})
    r = call(method, params)
    refute r[:error], r[:error]
    r[:result]
  end

  # One API method per simulator action, and no other.
  def test_every_action_has_a_method
    assert_equal ISIS::Sim::Simulator::ACTIONS.keys.sort, ISIS::Daemon::Api::SIM_PARAMS.keys.sort
  end

  def test_state_and_graph
    assert_equal [true, true, 4], result("sim.state").values_at(:generating, :aging).push(result("sim.state").dig(:counts, :systems))
    assert_equal 5, result("sim.graph")[:nodes].size
  end

  def test_link_actions
    assert_equal({ action: "link.down", state: { generating: true, aging: true } },
                 result("sim.link.down", "link" => "r1c1--r1c2"))
    refute @sim.link("r1c1--r1c2").up?
    result("sim.link.toggle", "link" => "r1c1--r1c2")
    assert @sim.link("r1c1--r1c2").up?
    result("sim.link.metric", "link" => 1, "metric" => 40)
    assert_equal 40, @sim.link(1).metric
    result("sim.link.flap", "link" => "r1c1--r1c2", "count" => 1, "interval" => 1)
    @scheduler.advance(0.5)
    refute @sim.link("r1c1--r1c2").up?
  end

  def test_router_and_prefix_actions
    result("sim.router.overload", "router" => "r1c1", "on" => true)
    assert @sim.system("r1c1").overload
    result("sim.router.attached", "router" => "r2c2", "on" => true)
    assert @sim.system("r2c2").attached
    result("sim.prefixes.withdraw", "router" => "r2c2", "prefix" => "30.0.0.0/24")
    assert_equal ["30.0.0.0/24"], result("sim.state")[:systems].find { _1[:name] == "r2c2" }[:withdrawn]
    result("sim.prefixes.advertise", "router" => "r2c2", "prefix" => "30.0.0.0/24")
    assert_equal [], result("sim.state")[:systems].find { _1[:name] == "r2c2" }[:withdrawn]
  end

  def test_database_actions
    assert_equal({ generating: false, aging: true }, result("sim.flush")[:state])
    assert_equal({ generating: true, aging: true }, result("sim.restore")[:state])
    result("sim.refresh")
    assert_equal({ generating: false, aging: false }, result("sim.aging", "on" => false)[:state])
    assert_equal({ generating: true, aging: true }, result("sim.aging", "on" => true)[:state])
  end

  def test_neighbor_actions
    result("sim.neighbor.stop", "circuit" => "a")
    result("sim.neighbor.start")
    assert_includes @log.events.map(&:message), "simulator: hellos stopped on a"
  end

  # Wrong parameters and wrong values come back as errors, with the reason.
  def test_errors
    assert_equal "sim.link.down needs link", call("sim.link.down")[:error]
    assert_equal "no link nope", call("sim.link.down", "link" => "nope")[:error]
    assert_equal "sim.flush takes no parameters, not link", call("sim.flush", "link" => "x")[:error]
    assert_equal "sim.link.down takes link, not metric", call("sim.link.down", "link" => 1, "metric" => 3)[:error]
    assert_match(/\Aa wide link metric is 0 to 16777215/, call("sim.link.metric", "link" => 1, "metric" => 1 << 24)[:error])
  end

  def test_api_info_lists_the_sim_methods
    methods = result("api.info")[:methods]
    assert_includes methods, "sim.link.down"
    assert_includes methods, "show.overview"
    assert result("api.info")[:simulator]
  end

  # Without a simulator, isisd answers none of them.
  def test_no_simulator_no_sim_methods
    api = ISIS::Daemon::Api.new(@sim.router, path: "/nonexistent")
    assert_equal "unknown method sim.state", api.handle("id" => 1, "method" => "sim.state")[:error]
    refute(api.method_names.any? { _1.start_with?("sim.") })
  end
end
