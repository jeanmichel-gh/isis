# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"

# What the API shows of a Router: two of them on a simulated point to
# point wire, and a LAN of two at both levels, on a manual clock.
class TestDaemonViews < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @routers = []
  end

  def router(config, macs)
    r = ISIS::Router.new(config, clock: @clock, scheduler: @scheduler, log: @log, host: SimHost.new(@wires, macs))
    @routers << r
    r
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @routers.each { |r| r.step(wait: 0) }
    end
  end

  def p2p_pair
    a = router({ system_id: "0000.0000.000a", hostname: "a", minimum_lsp_interval: 1,
                 interfaces: [{ name: "ab", ip_addresses: ["10.0.12.1"], hello_interval: 1, hello_multiplier: 3 }],
                 prefixes: [{ prefix: "192.0.2.10/32", metric: 1 }] }, { "ab" => "00:00:00:00:00:0a" })
    b = router({ system_id: "0000.0000.000b", hostname: "b", minimum_lsp_interval: 1,
                 interfaces: [{ name: "ab", ip_addresses: ["10.0.12.2"], hello_interval: 1, hello_multiplier: 3 }],
                 prefixes: [{ prefix: "192.0.2.11/32", metric: 1 }] }, { "ab" => "00:00:00:00:00:0b" })
    @routers.each(&:start)
    run_for(10)
    [ISIS::Daemon::Views.new(a), a, b]
  end

  def test_adjacency_names_the_neighbour_by_its_hostname
    views, = p2p_pair
    adj = views.adjacencies
    assert_equal 1, adj.size
    row = adj.first
    assert_equal({ interface: "ab", level: 1, network: "point-to-point", system_id: "0000.0000.000b", hostname: "b",
                   state: "up", address: "10.0.12.2", areas: ["49.0001"] },
                 row.slice(:interface, :level, :network, :system_id, :hostname, :state, :address, :areas))
    assert_operator row[:hold], :<=, 3
    assert_operator row[:hold], :>, 0
  end

  def test_overview
    views, = p2p_pair
    o = views.overview
    assert_equal "0000.0000.000a", o[:system_id]
    assert_equal "a", o[:hostname]
    assert_equal [1], o[:levels]
    assert_equal 1, o[:adjacencies_up]
    assert_equal({ 1 => 2 }, o[:lsps])
    assert_operator o[:spf_runs][1], :>, 0
  end

  def test_database_marks_its_own_and_names_each
    views, = p2p_pair
    rows = views.database.sort_by { _1[:lsp_id] }
    assert_equal %w[0000.0000.000a.00-00 0000.0000.000b.00-00], rows.map { _1[:lsp_id] }
    assert_equal [true, false], rows.map { _1[:self] }
    assert_equal %w[a b], rows.map { _1[:hostname] }
    assert_match(/\A0x\h{4}\z/, rows.first[:checksum])
    assert_equal [], views.database(level: 2)
  end

  def test_routes
    views, = p2p_pair
    route = views.routes.find { _1[:prefix] == "192.0.2.11/32" }
    assert_equal({ level: 1, prefix: "192.0.2.11/32", metric: 11, external: false, up_down: false,
                   next_hops: [{ address: "10.0.12.2", interface: "ab" }] }, route)
  end

  def test_interfaces
    views, = p2p_pair
    assert_equal [{ name: "ab", network: "point-to-point", level: 1, metric: 10, local_circuit_id: 1, state: "up" }],
                 views.interfaces
  end

  # On a LAN at both levels, one adjacency per level, each found under its
  # interface's name and not the circuit's.
  def test_lan_at_both_levels
    a = router({ system_id: "0000.0000.000a", hostname: "a", level: "1-2", minimum_lsp_interval: 1,
                 interfaces: [{ name: "lan", network: "broadcast", ip_addresses: ["10.0.0.1"], priority: 100,
                                hello_interval: 1, hello_multiplier: 3 }],
                 prefixes: [{ prefix: "192.0.2.10/32", metric: 1 }] }, { "lan" => "00:00:00:00:00:0a" })
    router({ system_id: "0000.0000.000b", hostname: "b", level: "1-2", minimum_lsp_interval: 1,
             interfaces: [{ name: "lan", network: "broadcast", ip_addresses: ["10.0.0.2"],
                            hello_interval: 1, hello_multiplier: 3 }],
             prefixes: [{ prefix: "192.0.2.11/32", metric: 1 }] }, { "lan" => "00:00:00:00:00:0b" })
    @routers.each(&:start)
    run_for(20)
    views = ISIS::Daemon::Views.new(a)
    assert_equal [[1, "b", "up"], [2, "b", "up"]], views.adjacencies.map { [_1[:level], _1[:hostname], _1[:state]] }
    assert_equal [%w[lan self], %w[lan self]], views.interfaces.map { [_1[:name], _1[:dis]] }
    route = views.routes(level: 1).find { _1[:prefix] == "192.0.2.11/32" }
    assert_equal [{ address: "10.0.0.2", interface: "lan" }], route[:next_hops]
  end

  # A point to point adjacency at both levels with no area in common
  # serves Level 2 alone (RFC 1142 8.2.4.2), so it shows at Level 2 only.
  def test_point_to_point_shows_the_levels_it_serves
    a = router({ system_id: "0000.0000.000a", level: "1-2", minimum_lsp_interval: 1,
                 interfaces: [{ name: "ab", hello_interval: 1, hello_multiplier: 3 }] }, { "ab" => "00:00:00:00:00:0a" })
    router({ system_id: "0000.0000.000b", level: "1-2", areas: ["49.0002"], minimum_lsp_interval: 1,
             interfaces: [{ name: "ab", hello_interval: 1, hello_multiplier: 3 }] }, { "ab" => "00:00:00:00:00:0b" })
    @routers.each(&:start)
    run_for(10)
    assert_equal [[2, "up"]], ISIS::Daemon::Views.new(a).adjacencies.map { _1.values_at(:level, :state) }
  end

  def test_log_events_are_json_safe
    views, = p2p_pair
    @log.info("a name \xff", kind: :test, octets: "\xff".b, sym: :x)
    e = views.log(1).first
    assert_equal "test", e[:kind]
    assert_equal({ "octets" => "�", "sym" => "x" }, e[:data])
    JSON.generate(e)
  end
end
