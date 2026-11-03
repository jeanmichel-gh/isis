# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"

# The simulator against an ordinary Router, the device under test, on one
# simulated point to point wire and a manual clock: the DUT learns the
# simulated area through its adjacency with s1, and follows every action.
#
#   dut 0000.0000.0001 -- s1 0000.0000.0009 -- r1c1 -- r1c2 -- r1c3
#                                                |       |       |
#                                              r2c1 -- r2c2 -- r2c3
#
# Every metric 10, so the DUT reaches r2c3's loopback, 10.200.0.6, at 50:
# its link to s1, s1 to r1c1, and three grid hops.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestSimSimulator < Minitest::Test
  HELLO = { hello_interval: 1, hello_multiplier: 3 }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
  end

  def topology(extra = {})
    ISIS::Sim::Topology.from_hash(
      { "simulator" => { "system_id" => "0000.0000.0009", "hostname" => "s1", "areas" => ["49.0001"], "level" => 1,
                         "minimum_lsp_interval" => 1,
                         "interfaces" => [{ "name" => "a", "ip_addresses" => ["10.0.14.2"] }.merge(HELLO.transform_keys(&:to_s))] },
        "grid" => { "rows" => 2, "columns" => 3, "metric" => 10, "loopbacks" => "10.200.0.0/24" },
        "routers" => [{ "name" => "r2c3", "prefixes" => [{ "prefix" => "30.0.0.0/24", "count" => 3 }] }],
        "links" => [{ "from" => "s1", "to" => "r1c1" }] }.merge(extra)
    )
  end

  def start(topo = topology)
    @sim = ISIS::Sim::Simulator.new(topo, clock: @clock, scheduler: @scheduler, log: @log,
                                          host: SimHost.new(@wires, { "a" => "00:00:00:00:00:09" }))
    @dut = ISIS::Router.new({ system_id: "0000.0000.0001", hostname: "dut", minimum_lsp_interval: 1,
                              interfaces: [{ name: "a", ip_addresses: ["10.0.14.1"], **HELLO }] },
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

  def route(prefix) = @dut.decisions[1].routes.values.find { |r| r.prefix.to_s == prefix }

  def held(lsp_id) = @dut.databases[1][ISIS::Pdu.lsp_id_octets(lsp_id)]

  def test_the_dut_learns_the_area
    start
    ids = @dut.databases[1].entries.reject(&:placeholder?).map(&:lsp_id_s).sort
    assert_equal 8, ids.size, ids.inspect
    assert_includes ids, "0000.0001.0203.00-00"
    assert_equal 50, route("10.200.0.6/32").metric
    assert_equal ["10.0.14.2"], route("10.200.0.6/32").adjacencies.map(&:address)
    assert_equal 60, route("30.0.2.0/24").metric
    names = ISIS::Daemon::Views.new(@dut).hostnames
    assert_equal %w[r1c1 r2c3 s1], names.values_at("0000.0001.0101", "0000.0001.0203", "0000.0000.0009")
  end

  # Each simulated LSP carries what the topology gives the system: its
  # areas, its hostname, its loopback in TLV 132, its neighbours.
  def test_a_simulated_lsp
    start
    lsp = held("0000.0001.0101.00-00").lsp
    tlvs = lsp.tlvs.to_a
    assert_equal ["49.0001"], tlvs.grep(ISIS::Tlv::AreaAddresses).flat_map(&:areas).map(&:to_s)
    assert_equal ["r1c1"], tlvs.grep(ISIS::Tlv::DynamicHostname).map(&:to_hash)
    assert_equal "84040ac80001", tlvs.grep(ISIS::Tlv::IpInterfaceAddresses).map(&:to_shex).join
    neighbors = tlvs.grep(ISIS::Tlv::ExtendedIsReachability).flat_map(&:entries).map { |e| [e.neighbor_s, e.metric] }
    assert_equal [["0000.0000.0009.00", 10], ["0000.0001.0102.00", 10], ["0000.0001.0201.00", 10]], neighbors.sort
    assert lsp.checksum_ok?
    assert_equal 1, lsp.is_type
  end

  def test_a_link_metric_moves_the_route
    start
    @sim.link_metric("s1--r1c1", 50)
    run_for(5)
    assert_equal 90, route("10.200.0.6/32").metric
  end

  # Down is two entries gone, one in each end's LSP; the route goes the
  # other way, as long as there is one.
  def test_link_down_and_up
    start
    @sim.link_down("r1c1--r1c2")
    @sim.link_down("r2c1--r1c1")
    run_for(5)
    assert_nil route("10.200.0.6/32")
    assert_equal 20, route("10.200.0.1/32").metric
    @sim.link_up(1)
    run_for(5)
    assert_equal 50, route("10.200.0.6/32").metric
  end

  def test_flap
    start
    @sim.link_flap("s1--r1c1", count: 2, interval: 2)
    run_for(1)
    assert_nil route("10.200.0.6/32")
    run_for(10)
    assert_equal 50, route("10.200.0.6/32").metric
    assert @sim.link("s1--r1c1").up?
  end

  # Overloaded, r1c1 carries no transit (RFC 1142 7.2.8.1): the rest of the
  # grid is lost, its own loopback is not.
  def test_overload
    start
    @sim.router_overload("r1c1", true)
    run_for(5)
    assert held("0000.0001.0101.00-00").lsp.overload?
    assert_nil route("10.200.0.6/32")
    assert_equal 20, route("10.200.0.1/32").metric
    @sim.router_overload("r1c1", false)
    run_for(5)
    assert_equal 50, route("10.200.0.6/32").metric
  end

  def test_attached
    start
    @sim.router_attached("r2c3", true)
    run_for(5)
    assert_equal [:default], held("0000.0001.0203.00-00").lsp.attached
    assert_equal 50, route("0.0.0.0/0").metric
  end

  def test_withdraw_and_advertise_a_group
    start
    @sim.prefixes_withdraw("r2c3", "30.0.0.0/24")
    run_for(5)
    assert_nil route("30.0.2.0/24")
    assert_equal 50, route("10.200.0.6/32").metric
    @sim.prefixes_advertise("r2c3", "30.0.0.0/24")
    run_for(5)
    assert_equal 60, route("30.0.2.0/24").metric
    assert_raises(ArgumentError) { @sim.prefixes_withdraw("r2c3", "31.0.0.0/24") }
  end

  # Flushed, every simulated LSP is a purge at the DUT and the routes go;
  # restored, each comes back past its purge.
  def test_flush_and_restore
    start
    before = held("0000.0001.0203.00-00").sequence
    @sim.flush
    run_for(5)
    assert held("0000.0001.0203.00-00").purged?
    assert_nil route("10.200.0.6/32")
    refute held("0000.0000.0009.00-00").purged?, "the simulator's own LSP stays"
    @sim.restore
    run_for(5)
    assert_operator held("0000.0001.0203.00-00").sequence, :>, before
    assert_equal 50, route("10.200.0.6/32").metric
  end

  # Aging off: nothing refreshes, so the LSPs run out at the DUT within the
  # topology's lifetime. On: generated again at once.
  def test_aging
    start(topology("simulator" => topology.router_config.transform_keys(&:to_s).merge("lsp_lifetime" => 60)))
    assert_operator held("0000.0001.0203.00-00").remaining_lifetime, :<=, 60
    # Refreshed before the lifetime runs out, so nothing ever purges it,
    # here or at the DUT.
    run_for(150)
    purges = @log.events.select { |e| e.kind == :purge && e.data[:lsp_id] == "0000.0001.0203.00-00" }
    assert_empty purges.map(&:message)
    assert_equal 50, route("10.200.0.6/32").metric
    @sim.aging = false
    run_for(70)
    assert_nil route("10.200.0.6/32")
    @sim.aging = true
    run_for(5)
    assert_equal 50, route("10.200.0.6/32").metric
  end

  # A copy of a simulated LSP newer than the simulator's is generated past
  # (RFC 1142 7.3.16.1), as for the simulator's own.
  def test_a_newer_copy_is_generated_past
    start
    entry = held("0000.0001.0203.00-00")
    copy = ISIS::Pdu::Lsp.new(entry.lsp.to_hash.merge(sequence: entry.sequence + 5))
    entry.store(copy)
    @dut.databases[1].circuits.each { |c| c.flood(entry) }
    run_for(10)
    assert_equal entry.sequence, @sim.originators["r2c3"][1].sequence
    assert_operator held("0000.0001.0203.00-00").sequence, :>, copy.sequence
  end

  # Flushed, the simulator generates nothing: a newer copy that arrives is
  # held like any other system's, and not generated past.
  def test_flushed_systems_are_not_generated_past
    start
    entry = held("0000.0001.0203.00-00")
    copy = ISIS::Pdu::Lsp.new(entry.lsp.to_hash.merge(sequence: entry.sequence + 5))
    @sim.flush
    run_for(2)
    entry.store(copy)
    @dut.databases[1].circuits.each { |c| c.flood(entry) }
    run_for(10)
    assert_equal copy.sequence, @sim.router.databases[1][ISIS::Pdu.lsp_id_octets("0000.0001.0203.00-00")].sequence
    assert_equal copy.sequence, held("0000.0001.0203.00-00").sequence
  end

  # The simulator's hellos stop: the DUT's adjacency times out and the
  # area goes with it. Started again, it comes back.
  def test_neighbor_stop_and_start
    start
    @sim.neighbor_stop
    run_for(5)
    assert_nil route("10.200.0.6/32")
    @sim.neighbor_start(circuit: "a")
    run_for(15)
    assert_equal 50, route("10.200.0.6/32").metric
  end

  # Started again while sending, a circuit keeps one hello timer: stopped
  # once, it goes quiet and the DUT's adjacency times out.
  def test_neighbor_start_twice
    start
    @sim.neighbor_start
    @sim.neighbor_stop
    run_for(5)
    assert_nil route("10.200.0.6/32")
    assert_equal [{ name: "a", hellos: false }], @sim.state[:interfaces]
    @sim.neighbor_start
    assert_equal [{ name: "a", hellos: true }], @sim.state[:interfaces]
  end

  # One way, the two-way check fails (7.2.8.2) and nothing past is reached.
  def test_a_one_way_link
    start(topology("links" => [{ "from" => "s1", "to" => "r1c1", "one_way" => true }]))
    assert_nil route("10.200.0.1/32")
  end

  def test_state_and_graph
    start
    s = @sim.state
    assert_equal [true, true, 6], [s[:generating], s[:aging], s.dig(:counts, :systems)]
    r = s[:systems].find { _1[:name] == "r2c3" }
    assert_equal [4, { 1 => 1 }], [r[:prefixes], r[:lsps]]
    assert_equal({ name: "s1--r1c1", from: "s1", to: "r1c1", metric: 10, state: "up", one_way: false, levels: [1], number: 8 },
                 s[:links].find { _1[:name] == "s1--r1c1" })
    assert_equal ["wide", 0xFFFFFF, [{ name: "a", hellos: true }]], s.values_at(:metric_style, :metric_max, :interfaces)
    assert_equal ["10.200.0.6/32", "30.0.0.0/24"], r[:groups], "its loopback and its group of three"
    g = @sim.graph
    assert_equal 7, g[:nodes].size
    assert_equal [true, [1, 1]], g[:nodes].values_at(0, 1).map { _1[:simulator] ? true : _1[:grid] }
  end

  def test_refusals
    start
    assert_raises(ArgumentError) { @sim.link("nope") }
    assert_raises(ArgumentError) { @sim.router_overload("s1", true) }
    assert_raises(ArgumentError) { @sim.link_metric(1, 0x1000000) }
    assert_raises(ArgumentError) { @sim.restore }
    @sim.flush
    assert_raises(ArgumentError) { @sim.refresh }
  end
end
