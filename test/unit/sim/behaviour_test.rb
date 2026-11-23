# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"

# The catalog's behaviours (ISIS::Fault::BEHAVIOURS), each run by the
# simulator (Simulator#behave) against a point of local repair: dut, an
# ordinary Router with ti_lfa on its link a to the simulator s1. n2 is a
# second ordinary Router. x, y and d are simulated behind s1. On a
# manual clock.
#
#        a 10        b 10
#   s1 -------- dut -------- n2
#    |  \                     |
#    |   \--------------------/ c 100
#   10  10
#    x    y
#   10    20
#     \  /
#      d
#
# dut reaches d through s1 and x, 30. Without a, its path is n2, s1, x,
# d: n2 is in P-space, s1 in Q-space, so the repair is P and Q adjacent
# (RFC 9855 5.3): n2's Adj-SID to s1, then d's index, 13, in s1's SRGB.
# SRGBs: dut 16000, n2 18000, s1 17000, each 8000.
class TestSimBehaviour < Minitest::Test
  HELLO = { hello_interval: 1, hello_multiplier: 3 }.freeze
  D = "10.255.0.13/32"
  X = "10.255.0.11/32"
  LIFETIME = 120

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
  end

  def iface(name, address, metric, **more)
    { name: name, ip_addresses: [address], metric: metric, **HELLO, **more }
  end

  def router(id, n, interfaces, srgb, macs)
    ISIS::Router.new({ system_id: format("0000.0000.%04x", n), hostname: id, minimum_lsp_interval: 1,
                       interfaces: interfaces, forwarding: true,
                       prefixes: [{ prefix: "10.255.0.#{n}/32", metric: 0, sid: n }],
                       segment_routing: { srgb: [{ start: srgb, size: 8_000 }] } },
                     clock: @clock, scheduler: @scheduler, log: @log, host: SimHost.new(@wires, macs))
  end

  def start
    sim_if = ->(n, a, m) { { "name" => n, "ip_addresses" => [a], "metric" => m }.merge(HELLO.transform_keys(&:to_s)) }
    topo = ISIS::Sim::Topology.from_hash(
      { "simulator" => { "system_id" => "0000.0000.0009", "hostname" => "s1", "areas" => ["49.0001"], "level" => 1,
                         "minimum_lsp_interval" => 1, "lsp_lifetime" => LIFETIME,
                         "interfaces" => [sim_if.call("a", "10.0.1.2", 10), sim_if.call("c", "10.0.3.2", 100)] },
        "segment_routing" => {},
        "routers" => [{ "name" => "x", "system_id" => "0000.0000.0011", "loopback" => "10.255.0.11", "sid" => 11 },
                      { "name" => "y", "system_id" => "0000.0000.0012", "loopback" => "10.255.0.12", "sid" => 12 },
                      { "name" => "d", "system_id" => "0000.0000.0013", "loopback" => "10.255.0.13", "sid" => 13 }],
        "links" => [{ "from" => "s1", "to" => "x", "metric" => 10 }, { "from" => "s1", "to" => "y", "metric" => 10 },
                    { "from" => "x", "to" => "d", "metric" => 10 }, { "from" => "y", "to" => "d", "metric" => 20 }] }
    )
    topo.router_config[:segment_routing] = { srgb: [{ start: 17_000, size: 8_000 }] }
    topo.router_config[:router_id] = "10.0.0.9"
    @sim = ISIS::Sim::Simulator.new(topo, clock: @clock, scheduler: @scheduler, log: @log,
                                          host: SimHost.new(@wires, { "a" => "00:00:00:00:09:01", "c" => "00:00:00:00:09:02" }))
    @dut = router("dut", 1, [iface("a", "10.0.1.1", 10, ti_lfa: "link"), iface("b", "10.0.2.1", 10)], 16_000,
                  { "a" => "00:00:00:00:01:01", "b" => "00:00:00:00:01:02" })
    @n2 = router("n2", 2, [iface("b", "10.0.2.2", 10), iface("c", "10.0.3.1", 100)], 18_000,
                 { "b" => "00:00:00:00:02:01", "c" => "00:00:00:00:02:02" })
    [@sim, @dut, @n2].each(&:start)
    run_for(20)
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      [@sim, @dut, @n2].each { |r| r.step(wait: 0) }
    end
  end

  def route(prefix) = @dut.decisions[1].routes[prefix]
  def backup(prefix) = @dut.decisions[1].backups&.routes&.[](prefix)
  def first_hop(prefix) = route(prefix)&.adjacencies&.map(&:circuit)

  # [circuit, labels, case] of dut's backup for +prefix+.
  def repair(prefix)
    b = backup(prefix)
    b.respond_to?(:labels) ? [b.adjacency.circuit, b.labels, b.repair.case] : b
  end

  def held(system_id) = @dut.databases[1][(ISIS::Pdu.dotted_octets(system_id) + "\x00\x00").b]

  def srgb_held(system_id)
    cap = held(system_id).lsp.tlvs.find { _1.is_a?(ISIS::Tlv::RouterCapability) }
    cap.to_hash.dig(:subtlvs, 0, :sr_capabilities, :descriptors, 0, :label)
  end

  def adj_sid = repair(D)[1].first

  def test_the_repair_before_any_behaviour
    start
    assert_equal %w[a], first_hop(D)
    assert_equal 30, route(D).metric
    circuit, labels, kase = repair(D)
    assert_equal ["b", :p_and_q_adjacent], [circuit, kase]
    assert_equal 2, labels.size
    assert_equal 17_013, labels.last, "d's index in s1's SRGB (RFC 9855 7.1)"
  end

  # flap on a, hellos stopped 8 s then sent 12 s, twice: read 7 s into
  # each loss, dut has converged on its repair's first hop, n2; read 10 s
  # after each return, its backup is computed again, the one it had.
  def test_flap
    start
    before = repair(D)
    answer = @sim.behave(:flap, circuit: "a", count: 2, down: 8, up: 12)
    assert_equal [:flap, "RFC 9855 1"], answer.values_at(:behaviour, :rfc)
    assert_equal 28.0, answer[:ends_in]
    assert_equal :flap, @sim.behaviour[:name]
    run_for(7)
    2.times do |i|
      assert_equal %w[b], first_hop(D), "loss #{i + 1}: converged on the repair's first hop"
      assert_equal 130, route(D).metric
      assert_nil backup(D), "no backup through b, which has no ti_lfa"
      run_for(11)
      assert_equal %w[a], first_hop(D), "back #{i + 1}"
      assert_equal before, repair(D), "back #{i + 1}: the backup computed again"
      run_for(9)
    end
    assert_nil @sim.behaviour, "flap ends on its own"
  end

  # Stopped in a loss: hellos go again, and dut is whole.
  def test_flap_stopped_early
    start
    before = repair(D)
    @sim.behave(:flap, circuit: "a", count: 5, down: 30, up: 1)
    run_for(8)
    assert_equal %w[b], first_hop(D)
    assert_equal({ stopped: :flap }, @sim.behave_stop)
    run_for(8)
    assert_equal before, repair(D)
    assert_nil @sim.behaviour
  end

  # stale_lsp on x: s1 and d report their links to x down; x's own LSP
  # still reports them, unchanged, until it expires. dut uses neither
  # (RFC 1142 7.2.8.2): d through y, x unreachable. Then the LSP expires
  # (7.3.16.4). Stopped, x is generated again.
  def test_stale_lsp
    start
    x_id = "0000.0000.0011"
    seq = held(x_id).sequence
    answer = @sim.behave(:stale_lsp, router: "x")
    assert_equal [%w[s1--x x--d], LIFETIME], answer.values_at(:links, :lifetime)
    assert @sim.stale?("x")
    run_for(10)
    assert_equal seq, held(x_id).sequence, "x's own LSP as it was"
    refute held(x_id).purged?
    assert_nil route(X), "x unreachable: only x reports its links"
    assert_equal 40, route(D).metric, "d through y"
    assert_equal %w[a], first_hop(D)
    assert_equal 17_013, repair(D)[1].last, "the repair does not cross x"
    e = assert_raises(ArgumentError) { @sim.router_overload("x", true) }
    assert_match(/stale/, e.message)

    run_for(LIFETIME)
    entry = held(x_id)
    assert entry.nil? || entry.purged?, "x's LSP expired"

    assert_equal({ stopped: :stale_lsp }, @sim.behave_stop)
    refute @sim.stale?("x")
    run_for(10)
    assert_operator held(x_id).sequence, :>, seq
    assert_equal 20, route(X).metric
    assert_equal 30, route(D).metric
  end

  # srgb_change on s1, the repair's Q: its SRGB moves 100000 up, and the
  # last label of dut's repair with it (RFC 8660 2.4, RFC 9855 7.1); n2's
  # Adj-SID stays. Stopped, the SRGB is back.
  def test_srgb_change_on_q
    start
    adj = adj_sid
    answer = @sim.behave(:srgb_change, router: "s1")
    assert_equal({ from: [[17_000, 8_000]], to: [[117_000, 8_000]] }, answer[:srgb])
    run_for(5)
    assert_equal 117_000, srgb_held("0000.0000.0009")
    assert_equal [adj, 117_013], repair(D)[1]
    @sim.behave_stop
    run_for(5)
    assert_equal 17_000, srgb_held("0000.0000.0009")
    assert_equal [adj, 17_013], repair(D)[1]
  end

  # On a simulated system, to a start given: its LSP carries the block.
  def test_srgb_change_on_a_simulated_system
    start
    @sim.behave(:srgb_change, router: "d", start: 300_000)
    run_for(5)
    assert_equal 300_000, srgb_held("0000.0000.0013")
    e = assert_raises(ArgumentError) { @sim.fault(:srgb_overlap, router: "d") }
    assert_match(/srgb_change/, e.message)
    @sim.behave_stop
    run_for(5)
    assert_equal 16_000, srgb_held("0000.0000.0013"), "the file's own SRGB"
  end

  def test_one_at_a_time_and_what_is_refused
    start
    e = assert_raises(ArgumentError) { @sim.behave(:nope) }
    assert_match(/flap, stale_lsp, srgb_change/, e.message)
    assert_match(/needs router/, assert_raises(ArgumentError) { @sim.behave(:stale_lsp) }.message)
    assert_match(/takes router/, assert_raises(ArgumentError) { @sim.behave(:stale_lsp, router: "x", count: 2) }.message)
    assert_match(/no interface/, assert_raises(ArgumentError) { @sim.behave(:flap, circuit: "z") }.message)
    assert_match(/simulator itself/, assert_raises(ArgumentError) { @sim.behave(:stale_lsp, router: "s1") }.message)
    assert_match(/label|block|range/i,
                 assert_raises(ArgumentError) { @sim.behave(:srgb_change, router: "d", start: 1_048_000) }.message)
    assert_nil @sim.behaviour, "nothing runs after a refusal"
    @sim.behave(:srgb_change, router: "d")
    assert_match(/srgb_change runs/, assert_raises(ArgumentError) { @sim.behave(:flap) }.message)
    assert_equal :srgb_change, @sim.state[:behaviour][:name]
    @sim.behave_stop
    assert_equal({ stopped: nil }, @sim.behave_stop)
  end
end
