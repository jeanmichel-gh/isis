# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"

# TI-LFA's backups in the Decision Process (Spf::Backups), on real routers
# on simulated wires and a manual clock: a protects its link to b
# (ti_lfa: link), and each route through b gets a backup with the labels
# RFC 9855 section 7.1 gives it. Every router has SR, SRGB 16000 for a,
# 18000 b, 20000 c, 22000 d, and its loopback 10.255.0.N/32 has index N.
class TestSpfBackups < Minitest::Test
  BASE = { "a" => 16_000, "b" => 18_000, "c" => 20_000, "d" => 22_000, "e" => 24_000 }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @routers = {}
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @routers.each_value { |r| r.step(wait: 0) }
    end
  end

  # Routers joined by +links+, [a, b, metric], each link a wire named for
  # its ends; a's interface to b has ti_lfa, +mode+ link unless told.
  def build(links, protect: %w[a ab], mode: "link")
    ifaces = Hash.new { |h, k| h[k] = [] }
    links.each_with_index do |(x, y, metric), i|
      name = "#{x}#{y}"
      [[x, 1], [y, 2]].each do |id, end_|
        i_conf = { name: name, ip_addresses: ["10.#{i}.0.#{end_}"], metric: metric, hello_interval: 1,
                   hello_multiplier: 3 }
        i_conf[:ti_lfa] = mode if [id, name] == protect
        ifaces[id] << i_conf
      end
    end
    ifaces.each do |id, list|
      n = id.ord - 96
      macs = list.to_h { |c| [c[:name], format("00:00:00:00:%02x:%02x", n, list.index(c) + 1)] }
      @routers[id] = ISIS::Router.new(
        { system_id: "0000.0000.000#{id}", hostname: id, minimum_lsp_interval: 1, interfaces: list, forwarding: true,
          prefixes: [{ prefix: "10.255.0.#{n}/32", metric: 0, sid: n }],
          segment_routing: { srgb: [{ start: BASE[id], size: 8_000 }] } },
        clock: @clock, scheduler: @scheduler, log: @log, host: SimHost.new(@wires, macs)
      )
    end
    @routers.each_value(&:start)
    run_for(20)
    @routers["a"]
  end

  def backup(router, prefix) = router.decisions[1].backups.routes[prefix]

  # 5.1: c is in P and Q; the label is b's index in c's SRGB.
  def test_a_triangle
    a = build([["a", "b", 10], ["a", "c", 10], ["b", "c", 10]])
    bk = backup(a, "10.255.0.2/32")
    assert_instance_of ISIS::Spf::Backups::Backup, bk
    assert_equal ["ac", [20_002], :neighbor], [bk.adjacency.circuit, bk.labels, bk.repair.case]
    assert_nil backup(a, "10.255.0.3/32"), "c's route does not go through b"
    # b's label route, 16002, popped toward b, backs up with the same labels.
    assert_equal [20_002], a.decisions[1].backups.label(16_002).labels
  end

  # 5.2: d is the PQ node. A node segment to d, in c's SRGB, then b's
  # index in d's.
  def test_a_square
    a = build([["a", "b", 10], ["a", "c", 10], ["c", "d", 10], ["d", "b", 10]])
    bk = backup(a, "10.255.0.2/32")
    assert_equal ["ac", [20_004, 22_002], :pq_node], [bk.adjacency.circuit, bk.labels, bk.repair.case]
    # d is reached at 20 through b and through c: ECMP.
    assert_instance_of ISIS::Spf::Backups::Ecmp, backup(a, "10.255.0.4/32")
  end

  # Nothing but b: no path.
  def test_a_line
    a = build([["a", "b", 10], ["b", "c", 10]])
    assert_equal :no_path, backup(a, "10.255.0.2/32").reason
    assert_equal :no_path, backup(a, "10.255.0.3/32").reason
  end

  # What isisd shows: the backup on the route and on its label, and the
  # summary.
  def test_the_views
    a = build([["a", "b", 10], ["a", "c", 10], ["c", "d", 10], ["d", "b", 10]])
    views = ISIS::Daemon::Views.new(a)
    row = views.routes.find { _1[:prefix] == "10.255.0.2/32" }
    # c's end of the a-c link, the second link, is 10.1.0.2.
    assert_equal({ address: "10.1.0.2", interface: "ac", labels: [20_004, 22_002], case: "pq_node", protects: "link" },
                 row[:backup])
    assert_equal({ ecmp: true }, views.routes.find { _1[:prefix] == "10.255.0.4/32" }[:backup])
    label = views.labels.find { _1[:label] == 16_002 }
    assert_equal [20_004, 22_002], label[:backup][:labels]
    t = views.ti_lfa
    assert_equal [true, ["ab"]], t.values_at(:enabled, :interfaces)
    p = t[:levels][1][:protecting].first
    assert_equal ["ab", "b", "link", 1, 1], p.values_at(:interface, :neighbor, :mode, :protected, :ecmp)
    assert_operator t[:levels][1][:trees], :>, 0
  end

  # The backups go to the forwarding adapter beside the routes, and the
  # host is asked to pass over routes whose link is down.
  def test_installed
    a = build([["a", "b", 10], ["a", "c", 10], ["c", "d", 10], ["d", "b", 10]])
    host = a.instance_variable_get(:@host)
    assert_equal ["ab"], host.link_down
    ops = host.adapters[1].operations.grep(ISIS::Forwarding::BackupOperation)
    op = ops.find { _1.prefix == "10.255.0.2/32" }
    assert_equal [:install, "ac", [20_004, 22_002]], [op.kind, op.adjacency.circuit, op.labels]
    refute ops.any? { _1.prefix == "10.255.0.4/32" }, "ECMP has no backup route"
  end

  # Node protection, a square with e behind b and, at 30, behind d too:
  #
  #   a -- b -- e
  #   |    |    |
  #   c -- d ---+
  #
  # e's backup avoids b: P is d, the last of the path a c d e in c's
  # P-space, Q is e, adjacent (5.3): d's Node-SID in c's SRGB, then d's
  # Adj-SID to e; e is Q and advertises its prefix, so nothing after.
  # b's own prefix has no node backup, nothing avoids b, so it falls back
  # to the link's: d is the PQ node, then b's index in d's SRGB.
  def test_node_protection_with_link_fallback
    a = build([["a", "b", 10], ["a", "c", 10], ["c", "d", 10], ["d", "b", 10], ["b", "e", 10], ["d", "e", 30]],
              mode: "node")
    e = backup(a, "10.255.0.5/32")
    graph = ISIS::Spf::Graph.from_database(a.databases[1])
    d_to_e = graph.adj_sids[[(ISIS::Pdu.dotted_octets("0000.0000.000d") + "\x00").b,
                             (ISIS::Pdu.dotted_octets("0000.0000.000e") + "\x00").b]]
    assert_equal ["ac", [20_004, d_to_e], :p_and_q_adjacent, :node, nil],
                 [e.adjacency.circuit, e.labels, e.repair.case, e.protects, e.fallback]
    b = backup(a, "10.255.0.2/32")
    assert_equal [[20_004, 22_002], :link, true], [b.labels, b.protects, b.fallback]
    s = a.decisions[1].backups.summaries.first
    assert_equal [:node, 1], [s.mode, s.fallback]
    row = ISIS::Daemon::Views.new(a).routes.find { _1[:prefix] == "10.255.0.2/32" }
    assert_equal ["link", true], row[:backup].values_at(:protects, :fallback)
  end

  # The same square protecting the link only: e's backup may cross b.
  def test_link_protection_may_cross_the_neighbor
    a = build([["a", "b", 10], ["a", "c", 10], ["c", "d", 10], ["d", "b", 10], ["b", "e", 10], ["d", "e", 30]])
    e = backup(a, "10.255.0.5/32")
    assert_equal :link, e.protects
    assert_nil e.fallback
  end

  # Without ti_lfa, nothing is computed and nothing shown.
  def test_off
    a = build([["a", "b", 10], ["a", "c", 10], ["b", "c", 10]], protect: [])
    assert_nil a.decisions[1].backups
    assert_equal({ enabled: false }, ISIS::Daemon::Views.new(a).ti_lfa)
    refute ISIS::Daemon::Views.new(a).routes.any? { _1.key?(:backup) }
  end

  def test_what_the_configuration_refuses
    base = { system_id: "0000.0000.000a", segment_routing: {}, prefixes: [{ prefix: "10.255.0.1/32", metric: 0 }] }
    refuse = lambda do |iface, conf = base|
      assert_raises(ArgumentError) { ISIS::Router.normalize(conf.merge(interfaces: [iface])) }.message
    end
    assert_match(/ti_lfa is link or node, not both/, refuse.({ name: "e1", ti_lfa: "both" }))
    assert_match(/ti_lfa protects point-to-point/, refuse.({ name: "e1", network: "broadcast", ti_lfa: "link" }))
    assert_match(/ti_lfa needs segment_routing/,
                 refuse.({ name: "e1", ti_lfa: "link" }, base.except(:segment_routing)))
  end
end
