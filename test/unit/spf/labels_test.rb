# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"

# The label table after SPF (Spf::Labels), on routers in a line on
# simulated wires: a ---- b ---- c, with SRGBs from 16000, 18000 and 20000,
# and Node-SIDs 1, 2 and 3 on 10.255.0.1, .2 and .3. The same line as
# routescope's frr-sr lab, where FRR 10.2.1 gave a 16003 swapped to 18003
# and 16002 popped, and b 18001 and 18003 popped
# (routescope test/fixtures/frr/sr-mpls).
class TestSpfLabels < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @routers = []
    @hosts = {}
  end

  # RFC 8667 section 3.1's example, under RFC 8660 section 2.4's formula:
  # ranges [100, 199], [1000, 1099], [500, 599].
  def test_an_index_across_ranges
    srgb = [[100, 199], [1000, 1099], [500, 599]]
    at = ->(i) { ISIS::Spf::Labels.label_at(srgb, i) }
    assert_equal [100, 199, 1000, 1099, 500, 599], [0, 99, 100, 199, 200, 299].map(&at)
    assert_nil at.(300)
    assert_nil at.(-1)
  end

  def router(config, macs)
    host = SimHost.new(@wires, macs)
    r = ISIS::Router.new(config, clock: @clock, scheduler: @scheduler, log: @log, host: host)
    @hosts[r] = host
    @routers << r
    r
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @routers.each { |r| r.step(wait: 0) }
    end
  end

  def p2p(name, ip)
    { name: name, ip_addresses: [ip], hello_interval: 1, hello_multiplier: 3 }
  end

  # a ---- b ---- c. +sr+ maps a router to its segment_routing block, or
  # nil for none; +sids+ to its loopback's prefix entry extras; +own+ to
  # more configuration for that router alone.
  def line(sr: {}, sids: {}, extra: {}, own: {})
    base = { "a" => 16_000, "b" => 18_000, "c" => 20_000 }
    conf = lambda do |id, ifaces|
      n = id.ord - 96
      block = sr.key?(id) ? sr[id] : { srgb: [{ start: base[id], size: 8_000 }] }
      prefix = { prefix: "10.255.0.#{n}/32", metric: 0 }
      prefix = prefix.merge(sid: n).merge(sids.fetch(id, {})) if block
      { system_id: "0000.0000.000#{id}", hostname: id, minimum_lsp_interval: 1, prefixes: [prefix],
        interfaces: ifaces }.merge(block ? { segment_routing: block } : {}).merge(extra).merge(own.fetch(id, {}))
    end
    a = router(conf.("a", [p2p("ab", "10.0.12.1")]), { "ab" => "00:00:00:00:00:0a" })
    b = router(conf.("b", [p2p("ab", "10.0.12.2"), p2p("bc", "10.0.23.1")]),
               { "ab" => "00:00:00:00:01:0b", "bc" => "00:00:00:00:02:0b" })
    c = router(conf.("c", [p2p("bc", "10.0.23.2")]), { "bc" => "00:00:00:00:00:0c" })
    @routers.each(&:start)
    run_for(20)
    [a, b, c]
  end

  # label => [op, kind, fec, [[circuit, out-label]]].
  def table(router)
    router.decisions[1].labels.entries.transform_values do |e|
      fec = e.kind == :adj_sid ? ISIS::SystemId.from_bytes(e.fec).to_s : e.fec
      [e.op, e.kind, fec, e.hops.map { |adj, out| [adj.circuit, out] }]
    end
  end

  # As FRR gave it: a pushes c's index in b's block and pops toward b; its
  # own Node-SID has no label, since with PHP nobody sends it one.
  def test_the_end_of_the_line
    a, = line
    assert_equal({ 15_000 => [:pop, :adj_sid, "0000.0000.000b", [["ab", 3]]],
                   16_002 => [:php, :prefix_sid, "10.255.0.2/32", [["ab", 3]]],
                   16_003 => [:swap, :prefix_sid, "10.255.0.3/32", [["ab", 18_003]]] }, table(a))
    adj = a.decisions[1].routes["10.255.0.3/32"].adjacencies.first
    assert_equal 18_003, a.decisions[1].labels.out_label("10.255.0.3/32", adj)
    assert_empty a.decisions[1].labels.problems
  end

  def test_the_middle_of_the_line
    _, b, = line
    assert_equal({ 15_000 => [:pop, :adj_sid, "0000.0000.000a", [["ab", 3]]],
                   15_001 => [:pop, :adj_sid, "0000.0000.000c", [["bc", 3]]],
                   18_001 => [:php, :prefix_sid, "10.255.0.1/32", [["ab", 3]]],
                   18_003 => [:php, :prefix_sid, "10.255.0.3/32", [["bc", 3]]] }, table(b))
  end

  # P on c's SID: b keeps the label, in c's block, and c pops its own.
  def test_no_php
    _, b, c = line(sids: { "c" => { no_php: true } })
    assert_equal [:swap, :prefix_sid, "10.255.0.3/32", [["bc", 20_003]]], table(b)[18_003]
    assert_equal [:pop, :prefix_sid, "10.255.0.3/32", []], table(c)[20_003]
  end

  # P and E: b sends explicit null, 0 for IPv4 (RFC 8667 section 2.1.1.3).
  def test_explicit_null
    _, b, = line(sids: { "c" => { explicit_null: true } })
    assert_equal [:swap, :prefix_sid, "10.255.0.3/32", [["bc", 0]]], table(b)[18_003]
  end

  # Two prefixes with one index: both left out, and said once.
  def test_an_index_used_twice
    _, b, = line(sids: { "a" => { sid: 7 }, "c" => { sid: 7 } })
    refute table(b).key?(18_007)
    assert_equal [:prefix_sid_duplicate], b.decisions[1].labels.findings.map(&:name)
    assert_equal 1, b.decisions[1].labels.problems.grep(/index 7: the Prefix-SID of 10.255.0.1\/32 and 10.255.0.3\/32/).size
  end

  # b runs no SR: a has no label for c's SID through it, and says why. Its
  # IP route stays.
  def test_a_neighbor_without_an_srgb
    a, = line(sr: { "b" => nil })
    refute table(a).key?(16_003)
    assert a.decisions[1].routes["10.255.0.3/32"]
    assert_equal 1, a.decisions[1].labels.problems.grep(/10.255.0.3\/32: neighbor 0000.0000.000b has no SRGB/).size
  end

  # A Prefix-SID past this system's SRGB has no in-label.
  def test_an_index_past_the_srgb
    a, = line(sr: { "a" => { srgb: [{ start: 16_000, size: 3 }] } }, sids: { "c" => { sid: 5 } })
    refute table(a).values.any? { _1[2] == "10.255.0.3/32" }
    assert_equal 1, a.decisions[1].labels.problems.grep(/index 5 is past this system's SRGB/).size
  end

  # Without segment_routing there is no table.
  def test_no_segment_routing_no_labels
    a, = line(sr: { "a" => nil, "b" => nil, "c" => nil })
    assert_nil a.decisions[1].labels
  end

  # What the API answers (show.labels, show.segment_routing, show.routes),
  # read from a, as routescope's inspector will read it.
  def test_the_views
    a, = line
    views = ISIS::Daemon::Views.new(a)
    rows = views.labels(level: 1)
    assert_equal [[15_000, "adj_sid", "b", "pop"], [16_002, "prefix_sid", "10.255.0.2/32", "php"],
                  [16_003, "prefix_sid", "10.255.0.3/32", "swap"]], rows.map { _1.values_at(:label, :kind, :fec, :op) }
    assert_equal [{ address: "10.0.12.2", interface: "ab", label: 18_003 }], rows.last[:next_hops]

    route = views.routes(level: 1).find { _1[:prefix] == "10.255.0.3/32" }
    assert_equal 3, route[:sid]
    assert_equal 18_003, route[:next_hops].first[:label]
    refute views.routes(level: 1).find { _1[:prefix] == "10.0.12.0/30" }&.key?(:sid)

    sr = views.segment_routing
    assert_equal [true, "10.255.0.1", ["16000-23999"], "15000-15999"], sr.values_at(:enabled, :router_id, :srgb, :srlb)
    assert_equal [{ interface: "ab", neighbor: "b", family: "ipv4", label: 15_000 }], sr[:adj_sids]
    nodes = sr[:levels][1][:nodes].to_h { [_1[:hostname], _1[:srgb]] }
    assert_equal({ "a" => ["16000-23999"], "b" => ["18000-25999"], "c" => ["20000-27999"] }, nodes)
    # Every system's Router ID, SRLB and Node-SID, as FRR's
    # "show isis segment-routing node" gives them, with the label a takes
    # each in: its own SRGB from 16000.
    rows = sr[:levels][1][:nodes].to_h { [_1[:hostname], _1.values_at(:router_id, :srlb, :sid, :prefix, :label)] }
    assert_equal({ "a" => ["10.255.0.1", ["15000-15999"], 1, "10.255.0.1/32", 16_001],
                   "b" => ["10.255.0.2", ["15000-15999"], 2, "10.255.0.2/32", 16_002],
                   "c" => ["10.255.0.3", ["15000-15999"], 3, "10.255.0.3/32", 16_003] }, rows)
    assert_equal [], sr[:levels][1][:problems]
    assert_equal [], sr[:levels][1][:findings]
    assert_equal "rfc", sr[:levels][1][:receive_policy]
  end

  # A Prefix-SID without the N flag is not a Node-SID: c's SID on a /24,
  # which gets no N (SegmentRouting.prefix_sid), gives c no sid in the view.
  def test_a_prefix_sid_without_n_is_no_node_sid
    a, = line(sids: { "c" => { prefix: "10.255.3.0/24" } }, own: { "c" => { router_id: "10.255.0.3" } })
    c = ISIS::Daemon::Views.new(a).segment_routing[:levels][1][:nodes].find { _1[:hostname] == "c" }
    refute c.key?(:sid)
    assert_equal "10.255.0.3", c[:router_id]
  end

  def test_the_views_without_segment_routing
    a, = line(sr: { "a" => nil, "b" => nil, "c" => nil })
    views = ISIS::Daemon::Views.new(a)
    assert_equal({ enabled: false }, views.segment_routing)
    assert_equal [], views.labels
    refute views.routes.any? { _1.key?(:sid) || _1[:next_hops].any? { |h| h.key?(:label) } }
  end

  # With forwarding on, the table goes to the host: a's label routes, and
  # its IP route to c's loopback pushing 18003 toward b.
  def test_forwarding_installs_the_labels
    a, = line(extra: { forwarding: true })
    adapter = @hosts[a].adapters[1]
    labels = adapter.operations.grep(ISIS::Forwarding::LabelOperation).select { _1.kind == :install }
    assert_equal [15_000, 16_002, 16_003], labels.map { _1.entry.label }.uniq.sort
    assert_equal a.label_table.installed.keys.sort, [15_000, 16_002, 16_003]
    push = adapter.operations.grep(ISIS::Forwarding::Operation).reverse.find { _1.route.prefix == "10.255.0.3/32" }
    assert_equal [18_003], push.labels.values
  end

  # Without forwarding, no label table.
  def test_no_forwarding_no_label_table
    a, = line
    assert_nil a.label_table
  end
end
