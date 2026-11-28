# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/sim_host"

# SRv6 origination between routers on a simulated wire
# (docs/design/srv6.md, step 2): each sends SRv6 Capabilities in TLV 242,
# its locator in TLV 27 with its End and End.DT6 SIDs and in TLV 236, and
# an End.X SID per adjacency in TLV 22, or LAN End.X SIDs to the DIS.
class TestRouterSrv6 < Minitest::Test
  STRUCTURE = { block: 32, node: 16, function: 16, argument: 0 }.freeze

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

  def srv6(n) = { locators: [{ name: "main", prefix: "fc00:0:#{n}::/48", structure: STRUCTURE }] }

  def conf(n, interfaces, **more)
    { system_id: "0000.0000.000#{n}", hostname: "r#{n}", minimum_lsp_interval: 1, ipv6: true,
      router_id: "10.255.0.#{n}", interfaces: interfaces, srv6: srv6(n) }.merge(more)
  end

  def p2p(n, **iface) = [{ name: "ab", hello_interval: 1, hello_multiplier: 3 }.merge(iface)]

  def pair(a_more = {}, b_more = {}, a_iface: {})
    a = router(conf(1, p2p(1, **a_iface), **a_more), { "ab" => "00:00:00:00:00:0a" })
    b = router(conf(2, p2p(2), **b_more), { "ab" => "00:00:00:00:00:0b" })
    @routers.each(&:start)
    run_for(15)
    [a, b]
  end

  # +r+'s own Level 1 LSP as +by+'s database holds it.
  def held(r, by) = by.databases[1][r.originators[1].lsp_id].lsp

  def grep(lsp, klass) = lsp.tlvs.to_a.grep(klass)

  def test_a_point_to_point_pair
    a, b = pair
    lsp = held(a, b)
    cap = grep(lsp, ISIS::Tlv::RouterCapability).first
    assert_equal "10.255.0.1", cap.router_id.to_s
    assert_equal [ISIS::SubTlv::Srv6Capabilities, ISIS::SubTlv::SrAlgorithm], cap.subtlvs.map(&:class)
    assert_equal [0], cap.subtlvs.to_a.last.algorithms
    refute cap.subtlvs.first.o?

    loc = grep(lsp, ISIS::Tlv::Srv6Locator).first.entries.first
    assert_equal ["fc00:0:1::/48", 0, 0, []], [loc.locator, loc.metric, loc.algorithm, loc.flag_letters]
    sids = loc.subtlvs_of(ISIS::SubTlv::Srv6EndSid)
    assert_equal [["fc00:0:1::", "End"], ["fc00:0:1:1::", "End.DT6"]], sids.map { [_1.sid, _1.behavior_name] }
    assert_equal [[32, 16, 16, 0]] * 2, sids.map { _1.structure.to_hash.values }
    assert_equal [[]], loc.subtlvs_of(ISIS::SubTlv::PrefixAttributeFlags).map(&:flag_letters)

    reach = grep(lsp, ISIS::Tlv::Ipv6Reachability).flat_map(&:entries).find { _1.prefix == "fc00:0:1::/48" }
    assert_equal 0, reach.metric

    x = grep(lsp, ISIS::Tlv::ExtendedIsReachability).flat_map(&:entries).flat_map { _1.subtlvs.to_a }
                                                                       .grep(ISIS::SubTlv::Srv6EndXSid)
    assert_equal [["fc00:0:1:2::", 5, 0, 0, []]], x.map { [_1.sid, _1.behavior, _1.algorithm, _1.weight, _1.flag_letters] }
    assert_equal [32, 16, 16, 0], x.first.structure.to_hash.values
    assert_equal "fc00:0:2:2::", grep(held(b, a), ISIS::Tlv::ExtendedIsReachability).first.entries.first.subtlvs.to_a.last.sid
  end

  # Without srv6 nothing of it is sent: no TLV 27, no SRv6 Capabilities,
  # no TLV 242 at all without segment routing.
  def test_off_sends_nothing
    a, b = pair({ srv6: nil }, { srv6: nil })
    lsp = held(a, b)
    assert_empty grep(lsp, ISIS::Tlv::Srv6Locator)
    assert_empty grep(lsp, ISIS::Tlv::RouterCapability)
    refute_includes grep(lsp, ISIS::Tlv::Ipv6Reachability).flat_map(&:entries).map(&:prefix), "fc00:0:1::/48"
  end

  # With SR-MPLS too: one TLV 242 with the SR sub-TLVs and SRv6
  # Capabilities, and each adjacency with its Adj-SIDs and its End.X SID.
  def test_with_segment_routing
    a, b = pair({ segment_routing: {}, prefixes: [{ prefix: "10.255.0.1/32", metric: 0, sid: 1 }] })
    lsp = held(a, b)
    cap = grep(lsp, ISIS::Tlv::RouterCapability)
    assert_equal 1, cap.size
    assert_equal [ISIS::SubTlv::SrCapabilities, ISIS::SubTlv::SrAlgorithm, ISIS::SubTlv::SrLocalBlock,
                  ISIS::SubTlv::Srv6Capabilities], cap.first.subtlvs.map(&:class)
    subs = grep(lsp, ISIS::Tlv::ExtendedIsReachability).first.entries.first.subtlvs.map(&:class)
    assert_equal [ISIS::SubTlv::AdjSid, ISIS::SubTlv::AdjSid, ISIS::SubTlv::Srv6EndXSid], subs
  end

  def test_end_x_false
    a, b = pair({}, {}, a_iface: { end_x: false })
    subs = grep(held(a, b), ISIS::Tlv::ExtendedIsReachability).first.entries.first.subtlvs.to_a
    assert_empty subs.grep(ISIS::SubTlv::Srv6EndXSid)
    refute_empty grep(held(a, b), ISIS::Tlv::Srv6Locator)
  end

  # On a LAN, each system's entry to the DIS carries a LAN End.X SID per
  # neighbour Up on the LAN (RFC 9352 section 8.2).
  def test_a_lan
    rs = (1..3).map do |n|
      router(conf(n, [{ name: "lan", network: "broadcast", hello_interval: 1, hello_multiplier: 3 }]),
             { "lan" => "00:00:00:00:00:0#{n}" })
    end
    @routers.each(&:start)
    run_for(25)
    lsp = held(rs[0], rs[1])
    entry = grep(lsp, ISIS::Tlv::ExtendedIsReachability).first.entries.first
    refute entry.neighbor.getbyte(-1).zero?, "the entry is to the pseudonode"
    lan = entry.subtlvs.to_a.grep(ISIS::SubTlv::Srv6LanEndXSid)
    assert_equal %w[0000.0000.0002 0000.0000.0003], lan.map { _1.neighbor_id.to_s }.sort
    assert_equal %w[fc00:0:1:2:: fc00:0:1:3::], lan.map(&:sid).sort
    assert(lan.all? { _1.behavior == 5 })
  end

  # A router at both levels sends its locator in each level's LSP, with
  # the same SIDs, since one Srv6::Local serves both.
  def test_both_levels
    a, b = pair({ level: "1-2" }, { level: "1-2" })
    l1 = held(a, b)
    l2 = b.databases[2][a.originators[2].lsp_id].lsp
    [l1, l2].each { refute_empty grep(_1, ISIS::Tlv::Srv6Locator) }
    sid = ->(lsp) { grep(lsp, ISIS::Tlv::ExtendedIsReachability).first.entries.first.subtlvs.to_a.last.sid }
    assert_equal sid[l1], sid[l2]
  end

  # Step 3: each routes to the other's locator, from TLV 236 marked by
  # TLV 27, through the neighbour's link-local address; and the SRv6
  # table holds the other's locator and SIDs, and this system's own SIDs
  # with the End.X on its adjacency.
  def test_each_routes_to_the_others_locator
    a, b = pair
    r = a.decisions[1].routes["fc00:0:2::/48"]
    assert_equal [10, "fc00:0:2::/48", nil], [r.metric, r.locator&.prefix, r.locator_only]
    assert_equal ["ab"], r.adjacencies.map(&:circuit)
    t = a.decisions[1].srv6_table
    other = t.node((ISIS::Pdu.dotted_octets("0000.0000.0002") + "\x00".b).b)
    assert_equal [%w[fc00:0:2:: End], %w[fc00:0:2:1:: End.DT6], %w[fc00:0:2:2:: End.X]],
                 other.sids.map { [_1.sid, ISIS::Spf::Srv6.behavior_text(_1.behavior)] }
    assert_equal [[:end, "fc00:0:1::"], [:decap, "fc00:0:1:1::"], [:end_x, "fc00:0:1:2::"]], t.own.map { [_1.kind, _1.sid] }
    assert_equal "ab", t.own.last.adjacency.circuit
    assert_empty t.findings
    assert b.decisions[1].routes["fc00:0:1::/48"].locator
  end

  # What isisd's API shows of it (docs/isisd.md): show.srv6, the
  # locator route in show.routes, show.overview and show.topology.
  def test_the_views
    a, = pair
    v = ISIS::Daemon::Views.new(a)
    s = v.srv6
    assert_equal [true, "sr0", true, "rfc"], s.values_at(:enabled, :interface, :decap, :receive_policy)
    assert_equal [{ name: "main", prefix: "fc00:0:1::/48", algorithm: 0, structure: STRUCTURE }], s[:locators]
    assert_equal [{ sid: "fc00:0:1::", behavior: "End", kind: "end", locator: "main" },
                  { sid: "fc00:0:1:1::", behavior: "End.DT6", kind: "decap", locator: "main" },
                  { sid: "fc00:0:1:2::", behavior: "End.X", kind: "end_x", locator: "main", interface: "ab", neighbor: "r2" }],
                 s[:sids]
    nodes = s[:levels][1][:nodes]
    assert_equal %w[0000.0000.0001 0000.0000.0002], nodes.map { _1[:system_id] }.sort
    r2 = nodes.find { _1[:hostname] == "r2" }
    assert_equal [{ o: false }, [0], false], r2.values_at(:capabilities, :algorithms, :ignored)
    assert_equal %w[fc00:0:2:: fc00:0:2:1::], r2[:locators].first[:end_sids].map { _1[:sid] }
    assert_equal ["fc00:0:2:2::"], r2[:end_x_sids].map { _1[:sid] }
    assert_empty s[:levels][1][:findings]

    route = v.routes(level: 1).find { _1[:prefix] == "fc00:0:2::/48" }
    assert_equal [true, 0], route.values_at(:locator, :algorithm)
    refute v.routes(level: 1).find { _1[:prefix] == "10.255.0.2/32" }&.key?(:locator)
    assert v.overview[:srv6]

    node = v.topology(level: 1)[:nodes].find { _1[:hostname] == "r2" }
    assert_equal [{ locator: "fc00:0:2::/48", algorithm: 0, metric: 0, up_down: false, flags: [] }], node[:locators]
    assert_equal [{ sid: "fc00:0:2::", behavior: "End", structure: STRUCTURE, locator: "fc00:0:2::/48" },
                  { sid: "fc00:0:2:1::", behavior: "End.DT6", structure: STRUCTURE, locator: "fc00:0:2::/48" }],
                 node[:end_sids]
    assert_equal [{ sid: "fc00:0:2:2::", behavior: "End.X", structure: STRUCTURE, algorithm: 0, weight: 0, flags: [] }],
                 node[:neighbors].first[:end_x_sids]
  end

  def test_the_views_without_srv6
    a, = pair({ srv6: nil }, { srv6: nil })
    v = ISIS::Daemon::Views.new(a)
    assert_equal({ enabled: false }, v.srv6)
    refute v.overview.key?(:srv6)
  end

  # A line of three, a at Level 1, b at both levels, c at Level 2 in
  # another area, b leaking +leak+.
  def across(leak: [])
    a = router(conf(1, [{ name: "ab", hello_interval: 1, hello_multiplier: 3 }]),
               { "ab" => "00:00:00:00:00:0a" })
    b = router(conf(2, [{ name: "ab", hello_interval: 1, hello_multiplier: 3 },
                        { name: "bc", hello_interval: 1, hello_multiplier: 3 }], level: "1-2", leak: leak),
               { "ab" => "00:00:00:00:00:0b", "bc" => "00:00:00:00:00:0c" })
    c = router(conf(3, [{ name: "bc", hello_interval: 1, hello_multiplier: 3 }], level: 2, areas: ["49.0002"]),
               { "bc" => "00:00:00:00:00:0d" })
    @routers.each(&:start)
    run_for(20)
    [a, b, c]
  end

  # a's locator goes into Level 2 at b, in TLV 27 with R and its End SIDs
  # (RFC 9352 section 7.1), so c routes to it. c's goes into Level 1 only
  # as b's leak policy allows, none by default.
  def test_a_locator_announced_up
    a, b, c = across
    assert_equal 20, c.decisions[2].routes["fc00:0:1::/48"].metric
    entry = grep(c.databases[2][b.originators[2].lsp_id].lsp, ISIS::Tlv::Srv6Locator).flat_map(&:entries)
                                                                                       .find { _1.locator == "fc00:0:1::/48" }
    assert_equal [[], %w[R]], [entry.flag_letters, entry.subtlvs_of(ISIS::SubTlv::PrefixAttributeFlags).first.flag_letters]
    assert_equal %w[fc00:0:1:: fc00:0:1:1::], entry.subtlvs_of(ISIS::SubTlv::Srv6EndSid).map(&:sid)
    assert_nil a.decisions[1].routes["fc00:0:3::/48"], "nothing leaked by default"
  end

  # Leaked into Level 1: D and R.
  def test_a_locator_leaked_down
    a, = across(leak: ["fc00::/16"])
    r = a.decisions[1].routes["fc00:0:3::/48"]
    assert_equal [20, true], [r.metric, r.up_down]
    assert_equal [%w[D], %w[R]], [r.locator.entry.flag_letters, r.locator.flags]
  end

  def test_refused_without_ipv6
    e = assert_raises(ArgumentError) { router(conf(1, p2p(1), ipv6: false), { "ab" => "00:00:00:00:00:0a" }) }
    assert_match(/srv6 needs ipv6: true/, e.message)
  end

  # A locator leaked from Level 2 into Level 1 goes in TLV 27 after the
  # system's own, with D and R (RFC 9352 section 7.1); one taken from
  # Level 1 into Level 2 with R alone. Spf::Leak and Spf::Summary hand
  # them over once the calculation reads locators (the design's step 3).
  def test_leaked_and_area_locators
    a, b = pair({ level: "1-2" }, { level: "1-2" })
    far = ISIS::Tlv::Srv6Locator::Entry.new(locator: "fc00:0:9::/48", metric: 7,
                                            subtlvs: [{ end_sid: { behavior: "End", sid: "fc00:0:9::" } }])
    a.originators[1].leaked_locators = [ISIS::Srv6::Local.propagated(far, down: true, metric: 30)]
    a.originators[2].area_locators = [ISIS::Srv6::Local.propagated(far, down: false, metric: 20)]
    run_for(5)
    entries = ->(lsp) { grep(lsp, ISIS::Tlv::Srv6Locator).flat_map(&:entries) }
    l1 = entries[held(a, b)]
    l2 = entries[b.databases[2][a.originators[2].lsp_id].lsp]
    assert_equal ["fc00:0:1::/48", "fc00:0:9::/48"], l1.map(&:locator)
    leaked = l1.last
    assert_equal [30, %w[D], %w[R]], [leaked.metric, leaked.flag_letters,
                                       leaked.subtlvs_of(ISIS::SubTlv::PrefixAttributeFlags).first.flag_letters]
    up = l2.last
    assert_equal [20, [], %w[R]], [up.metric, up.flag_letters, up.subtlvs_of(ISIS::SubTlv::PrefixAttributeFlags).first.flag_letters]
    assert_equal ["fc00:0:9::"], up.subtlvs_of(ISIS::SubTlv::Srv6EndSid).map(&:sid)
  end
end
