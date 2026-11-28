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
