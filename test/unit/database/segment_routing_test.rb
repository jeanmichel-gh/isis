# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"

# Segment routing as this system advertises it (RFC 8667): the settings in
# SegmentRouting, then what routers built from a configuration put in their
# LSPs, on simulated wires and a manual clock. Expected hex is our own
# arithmetic from the RFC's figures.
class TestSegmentRouting < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @routers = []
  end

  def sr(**over)
    ISIS::SegmentRouting.new(router_id: "10.255.0.1", **over)
  end

  # --- the settings

  def test_no_block_is_no_segment_routing
    assert_nil ISIS::SegmentRouting.from_config(nil, router_id: nil, prefixes: [], ipv6: false)
  end

  # RFC 7981 section 3: the Router ID "SHOULD be identical to an IP
  # Interface Address [RFC1195] advertised by the originating IS". The
  # first IPv4 /32 among the prefixes, when none is configured.
  def test_router_id_defaults_to_the_first_host_prefix
    s = ISIS::SegmentRouting.from_config({}, router_id: nil, ipv6: false,
                                             prefixes: [{ prefix: "10.0.0.0/24" }, { prefix: "10.255.0.7/32" }])
    assert_equal "10.255.0.7", s.router_id.to_s
    assert_equal [[16_000, 8_000]], s.srgb
    assert_equal [15_000, 1_000], s.srlb
    assert_raises(ArgumentError) do
      ISIS::SegmentRouting.from_config({}, router_id: nil, ipv6: false, prefixes: [{ prefix: "10.0.0.0/24" }])
    end
  end

  # RFC 8667 section 3.1: "The originating router MUST NOT advertise
  # overlapping ranges"; RFC 3032 section 6: labels 0 to 15 are special.
  def test_blocks_that_cannot_be_advertised_are_refused
    assert_raises(ArgumentError) { sr(srgb: [[16_000, 100]], srlb: [16_050, 10]) }
    assert_raises(ArgumentError) { sr(srgb: [[10, 100]]) }
    assert_raises(ArgumentError) { sr(srgb: [[16_000, 0]]) }
    assert_raises(ArgumentError) { sr(srgb: [[0xfff00, 0x200]]) }
    assert sr(srgb: [[16_000, 100], [20_000, 100]])
  end

  # f2 1e: Router ID 10.255.0.1, flags 00; SR-Capabilities with I (0x80),
  # range 8000 (001f40) from 16000 (003e80); SR-Algorithm 0; SRLB range
  # 1000 (0003e8) from 15000 (003a98). FRR's differs in the I and V flags
  # only (c0): it sets V without IPv6.
  def test_the_capability_tlv
    hex = "f21e0aff000100" "020980001f400103003e80" "13010" "0" "160900" "0003e8" "0103003a98"
    assert_equal hex, sr.capability.to_shex
    assert_equal %w[I V], sr(ipv6: true).capability.subtlvs.first.flag_letters
  end

  # Section 2.1.1.2: N only on a /32 or /128. Section 2.1.1.3: P for no
  # PHP, E only with P.
  def test_prefix_sid_flags
    sid = ->(p) { ISIS::SegmentRouting.prefix_sid(p)&.dig(:prefix_sid) }
    assert_equal({ flags: %w[N], algorithm: 0, index: 1 }, sid.({ prefix: "10.255.0.1/32", sid: 1 }))
    assert_equal %w[N P], sid.({ prefix: "10.255.0.1/32", sid: 1, no_php: true })[:flags]
    assert_equal %w[N P E], sid.({ prefix: "10.255.0.1/32", sid: 1, explicit_null: true })[:flags]
    assert_equal [], sid.({ prefix: "10.9.0.0/24", sid: 9 })[:flags]
    assert_equal %w[N], sid.({ prefix: "2001:db8::1/128", sid: 4 })[:flags]
    assert_nil sid.({ prefix: "10.9.0.0/24" })
  end

  # Section 2.1.2 and 2.1.1.3: across levels, R and P set, E cleared, the
  # rest kept.
  def test_a_propagated_sid
    h = ->(flags) { ISIS::SegmentRouting.propagated_sid({ flags: flags, algorithm: 0, index: 3 })[:prefix_sid] }
    assert_equal({ flags: %w[R N P], algorithm: 0, index: 3 }, h.(%w[N]))
    assert_equal %w[R N P], h.(%w[N P E])[:flags]
    assert_nil ISIS::SegmentRouting.propagated_sid(nil)
  end

  # Each adjacency gets the lowest free SRLB label, the same one every
  # time; with IPv6 a second, with F (section 2.2.1).
  def test_adj_labels
    s = sr
    assert_equal [{ adj_sid: { flags: %w[V L], label: 15_000 } }], s.adj_sids("ab", "b")
    assert_equal 15_001, s.adj_sids("ac", "c").first.dig(:adj_sid, :label)
    assert_equal 15_000, s.adj_sids("ab", "b").first.dig(:adj_sid, :label), "stable"
    six = sr(ipv6: true).adj_sids("ab", "b")
    assert_equal [%w[V L], %w[F V L]], six.map { _1.dig(:adj_sid, :flags) }
    assert_equal [], sr(no_adj_sid: ["ab"]).adj_sids("ab", "b")
  end

  def test_a_used_up_srlb_raises
    s = sr(srlb: [15_000, 1])
    s.adj_sids("ab", "b")
    assert_raises(ISIS::Error) { s.adj_sids("ac", "c") }
  end

  # --- routers

  def router(config, macs)
    host = SimHost.new(@wires, macs)
    r = ISIS::Router.new(config, clock: @clock, scheduler: @scheduler, log: @log, host: host)
    @routers << r
    r
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @routers.each { |r| r.step(wait: 0) }
    end
  end

  def conf(id, extra = {})
    { system_id: "0000.0000.000#{id}", hostname: id, minimum_lsp_interval: 1,
      prefixes: [{ prefix: "10.255.0.#{id.ord - 96}/32", metric: 0, sid: id.ord - 96 }] }.merge(extra)
  end

  def p2p(name, ip)
    { name: name, ip_addresses: [ip], hello_interval: 1, hello_multiplier: 3 }
  end

  def tlvs(router, level, of = router)
    lsp = router.databases[level][of.originators[level].lsp_id]&.lsp
    lsp ? lsp.tlvs.to_a : []
  end

  def find(list, klass) = list.select { _1.is_a?(klass) }

  # Two routers on a point to point link, with different SRGBs. Each LSP
  # carries TLV 242, the Prefix-SID of its loopback and an Adj-SID toward
  # the other; each router holds the other's.
  def test_a_pair_advertises_its_sr
    a = router(conf("a", segment_routing: {}, interfaces: [p2p("ab", "10.0.12.1")]), { "ab" => "00:00:00:00:00:0a" })
    b = router(conf("b", segment_routing: { srgb: [{ start: 18_000, size: 8_000 }] }, interfaces: [p2p("ab", "10.0.12.2")]),
               { "ab" => "00:00:00:00:00:0b" })
    [a, b].each(&:start)
    run_for(10)

    cap = find(tlvs(b, 1, a), ISIS::Tlv::RouterCapability).first
    assert cap, "b holds a's TLV 242"
    assert_equal "10.255.0.1", cap.router_id.to_s
    assert_equal [[18_000, 25_999]], find(tlvs(a, 1, b), ISIS::Tlv::RouterCapability).first.subtlvs.first.ranges

    reach = find(tlvs(b, 1, a), ISIS::Tlv::ExtendedIpReachability).flat_map(&:entries)
    sid = reach.find { _1.prefix == "10.255.0.1/32" }.subtlvs.first
    assert_equal({ flags: %w[N], algorithm: 0, index: 1 }, sid.to_hash)

    entry = find(tlvs(b, 1, a), ISIS::Tlv::ExtendedIsReachability).flat_map(&:entries).first
    kinds = entry.subtlvs.map(&:class)
    assert_equal [ISIS::SubTlv::Ipv4InterfaceAddress, ISIS::SubTlv::Ipv4NeighborAddress, ISIS::SubTlv::AdjSid], kinds
    assert_equal({ flags: %w[V L], label: 15_000 }, entry.subtlvs.to_a.last.to_hash)
  end

  # Without segment_routing, nothing of RFC 8667 is sent, sid: or not.
  def test_without_segment_routing_nothing_is_sent
    a = router(conf("a", interfaces: [p2p("ab", "10.0.12.1")]), { "ab" => "00:00:00:00:00:0a" })
    b = router(conf("b", interfaces: [p2p("ab", "10.0.12.2")]), { "ab" => "00:00:00:00:00:0b" })
    [a, b].each(&:start)
    run_for(10)
    own = tlvs(a, 1)
    assert_empty find(own, ISIS::Tlv::RouterCapability)
    subs = own.flat_map { |t| t.respond_to?(:entries) ? t.entries.filter_map { _1.respond_to?(:subtlvs) && _1.subtlvs }.flat_map(&:to_a) : [] }
    assert_empty subs.grep(ISIS::SubTlv::PrefixSid)
    assert_empty subs.grep(ISIS::SubTlv::AdjSid)
  end

  # adj_sid: false on an interface: no Adj-SID there, the rest as before.
  def test_adj_sid_off_per_interface
    a = router(conf("a", segment_routing: {}, interfaces: [p2p("ab", "10.0.12.1").merge(adj_sid: false)]),
               { "ab" => "00:00:00:00:00:0a" })
    b = router(conf("b", segment_routing: {}, interfaces: [p2p("ab", "10.0.12.2")]), { "ab" => "00:00:00:00:00:0b" })
    [a, b].each(&:start)
    run_for(10)
    entry = find(tlvs(a, 1), ISIS::Tlv::ExtendedIsReachability).flat_map(&:entries).first
    assert entry
    assert_empty entry.subtlvs.to_a.grep(ISIS::SubTlv::AdjSid)
  end

  # On a LAN, the entry to the pseudonode carries a LAN-Adj-SID per
  # neighbour Up (section 2.2.2), whichever system is DIS.
  def test_a_lan_gets_lan_adj_sids
    lan = ->(ip) { { name: "lan", network: "broadcast", ip_addresses: [ip], hello_interval: 1, hello_multiplier: 3 } }
    a = router(conf("a", segment_routing: {}, interfaces: [lan.("10.0.0.1")]), { "lan" => "00:00:00:00:00:0a" })
    b = router(conf("b", segment_routing: {}, interfaces: [lan.("10.0.0.2")]), { "lan" => "00:00:00:00:00:0b" })
    [a, b].each(&:start)
    run_for(30)
    [[a, "0000.0000.000b"], [b, "0000.0000.000a"]].each do |r, other|
      entry = find(tlvs(r, 1), ISIS::Tlv::ExtendedIsReachability).flat_map(&:entries).first
      assert entry, "#{r.config[:hostname]} lists the pseudonode"
      lan_sids = entry.subtlvs.to_a.grep(ISIS::SubTlv::LanAdjSid)
      assert_equal [[other, 15_000]], lan_sids.map { [ISIS::SystemId.from_bytes(_1.neighbor).to_s, _1.label] }
    end
  end

  # f, at both levels, puts its Level 1 neighbour e's loopback in its
  # Level 2 LSP with the Prefix-SID it came with, R and P set (sections
  # 2.1.1.2, 2.1.1.3, 2.1.2). Its own loopback's stays as configured.
  def test_a_sid_crosses_into_level_2
    e = router(conf("e", segment_routing: {}, interfaces: [p2p("xm", "10.0.1.1")]), { "xm" => "00:00:00:00:00:01" })
    f = router(conf("f", segment_routing: {}, level: "1-2", interfaces: [p2p("xm", "10.0.1.2")]),
               { "xm" => "00:00:00:00:00:02" })
    [e, f].each(&:start)
    run_for(20)
    reach = find(tlvs(f, 2), ISIS::Tlv::ExtendedIpReachability).flat_map(&:entries)
    xs = reach.find { _1.prefix == "10.255.0.5/32" }
    assert xs, "f announces e's loopback at Level 2"
    assert_equal({ flags: %w[R N P], algorithm: 0, index: 5 }, xs.subtlvs.first.to_hash)
    own = reach.find { _1.prefix == "10.255.0.6/32" }
    assert_equal({ flags: %w[N], algorithm: 0, index: 6 }, own.subtlvs.first.to_hash)
    assert_empty find(tlvs(f, 2), ISIS::Tlv::RouterCapability).first.subtlvs.to_a.grep(ISIS::SubTlv::PrefixSid)
  end

  # The other way: d, at Level 2 only, behind c at both levels, which leaks
  # 10.0.0.0/8 into Level 1. c puts d's loopback in its Level 1 LSP with the
  # up/down bit and d's Prefix-SID, R and P set (RFC 5302 section 2; RFC
  # 8667 section 2.1.2).
  def test_a_sid_leaks_into_level_1
    c = router(conf("c", segment_routing: {}, level: "1-2", leak: ["10.0.0.0/8"], interfaces: [p2p("cd", "10.0.34.1")]),
               { "cd" => "00:00:00:00:00:03" })
    d = router(conf("d", segment_routing: {}, level: 2, interfaces: [p2p("cd", "10.0.34.2")]), { "cd" => "00:00:00:00:00:04" })
    [c, d].each(&:start)
    run_for(20)
    ds = find(tlvs(c, 1), ISIS::Tlv::ExtendedIpReachability).flat_map(&:entries).find { _1.prefix == "10.255.0.4/32" }
    assert ds, "c leaks d's loopback into Level 1"
    assert ds.up_down
    assert_equal({ flags: %w[R N P], algorithm: 0, index: 4 }, ds.subtlvs.first.to_hash)
  end
end
