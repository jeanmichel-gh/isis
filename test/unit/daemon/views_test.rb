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

  # How a change to its own LSP is timed: the fixed hold here, the backoff
  # with lsp_generation.
  def test_overview_lsp_generation
    views, = p2p_pair
    assert_equal({ mode: "fixed", minimum: 1 }, views.overview[:lsp_generation])
    r = router({ system_id: "0000.0000.000c", lsp_generation: { maximum: 10 } }, {})
    assert_equal({ mode: "backoff", initial: 0, secondary: 1, maximum: 10 },
                 ISIS::Daemon::Views.new(r).overview[:lsp_generation])
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

  # A purge carries no TLV 137, and is still listed by the name its LSP
  # had, as FRR 8.4.4 lists one.
  def test_database_names_a_purge
    views, a, = p2p_pair
    db = a.databases[1]
    entry = db.entries.find { _1.lsp_id_s == "0000.0000.000b.00-00" }
    db.purge(entry, "test")
    row = views.database.find { _1[:lsp_id] == "0000.0000.000b.00-00" }
    assert row[:purged]
    assert_equal "b", row[:hostname]
    assert_equal "b", views.hostnames["0000.0000.000b"]
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

  # An LSP of +id+, "0000.0000.000c.00-01", stored in +router+'s Level 1
  # database as if it had arrived.
  def store_lsp(router, id, tlvs, **flags)
    lsp = ISIS::Pdu::Lsp.new(level: 1, lsp_id: id, lifetime: 1200, sequence: 1, tlvs: tlvs, **flags)
    router.databases[1].entry(ISIS::Pdu.lsp_id_octets(id)).store(lsp)
  end

  # C in two fragments, with TLV 132 in both and TLV 232 in fragment 1,
  # its pseudonode C.01, D narrow, in two fragments,
  # overloaded and attached in fragment 0 alone, F with both styles, and E
  # purged; then an SPF run. Only A and B are linked both ways, so only
  # they are reachable.
  def topology_fixture
    views, a, = p2p_pair
    store_lsp(a, "0000.0000.000c.00-00",
              [ISIS::Tlv::AreaAddresses.new("49.0001"), ISIS::Tlv::DynamicHostname.new("c"),
               ISIS::Tlv::ExtendedIsReachability.new({ neighbor: "0000.0000.000a.00", metric: 10,
                                                       subtlvs: [{ ipv4_interface_address: "10.0.12.3" },
                                                                 { ipv4_neighbor_address: "10.0.12.1" }] }),
               ISIS::Tlv::IpInterfaceAddresses.new("10.0.12.3")])
    store_lsp(a, "0000.0000.000c.00-01",
              [ISIS::Tlv::ExtendedIsReachability.new({ neighbor: "0000.0000.000c.01", metric: 20 }),
               ISIS::Tlv::ExtendedIpReachability.new({ prefix: "192.0.2.12/32", metric: 3, up_down: true }),
               ISIS::Tlv::IpInterfaceAddresses.new("10.0.13.3", "10.0.12.3"),
               ISIS::Tlv::Ipv6InterfaceAddresses.new("2001:db8::c")])
    store_lsp(a, "0000.0000.000c.01-00",
              [ISIS::Tlv::ExtendedIsReachability.new([{ neighbor: "0000.0000.000c.00", metric: 0 },
                                                      { neighbor: "0000.0000.000d.00", metric: 0 }])])
    store_lsp(a, "0000.0000.000d.00-00",
              [ISIS::Tlv::AreaAddresses.new("49.0002"),
               ISIS::Tlv::IsReachability.new({ neighbor: "0000.0000.000c.01", metric: 5 }),
               ISIS::Tlv::IpInternalReachability.new({ prefix: "10.0.13.0/24", metric: 7 }),
               ISIS::Tlv::IpExternalReachability.new({ prefix: "198.51.100.0/24", metric: 9, up_down: true })],
              overload: true, attached: [:default])
    store_lsp(a, "0000.0000.000d.00-01", []) # OL and ATT clear: only fragment 0's count
    store_lsp(a, "0000.0000.000f.00-00",
              [ISIS::Tlv::IsReachability.new({ neighbor: "0000.0000.000a.00", metric: 5 }),
               ISIS::Tlv::ExtendedIsReachability.new({ neighbor: "0000.0000.000a.00", metric: 6 }),
               ISIS::Tlv::IpInternalReachability.new({ prefix: "10.0.15.0/24", metric: 7 }),
               ISIS::Tlv::ExtendedIpReachability.new({ prefix: "10.0.15.0/24", metric: 8 })])
    db = a.databases[1]
    store_lsp(a, "0000.0000.000e.00-00", [ISIS::Tlv::ExtendedIsReachability.new({ neighbor: "0000.0000.000a.00", metric: 1 })])
    db.purge(db[ISIS::Pdu.lsp_id_octets("0000.0000.000e.00-00")], "test")
    a.decisions[1].run(["test"])
    [views, a]
  end

  def topology_node(topology, id)
    topology[:nodes].find { _1[:id] == id }
  end

# SR from the LSPs, as RFC 8667 advertises it (routescope
# docs/design/bgp-ls-sr.md): the node's SRGB, flags, SRLB and algorithms
# from TLV 242, here in fragment 1; each neighbor's Adj-SIDs and LAN
# Adj-SIDs; each prefix's Prefix-SID. A node without SR has no sr key,
# and an entry without a SID no SID key.
def test_topology_gives_sr_when_the_lsps_carry_it
  views, a = topology_fixture
  cap = ISIS::SegmentRouting.new(router_id: "10.255.0.7", srgb: [[17000, 8000]], srlb: [15000, 1000]).capability
  lan = { neighbor: "0000.0000.000b", flags: %w[V L], label: 15002 }
  store_lsp(a, "0000.0000.0007.00-00",
            [ISIS::Tlv::AreaAddresses.new("49.0001"),
             ISIS::Tlv::ExtendedIsReachability.new([{ neighbor: "0000.0000.000a.00", metric: 10,
                                                      subtlvs: [{ adj_sid: { flags: %w[V L], label: 15000 } }] },
                                                    { neighbor: "0000.0000.000c.01", metric: 10,
                                                      subtlvs: [{ lan_adj_sid: lan }] }]),
             ISIS::Tlv::ExtendedIpReachability.new([{ prefix: "10.255.0.7/32", metric: 0,
                                                      subtlvs: [{ prefix_sid: { flags: ["N"], algorithm: 0, index: 7 } }] },
                                                    { prefix: "10.0.17.0/24", metric: 10 }])])
  store_lsp(a, "0000.0000.0007.00-01", [cap])
  t = views.topology(level: 1)
  g = topology_node(t, "0000.0000.0007.00")
  assert_equal({ srgb: [{ start: 17_000, size: 8000 }], flags: ["I"], srlb: [{ start: 15_000, size: 1000 }],
                 algorithms: [0] }, g[:sr])
  assert_equal [[{ flags: %w[V L], label: 15_000 }], nil], g[:neighbors].map { _1[:adj_sids] }
  assert_equal [nil, [lan]], g[:neighbors].map { _1[:lan_adj_sids] }
  assert_equal [{ flags: ["N"], algorithm: 0, index: 7 }, nil], g[:prefixes].map { _1[:prefix_sid] }
  assert_nil topology_node(t, "0000.0000.000c.00")[:sr], "no TLV 242, no sr"
  JSON.generate(t)
end

  # Each link's attributes for flex-algo, as Spf::LinkAttributes reads
  # them, and the node's findings on them; none on a link without.
  def test_topology_gives_link_attributes_and_their_findings
    views, a, = p2p_pair
    asla = lambda do |metric|
      { asla: { applications: %w[X], subtlvs: [{ te_default_metric: { metric: metric } },
                                               { extended_admin_group: { groups: [1] } }] } }
    end
    store_lsp(a, "0000.0000.0007.00-00",
              [ISIS::Tlv::AreaAddresses.new("49.0001"),
               ISIS::Tlv::ExtendedIsReachability.new([{ neighbor: "0000.0000.000a.00", metric: 10,
                                                        subtlvs: [{ ipv4_interface_address: "10.0.17.7" }, asla.(100),
                                                                  asla.(200)] },
                                                      { neighbor: "0000.0000.000b.00", metric: 10 }]),
               ISIS::Tlv::AslaSrlg.new(neighbor: "0000.0000.000a.00", applications: %w[X],
                                       links: [{ ipv4_interface_address: "10.0.17.7" }], srlgs: [4])])
    g = topology_node(views.topology(level: 1), "0000.0000.0007.00")
    assert_equal [[[1], 100, [4]], [nil, nil, nil]], g[:neighbors].map { _1.values_at(:affinity, :te_metric, :srlg) }
    assert_equal [{ name: "asla_conflict", channel: "errors", clause: ISIS::Validation.rule(:asla_conflict).clause,
                    subject: "0000.0000.0007.00 link to 0000.0000.000a.00 via 10.0.17.7",
                    detail: "2 TeDefaultMetric values: TE Default Metric 100; TE Default Metric 200; the first is used" }],
                 g[:link_findings]
    assert_nil topology_node(views.topology(level: 1), "0000.0000.000a.00")[:link_findings]
  end

  def test_topology_lists_each_node_once_and_leaves_out_a_purge
    views, = topology_fixture
    t = views.topology(level: 1)
    assert_equal 1, t[:level]
    assert_equal %w[0000.0000.000a.00 0000.0000.000b.00 0000.0000.000c.00 0000.0000.000c.01 0000.0000.000d.00
                    0000.0000.000f.00], t[:nodes].map { _1[:id] }
    JSON.generate(t)
  end

  def test_topology_run_is_the_decisions
    views, a, = topology_fixture
    assert_equal a.decisions[1].runs, views.topology(level: "1")[:run]
    a.decisions[1].run(["again"])
    assert_equal a.decisions[1].runs, views.topology(level: 1)[:run]
  end

  # Fragment 1's neighbour and prefix join fragment 0's.
  def test_topology_merges_fragments
    views, = topology_fixture
    c = topology_node(views.topology(level: 1), "0000.0000.000c.00")
    assert_equal({ id: "0000.0000.000c.00", hostname: "c", areas: ["49.0001"], overload: false, attached: false,
                   reachable: false,
                   neighbors: [{ id: "0000.0000.000a.00", metric: 10, style: "wide",
                                 interface_address: "10.0.12.3", neighbor_address: "10.0.12.1" },
                               { id: "0000.0000.000c.01", metric: 20, style: "wide" }],
                   prefixes: [{ prefix: "192.0.2.12/32", metric: 3, up_down: true, style: "wide" }],
                   interface_addresses: ["10.0.12.3", "10.0.13.3"],
                   ipv6_interface_addresses: ["2001:db8::c"] }, c)
  end

  # TLV 132 may occur "in an LSP with any LSP number" (RFC 1195 section
  # 5.2): every fragment's, fragment 0's first, each address once. A node
  # with no TLV 132 or 232 answers empty lists.
  def test_topology_interface_addresses_from_every_fragment
    views, = topology_fixture
    t = views.topology(level: 1)
    c = topology_node(t, "0000.0000.000c.00")
    assert_equal ["10.0.12.3", "10.0.13.3"], c[:interface_addresses]
    assert_equal ["2001:db8::c"], c[:ipv6_interface_addresses]
    d = topology_node(t, "0000.0000.000d.00")
    assert_equal [[], []], d.values_at(:interface_addresses, :ipv6_interface_addresses)
  end

  def test_topology_pseudonode_is_a_node
    views, = topology_fixture
    p = topology_node(views.topology(level: 1), "0000.0000.000c.01")
    assert_equal [%w[0000.0000.000c.00 wide], %w[0000.0000.000d.00 wide]],
                 p[:neighbors].map { _1.values_at(:id, :style) }
    assert_equal [], p[:areas]
    assert_equal [], p[:prefixes]
  end

  # D has no TLV 22 and no TLV 135: TLV 2, 128 and 130, marked narrow; and
  # its fragment 0 sets OL and ATT.
  def test_topology_narrow_when_no_wide_and_flags_from_fragment_zero
    views, = topology_fixture
    d = topology_node(views.topology(level: 1), "0000.0000.000d.00")
    assert_equal [{ id: "0000.0000.000c.01", metric: 5, style: "narrow" }], d[:neighbors]
    assert_equal [{ prefix: "10.0.13.0/24", metric: 7, up_down: false, style: "narrow" },
                  { prefix: "198.51.100.0/24", metric: 9, up_down: true, style: "narrow" }], d[:prefixes]
    assert_equal [true, true, ["49.0002"]], d.values_at(:overload, :attached, :areas)
  end

  # F has both styles: only the wide ones are given.
  def test_topology_wide_over_narrow
    views, = topology_fixture
    f = topology_node(views.topology(level: 1), "0000.0000.000f.00")
    assert_equal [{ id: "0000.0000.000a.00", metric: 6, style: "wide" }], f[:neighbors]
    assert_equal [{ prefix: "10.0.15.0/24", metric: 8, up_down: false, style: "wide" }], f[:prefixes]
  end

  # A and B are on PATHS; C, its pseudonode, D and F are not, since A
  # lists none of them.
  def test_topology_reachable_is_on_paths
    views, = topology_fixture
    t = views.topology(level: 1)
    assert_equal({ "0000.0000.000a.00" => true, "0000.0000.000b.00" => true, "0000.0000.000c.00" => false,
                   "0000.0000.000c.01" => false, "0000.0000.000d.00" => false, "0000.0000.000f.00" => false },
                 t[:nodes].to_h { [_1[:id], _1[:reachable]] })
    b = topology_node(t, "0000.0000.000b.00")
    # B's own LSP, from the running pair: its address in sub-TLV 6 and A's,
    # from A's hellos, in sub-TLV 8.
    assert_equal [{ id: "0000.0000.000a.00", metric: 10, style: "wide",
                    interface_address: "10.0.12.2", neighbor_address: "10.0.12.1" }], b[:neighbors]
    assert_includes b[:prefixes], { prefix: "192.0.2.11/32", metric: 1, up_down: false, style: "wide" }
  end

  # A fragment 1 with no fragment 0 is no node, as clause 7.2.5 has it.
  def test_topology_needs_fragment_zero
    views, a, = p2p_pair
    store_lsp(a, "0000.0000.000c.00-01", [ISIS::Tlv::ExtendedIsReachability.new({ neighbor: "0000.0000.000a.00", metric: 1 })])
    assert_equal %w[0000.0000.000a.00 0000.0000.000b.00], views.topology(level: 1)[:nodes].map { _1[:id] }
  end

  def test_topology_needs_a_level
    views, = p2p_pair
    assert_raises(ArgumentError) { views.topology(level: nil) }
    assert_equal({ level: 2, run: 0, nodes: [] }, views.topology(level: 2))
  end
end
