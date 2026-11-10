# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/sim_host"

# A Router from one configuration, on simulated wires and a manual clock.
# What is asserted is what the configuration should build, and that the
# routers it builds route: the mechanisms themselves have their own tests.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestRouter < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @routers = []
  end

  def router(config, macs)
    host = SimHost.new(@wires, macs)
    r = ISIS::Router.new(config, clock: @clock, scheduler: @scheduler, log: @log, host: host)
    @routers << [r, host]
    r
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @routers.each { |r, _| r.step(wait: 0) }
    end
  end

  def pair(a = {}, b = {})
    a = router({ system_id: "0000.0000.000a", hostname: "a", minimum_lsp_interval: 1,
                 interfaces: [{ name: "ab", ip_addresses: ["10.0.12.1"], hello_interval: 1, hello_multiplier: 3 }],
                 prefixes: [{ prefix: "192.0.2.10/32", metric: 1 }] }.merge(a), { "ab" => "00:00:00:00:00:0a" })
    b = router({ system_id: "0000.0000.000b", hostname: "b", minimum_lsp_interval: 1,
                 interfaces: [{ name: "ab", ip_addresses: ["10.0.12.2"], hello_interval: 1, hello_multiplier: 3 }],
                 prefixes: [{ prefix: "192.0.2.11/32", metric: 1 }] }.merge(b), { "ab" => "00:00:00:00:00:0b" })
    [a, b]
  end

  def test_point_to_point_pair_routes
    a, b = pair
    [a, b].each(&:start)
    run_for(10)
    assert_equal "up", a.interfaces.first.circuits[1].three_way_state.to_s
    route = a.decisions[1].routes.values.find { |r| r.prefix.to_s == "192.0.2.11/32" }
    assert route, "A has no route to B's prefix"
    assert_equal 11, route.metric
    refute_nil b.decisions[1].routes.values.find { |r| r.prefix.to_s == "192.0.2.10/32" }
  end

  # The hostname goes in the LSP (TLV 137), and the interfaces' addresses
  # in TLV 132 when the configuration gives none of its own.
  def test_lsp_carries_the_hostname_and_the_interface_addresses
    a, = pair
    a.start
    tlvs = a.databases[1][a.originators[1].lsp_id].lsp.tlvs.to_a
    assert_equal ["a"], tlvs.grep(ISIS::Tlv::DynamicHostname).map(&:to_hash)
    assert_equal "84040a000c01", tlvs.grep(ISIS::Tlv::IpInterfaceAddresses).map(&:to_shex).join
  end

  def test_configured_ip_addresses_win
    a, = pair(ip_addresses: ["192.0.2.10"])
    a.start
    tlvs = a.databases[1][a.originators[1].lsp_id].lsp.tlvs.to_a
    assert_equal "8404c000020a", tlvs.grep(ISIS::Tlv::IpInterfaceAddresses).map(&:to_shex).join
  end

  # JSON and YAML give string keys.
  def test_string_keys
    r = router({ "system_id" => "0000.0000.000c", "level" => "1-2",
                 "interfaces" => [{ "name" => "lan", "network" => "broadcast" }] }, { "lan" => "00:00:00:00:00:0c" })
    assert_equal [1, 2], r.levels
    assert r.interfaces.first.broadcast?
  end

  # A broadcast interface at both levels has a LAN circuit per level, named
  # for its level, with circuit type 3; a point to point one has one
  # circuit for both.
  def test_both_levels
    r = router({ system_id: "0000.0000.000c", level: "1-2",
                 interfaces: [{ name: "lan", network: "broadcast" }, { name: "p2p" }] },
               { "lan" => "00:00:00:00:00:0c", "p2p" => "00:00:00:00:00:1c" })
    lan, p2p = r.interfaces
    assert_equal %w[lan-l1 lan-l2], lan.circuits.values.map(&:name)
    assert_equal [1, 2], lan.circuits.values.map(&:level)
    assert_equal %i[l1l2 l1l2], lan.circuits.values.map(&:circuit_type)
    assert_equal 1, p2p.circuits.values.uniq.size
    assert_equal [1, 2], p2p.circuits[1].levels.keys
    assert_equal 3, r.originators[1].is_type
    assert r.leak
    assert r.summary
  end

  def test_one_level_has_no_leak_or_summary
    a, = pair
    assert_nil a.leak
    assert_nil a.summary
  end

  # Each point to point circuit has its own circuit ID, from 1.
  def test_circuit_ids
    r = router({ system_id: "0000.0000.000c", interfaces: [{ name: "x" }, { name: "y" }] },
               { "x" => "00:00:00:00:00:0c", "y" => "00:00:00:00:00:1c" })
    assert_equal [1, 2], r.interfaces.map { |i| i.circuits[1].local_circuit_id }
  end

  # With forwarding, an adapter per level, flushed when built; at both
  # levels a LAN circuit's name maps to its interface.
  def test_forwarding
    r = router({ system_id: "0000.0000.000c", level: "1-2", forwarding: true,
                 interfaces: [{ name: "lan", network: "broadcast" }] }, { "lan" => "00:00:00:00:00:0c" })
    host = @routers.last.last
    assert_equal [1, 2], r.adapters.keys
    assert_equal [1, 1], host.adapters.values.map(&:flushes)
    assert_equal({ "lan-l1" => "lan", "lan-l2" => "lan" }, host.adapters[1].interfaces)
  end

  def test_forwarding_installs_routes
    a, b = pair({ forwarding: true })
    [a, b].each(&:start)
    run_for(10)
    host = @routers.first.last
    assert(host.adapters[1].operations.any? { |o| o.route.prefix.to_s == "192.0.2.11/32" })
  end

  def test_ipv6_link_local_in_hellos
    r = router({ system_id: "0000.0000.000c", ipv6: true, interfaces: [{ name: "x" }] }, { "x" => "00:00:00:00:00:0c" })
    assert_equal %i[ipv4 ipv6], r.originators[1].protocols
    peer = ISIS::Link::SimulatedTransport.new(@wires["x"])
    r.start
    _llc, octets = Datalink::LLC.parse(peer.receive.sdu)
    hello = ISIS::Pdu.factory(ISIS::Octets.new(octets))
    assert_equal ["fe80::c"], hello.tlvs.to_a.grep(ISIS::Tlv::Ipv6InterfaceAddresses).flat_map { _1.to_hash }
  end

  def test_leak_policy_changes
    r = router({ system_id: "0000.0000.000c", level: "1-2", leak: ["10.0.0.0/8"], interfaces: [] }, {})
    refute_same ISIS::Spf::Leak::NONE, r.leak.policy
    r.leak_prefixes = []
    assert_same ISIS::Spf::Leak::NONE, r.leak.policy
  end

  # Redistribution per level, reading the host's route source.
  def test_redistribution_per_level
    r = router({ system_id: "0000.0000.000c", level: "1-2", redistribute: { kinds: ["static"], interval: 2 },
                 interfaces: [] }, {})
    assert_equal [[:static], [:static]], r.redistributions.map(&:kinds)
    assert_equal [2, 2], r.redistributions.map(&:interval)
    r.redistribute = ["connected"]
    assert_equal [[:connected], [:connected]], r.redistributions.map(&:kinds)
  end

  def test_refusals
    assert_raises(ArgumentError) { router({ interfaces: [] }, {}) }
    assert_raises(ArgumentError) { router({ system_id: "0000.0000.000c", level: 3 }, {}) }
    assert_raises(ArgumentError) do
      router({ system_id: "0000.0000.000c", interfaces: [{ name: "x", network: "nbma" }] }, { "x" => "00:00:00:00:00:0c" })
    end
  end

  # A line of three, a - b - c, where b - c comes up before a starts, as
  # in a lab whose systems start in any order. b has to pass a's LSP on to
  # c (RFC 1142 7.3.15.1 e 1 ii). isis4r sends no periodic CSNP on a point
  # to point circuit, so nothing else would bring it to c.
  def test_a_system_in_the_middle_passes_lsps_on
    conf = lambda do |id, name, ifaces|
      { system_id: "0000.0000.000#{id}", hostname: name, minimum_lsp_interval: 1,
        interfaces: ifaces.map { |i, ip| { name: i, ip_addresses: [ip], hello_interval: 1, hello_multiplier: 3 } } }
    end
    a = router(conf.("a", "a", [["ab", "10.0.12.1"]]), { "ab" => "00:00:00:00:00:0a" })
    b = router(conf.("b", "b", [["ab", "10.0.12.2"], ["bc", "10.0.23.2"]]),
               { "ab" => "00:00:00:00:00:1b", "bc" => "00:00:00:00:00:2b" })
    c = router(conf.("c", "c", [["bc", "10.0.23.3"]]), { "bc" => "00:00:00:00:00:0c" })
    [b, c].each(&:start)
    run_for(10)
    assert_equal "up", c.interfaces.first.circuits[1].three_way_state.to_s, "b - c is up before a starts"
    a.start
    run_for(10)
    a_lsp = a.originators[1].lsp_id
    assert b.databases[1][a_lsp], "b has a's LSP"
    held = c.databases[1][a_lsp]
    assert held && !held.placeholder?, "c has a's LSP, through b"
    assert_equal a.databases[1][a_lsp].sequence, held.sequence
  end

  def test_stop_stops_the_circuits
    a, b = pair
    [a, b].each(&:start)
    run_for(5)
    a.stop
    run_for(5)
    refute_equal "up", b.interfaces.first.circuits[1].three_way_state.to_s
  end
end
