# frozen_string_literal: true

require_relative "../../test_helper"

# The Decision Process over circuits on a simulated wire, on one manual
# clock. Each system has a database, an originator and a decision, and
# advertises one /32 at metric 1; circuits are at metric 10. The expected
# metrics are our own arithmetic.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestDecisionP2p < Minitest::Test
  IDS = { a: "0000.0000.000a", b: "0000.0000.000b" }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    TestLogs.heading(name)
    @nodes = { a: node(:a, "10.0.12.1", "192.0.2.1/32"), b: node(:b, "10.0.12.2", "192.0.2.2/32") }
  end

  def node(who, address, prefix)
    log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    db = ISIS::Database.new(level: 1, clock: @clock, scheduler: @scheduler, log: log)
    orig = ISIS::Originator.new(system_id: IDS[who], database: db, scheduler: @scheduler, log: log,
                                minimum_interval: 1, prefixes: [{ prefix: prefix, metric: 1 }])
    circuit = ISIS::P2pCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler,
                                   log: log, name: "#{who}-eth1", system_id: IDS[who],
                                   snpa: "00:00:00:00:00:0#{who}", ip_addresses: [address], database: db,
                                   originator: orig, hello_interval: 1, hello_multiplier: 3)
    decision = ISIS::Spf::Decision.new(system_id: IDS[who], database: db, scheduler: @scheduler, log: log)
    circuit.levels.each_value { |l| decision.attach(l) }
    { log: log, db: db, orig: orig, circuit: circuit, decision: decision }
  end

  def start(*who)
    who.each { |w| %i[orig circuit decision].each { |k| @nodes[w][k].start } }
  end

  def run_for(seconds, step: 0.25, only: @nodes.keys)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      only.each { |w| @nodes[w][:circuit].poll }
    end
  end

  def routes(who)
    @nodes[who][:decision].routes.transform_values(&:to_s)
  end

  # Each learns the other's /32: 10 to the neighbour, 1 for the prefix,
  # through the address the neighbour's hellos carry; and its own is local.
  def test_each_learns_the_others_prefix
    start(:a, :b)
    run_for(10)
    assert_equal({ "192.0.2.1/32" => "192.0.2.1/32 metric 1 local",
                   "192.0.2.2/32" => "192.0.2.2/32 metric 11 via 10.0.12.2 via a-eth1" }, routes(:a))
    assert_equal "192.0.2.1/32 metric 11 via 10.0.12.1 via b-eth1", routes(:b)["192.0.2.1/32"]
  end

  # The route goes when the adjacency does, without waiting for the
  # originator's LSP, which is held back here: B stops reading, its
  # holding timer, 3 s, expires, and its next hello takes A out of Up.
  def test_the_route_goes_with_the_adjacency
    start(:a, :b)
    run_for(10)
    @nodes[:a][:orig].define_singleton_method(:changed) { |_reason| nil }
    run_for(4, only: [:a])
    assert_nil routes(:a)["192.0.2.2/32"]
    removed = @nodes[:a][:log].events.select { |e| e.kind == :route && e.data[:change] == :removed }
    assert_equal ["192.0.2.2/32"], removed.map { |e| e.data[:prefix] }
  end

  # Each change goes to the forwarding adapter as a route operation: an
  # install when B's prefix appears, a withdrawal when the adjacency goes.
  # A's own prefix is local and is never an operation.
  def test_changes_go_to_the_forwarding_adapter
    recorder = ISIS::Forwarding::Recorder.new
    @nodes[:a][:decision].forwarding = recorder
    start(:a, :b)
    run_for(10)
    assert_equal ["install 192.0.2.2/32 metric 11 via 10.0.12.2 via a-eth1"], recorder.operations.map(&:to_s)
    assert_equal [1], recorder.operations.map(&:level)
    @nodes[:a][:orig].define_singleton_method(:changed) { |_reason| nil }
    run_for(4, only: [:a])
    assert_equal ["withdraw 192.0.2.2/32"], recorder.operations.drop(1).map(&:to_s)
  end

  # A route added is logged at info, as an event a test can read.
  def test_a_new_route_is_an_event
    start(:a, :b)
    run_for(10)
    added = @nodes[:a][:log].events.select { |e| e.kind == :route && e.data[:change] == :added }
    assert_includes added.map { |e| e.data[:prefix] }, "192.0.2.2/32"
  end

  # A run that finds the routes as they were reports nothing.
  def test_an_unchanged_route_is_not_reported
    start(:a, :b)
    run_for(10)
    log = @nodes[:a][:log]
    before = log.events.count { |e| e.kind == :route }
    @nodes[:a][:decision].run
    assert_equal before, log.events.count { |e| e.kind == :route }
  end

  # The circuit tells the decision of each adjacency change, Up and Down.
  def test_the_circuit_reports_adjacency_changes
    heard = []
    recorder = Object.new
    recorder.define_singleton_method(:changed) { |reason| heard << reason }
    @nodes[:a][:circuit].levels[1].decision = recorder
    start(:a, :b)
    run_for(5)
    @nodes[:b][:circuit].stop
    run_for(5, only: [:a])
    assert_equal ["adjacency with 0000.0000.000b on a-eth1 up", "adjacency on a-eth1 down"], heard
  end

  # Changes in one callback share one run.
  def test_changes_at_one_time_share_a_run
    decision = @nodes[:a][:decision]
    decision.start
    @scheduler.advance(0)
    runs = decision.runs
    3.times { |i| decision.changed("change #{i}") }
    @scheduler.advance(0)
    assert_equal runs + 1, decision.runs
  end

  # Before start, nothing runs.
  def test_nothing_runs_before_start
    decision = @nodes[:a][:decision]
    decision.changed("change")
    @scheduler.advance(1)
    assert_equal 0, decision.runs
  end
end

# Three systems on a LAN. C has the highest LAN address, so it is the DIS
# (RFC 1142 8.4.4) and generates the pseudonode, 0000.0000.000c.01.
class TestDecisionLan < Minitest::Test
  IDS = { a: "0000.0000.000a", b: "0000.0000.000b", c: "0000.0000.000c" }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    TestLogs.heading(name)
    @nodes = IDS.keys.each_with_index.to_h { |w, i| [w, node(w, "10.0.1.#{i + 1}", "192.0.2.#{i + 1}/32")] }
  end

  def node(who, address, prefix)
    log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    db = ISIS::Database.new(level: 1, clock: @clock, scheduler: @scheduler, log: log)
    orig = ISIS::Originator.new(system_id: IDS[who], database: db, scheduler: @scheduler, log: log,
                                minimum_interval: 1, prefixes: [{ prefix: prefix, metric: 1 }])
    circuit = ISIS::LanCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler,
                                   log: log, name: "#{who}-eth0", system_id: IDS[who],
                                   snpa: "00:00:00:00:00:0#{who}", ip_addresses: [address], database: db,
                                   originator: orig)
    decision = ISIS::Spf::Decision.new(system_id: IDS[who], database: db, scheduler: @scheduler, log: log)
    decision.attach(circuit)
    { log: log, circuit: circuit, decision: decision, orig: orig }
  end

  def run_for(seconds, step: 0.25)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @nodes.each_value { |n| n[:circuit].poll }
    end
  end

  # Through the pseudonode: 10 from A to it, 0 to each system (7.2.3), 1
  # for the prefix, through the system's own address on the LAN.
  def test_routes_across_the_lan
    @nodes.each_value { |n| %i[orig circuit decision].each { |k| n[k].start } }
    run_for(40)
    routes = @nodes[:a][:decision].routes.transform_values(&:to_s)
    assert_equal "192.0.2.2/32 metric 11 via 10.0.1.2 via a-eth0", routes["192.0.2.2/32"]
    assert_equal "192.0.2.3/32 metric 11 via 10.0.1.3 via a-eth0", routes["192.0.2.3/32"]
  end

  # The circuit tells the decision of each adjacency change and each change
  # of DIS.
  def test_the_circuit_reports_adjacency_and_dis_changes
    heard = []
    recorder = Object.new
    recorder.define_singleton_method(:changed) { |reason| heard << reason }
    @nodes[:a][:circuit].decision = recorder
    @nodes.each_value { |n| %i[orig circuit decision].each { |k| n[k].start } }
    run_for(40)
    assert_includes heard, "adjacency with 0000.0000.000b up on a-eth0"
    assert(heard.any? { |r| r.start_with?("Level 1 DIS on a-eth0 now") }, heard.inspect)
  end

  # No pseudonode to step through while the DIS's adjacency is not Up, or
  # while its LAN ID names none, a circuit octet of zero.
  def test_no_pseudonode_without_a_dis_up_naming_one
    @nodes.each_value { |n| %i[orig circuit decision].each { |k| n[k].start } }
    run_for(40)
    circuit = @nodes[:a][:circuit]
    dis = circuit.dis
    dis.lan_id = ISIS::Pdu.dotted_octets("0000.0000.000c.00")
    assert_nil circuit.spf_broadcast
    dis.lan_id = ISIS::Pdu.dotted_octets("0000.0000.000c.01")
    dis.state = :initializing
    assert_nil circuit.spf_broadcast
  end

  # The circuit's first hops: B and C Up, and the pseudonode through C.
  def test_the_circuit_gives_its_adjacencies_and_pseudonode
    @nodes.each_value { |n| %i[orig circuit decision].each { |k| n[k].start } }
    run_for(40)
    circuit = @nodes[:a][:circuit]
    assert_equal %w[00000000000b00 00000000000c00],
                 circuit.spf_adjacencies.map { |id, _, _| id.unpack1("H*") }.sort
    pseudonode, metric, dis = circuit.spf_broadcast
    assert_equal ["00000000000c01", 10, "10.0.1.3 via a-eth0"], [pseudonode.unpack1("H*"), metric, dis.to_s]
    assert_nil @nodes[:c][:circuit].spf_broadcast
  end
end

# The default route toward the nearest attached Level 2 system. One fake
# circuit with an adjacency Up to B at 10, and LSPs stored straight into
# the database; B sets ATT for the default metric.
class TestDecisionDefaultRoute < Minitest::Test
  Circuit = Struct.new(:adjacencies) do
    def spf_adjacencies = adjacencies
    def spf_broadcast = nil
  end

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @log = ISIS::Runtime::Log.new(clock: @clock)
  end

  def id(letter) = (ISIS::Pdu.dotted_octets("0000.0000.000#{letter}") + "\x00".b).b

  def decision(level)
    db = ISIS::Database.new(level: level, clock: @clock)
    store = lambda do |letter, links, prefixes: [], attached: []|
      tlvs = [ISIS::Tlv::ExtendedIsReachability.new(links.map do |n|
        ISIS::Tlv::ExtendedIsReachability::Entry.new(neighbor: id(n), metric: 10)
      end)]
      tlvs << ISIS::Tlv::ExtendedIpReachability.new(prefixes) unless prefixes.empty?
      lsp = ISIS::Pdu::Lsp.new(level: level, lsp_id: ISIS::Octets.new(id(letter) + "\x00".b), lifetime: 1200,
                               sequence: 1, tlvs: tlvs, attached: attached)
      db.entry(lsp.lsp_id).store(lsp)
    end
    store.call("a", ["b"])
    adj = ISIS::Spf::Adjacency.new(circuit: "eth-b", neighbor: ISIS::Pdu.dotted_octets("0000.0000.000b"),
                                   circuit_id: 1, address: "10.0.0.11")
    d = ISIS::Spf::Decision.new(system_id: "0000.0000.000a", database: db, scheduler: @scheduler, log: @log)
    d.attach(Circuit.new([[id("b"), 10, adj]]))
    [d, store]
  end

  # At Level 1, 0.0.0.0/0 at the distance to B, through B.
  def test_a_default_route_toward_the_attached_system
    d, store = decision(1)
    store.call("b", ["a"], attached: [:default])
    assert_equal "0.0.0.0/0 metric 10 via 10.0.0.11 via eth-b", d.run["0.0.0.0/0"].to_s
  end

  # None without an attached system, and none at Level 2.
  def test_no_default_route_without_one_or_at_level_2
    d, store = decision(1)
    store.call("b", ["a"])
    assert_nil d.run["0.0.0.0/0"]
    d, store = decision(2)
    store.call("b", ["a"], attached: [:default])
    assert_nil d.run["0.0.0.0/0"]
  end

  # An advertised 0.0.0.0/0 that is farther loses to the attached route:
  # B's at 5 is 15, B itself 10. RFC 1195 section 1.3: "Default routes are
  # not permitted at level 1", so one arriving there is not trusted over
  # the area's exit.
  def test_a_farther_advertised_default_loses
    d, store = decision(1)
    store.call("b", ["a"], prefixes: [{ prefix: "0.0.0.0/0", metric: 5 }], attached: [:default])
    assert_equal 10, d.run["0.0.0.0/0"].metric
  end
end

# IPv6 over the same adjacency (RFC 5308): each side's hellos carry its
# link-local address in TLV 232, its LSP its global address in TLV 232 and
# a /64 in TLV 236, and each reaches the other's /64 at 10 + 1 through the
# other's link-local address.
class TestDecisionIpv6 < Minitest::Test
  IDS = { a: "0000.0000.000a", b: "0000.0000.000b" }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    TestLogs.heading(name)
    @nodes = { a: node(:a, 1), b: node(:b, 2) }
  end

  def node(who, n)
    log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    db = ISIS::Database.new(level: 1, clock: @clock, scheduler: @scheduler, log: log)
    orig = ISIS::Originator.new(system_id: IDS[who], database: db, scheduler: @scheduler, log: log,
                                minimum_interval: 1, protocols: %i[ipv4 ipv6],
                                ipv6_addresses: ["2001:db8::#{n}"],
                                ipv6_prefixes: [{ prefix: "2001:db8:#{n}::/64", metric: 1 }])
    circuit = ISIS::P2pCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler,
                                   log: log, name: "#{who}-eth1", system_id: IDS[who],
                                   snpa: "00:00:00:00:00:0#{who}", ipv6_addresses: ["fe80::#{n}"],
                                   protocols: %i[ipv4 ipv6], database: db, originator: orig,
                                   hello_interval: 1, hello_multiplier: 3)
    decision = ISIS::Spf::Decision.new(system_id: IDS[who], database: db, scheduler: @scheduler, log: log)
    circuit.levels.each_value { |l| decision.attach(l) }
    { orig: orig, circuit: circuit, decision: decision }
  end

  def test_each_reaches_the_others_ipv6_prefix_through_its_link_local_address
    @nodes.each_value { |n| %i[orig circuit decision].each { |k| n[k].start } }
    20.times do
      @scheduler.advance(0.5)
      @nodes.each_value { |n| n[:circuit].poll }
    end
    a = @nodes[:a][:decision].routes.transform_values(&:to_s)
    assert_equal "2001:db8:2::/64 metric 11 via fe80::2 via a-eth1", a["2001:db8:2::/64"]
    assert_equal "2001:db8:1::/64 metric 1 local", a["2001:db8:1::/64"]
    assert_equal ["fe80::1"], @nodes[:b][:circuit].neighbor.ipv6_addresses
  end
end

# The AttachedFlag (RFC 1142 7.2.9.2). A, at both levels in 49.0001, runs
# its Level 2 Decision Process with its Level 1 originator's flag, here a
# stand-in, and B is its Level 2 neighbour. A is attached when it reaches a
# system whose areas share none with its own.
class TestDecisionAttachedFlag < Minitest::Test
  Flag = Struct.new(:attached)
  Circuit = TestDecisionDefaultRoute::Circuit

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @log = ISIS::Runtime::Log.new(clock: @clock)
    @db = ISIS::Database.new(level: 2, clock: @clock)
    @flag = Flag.new(false)
    store("a", ["b"], ["49.0001"])
    adj = ISIS::Spf::Adjacency.new(circuit: "eth-b", neighbor: ISIS::Pdu.dotted_octets("0000.0000.000b"),
                                   circuit_id: 1, address: "10.0.0.11")
    @decision = ISIS::Spf::Decision.new(system_id: "0000.0000.000a", database: @db, scheduler: @scheduler,
                                        log: @log, attached_flag: @flag)
    @circuit = Circuit.new([[id("b"), 10, adj]])
    @decision.attach(@circuit)
  end

  def id(letter) = (ISIS::Pdu.dotted_octets("0000.0000.000#{letter}") + "\x00".b).b

  def store(letter, links, areas, level: 2, db: @db, attached: [], prefixes: [])
    tlvs = []
    tlvs << ISIS::Tlv::AreaAddresses.new(areas) unless areas.empty?
    tlvs << ISIS::Tlv::ExtendedIpReachability.new(prefixes) unless prefixes.empty?
    tlvs << ISIS::Tlv::ExtendedIsReachability.new(links.map do |n|
      ISIS::Tlv::ExtendedIsReachability::Entry.new(neighbor: id(n), metric: 10)
    end)
    lsp = ISIS::Pdu::Lsp.new(level: level, lsp_id: ISIS::Octets.new(id(letter) + "\x00".b), lifetime: 1200,
                             sequence: 1, tlvs: tlvs, attached: attached)
    db.entry(lsp.lsp_id).store(lsp)
  end

  def test_another_area_reached_sets_the_flag
    store("b", ["a"], ["49.0002"])
    @decision.run
    @decision.run
    assert @flag.attached
    assert_equal 1, @log.events.count { |e| e.kind == :attached }, "a run that changes nothing logs nothing"
    event = @log.events.find { |e| e.kind == :attached }
    assert_match(/reach other area, AttachedFlag set .*RFC 1142 7\.2\.9\.2/, event.message)
  end

  def test_only_its_own_area_reached_clears_the_flag
    @flag.attached = true
    store("b", ["a"], ["49.0001"])
    @decision.run
    refute @flag.attached
  end

  # One area address in common is the same area: an area may have several
  # (7.2.11).
  def test_an_area_address_in_common_is_the_same_area
    store("b", ["a"], %w[49.0001 49.0002])
    @decision.run
    refute @flag.attached
  end

  # A system in another area that is not reached, C, in the database with
  # no link to anything, does not count.
  def test_a_system_not_reached_does_not_count
    store("b", ["a"], ["49.0001"])
    store("c", [], ["49.0002"])
    @decision.run
    refute @flag.attached
  end

  # The flag follows the routes: the adjacency to B goes, and A cannot
  # reach another area.
  def test_the_flag_follows_the_routes
    store("b", ["a"], ["49.0002"])
    @decision.run
    @circuit.adjacencies = []
    @decision.run
    refute @flag.attached
    assert_equal [true, false], @log.events.select { |e| e.kind == :attached }.map { |e| e.data[:attached] }
  end

  # A pseudonode reached lists no areas and does not count. B reports a
  # link to its pseudonode B.01, which reports one back, so B.01 is on
  # PATHS.
  def test_a_pseudonode_does_not_count
    pseudo_id = ISIS::Octets.new(id("b").byteslice(0, 6) + "\x01".b)
    entry = ->(n) { ISIS::Tlv::ExtendedIsReachability::Entry.new(neighbor: n, metric: 10) }
    b = ISIS::Pdu::Lsp.new(level: 2, lsp_id: ISIS::Octets.new(id("b") + "\x00".b), lifetime: 1200, sequence: 1,
                           tlvs: [ISIS::Tlv::AreaAddresses.new(["49.0001"]),
                                  ISIS::Tlv::ExtendedIsReachability.new([entry.call(id("a")), entry.call(pseudo_id)])])
    pseudo = ISIS::Pdu::Lsp.new(level: 2, lsp_id: ISIS::Octets.new(pseudo_id + "\x00".b), lifetime: 1200,
                                sequence: 1, tlvs: [ISIS::Tlv::ExtendedIsReachability.new([entry.call(id("b"))])])
    [b, pseudo].each { |l| @db.entry(l.lsp_id).store(l) }
    @decision.run
    assert @decision.paths.key?(pseudo_id.b), "the pseudonode is not on PATHS"
    refute @flag.attached
  end

  # Areas are read from LSP Number 0 alone, as 7.2.11 reads them: B's LSP
  # 0 lists 49.0002 and its LSP 1 a TLV 1 with 49.0001, which does not
  # make B one of A's area.
  def test_areas_come_from_lsp_number_zero
    store("b", ["a"], ["49.0002"])
    one = ISIS::Pdu::Lsp.new(level: 2, lsp_id: ISIS::Octets.new(id("b") + "\x01".b), lifetime: 1200, sequence: 1,
                             tlvs: [ISIS::Tlv::AreaAddresses.new(["49.0001"])])
    @db.entry(one.lsp_id).store(one)
    @decision.run
    assert @flag.attached
  end

  # With a Leak, each Level 2 run hands it the routes: B's 198.51.100.3/32
  # at 10 + 5 reaches the Level 1 originator, here a stand-in. A Level 1
  # decision hands it nothing.
  LeakTarget = Struct.new(:leaked_prefixes, :sets) do
    def leaked_prefixes=(list)
      self.sets += 1
      self[:leaked_prefixes] = list
    end
  end

  def test_a_level_2_run_hands_its_routes_to_the_leak
    orig = LeakTarget.new([], 0)
    @decision.leak = ISIS::Spf::Leak.new(originator: orig, log: @log, policy: ->(_r) { true })
    store("b", ["a"], ["49.0002"], prefixes: [{ prefix: "198.51.100.3/32", metric: 5 }])
    @decision.run
    assert_equal [{ prefix: "198.51.100.3/32", metric: 15 }], orig.leaked_prefixes
    db = ISIS::Database.new(level: 1, clock: @clock)
    l1 = ISIS::Spf::Decision.new(system_id: "0000.0000.000a", database: db, scheduler: @scheduler, log: @log,
                                 leak: ISIS::Spf::Leak.new(originator: (o1 = LeakTarget.new([], 0)),
                                                           log: @log, policy: ->(_r) { true }))
    l1.run
    assert_equal 0, o1.sets
  end

  SummaryTarget = Struct.new(:area_prefixes, :sets) do
    def area_prefixes=(list)
      self.sets += 1
      self[:area_prefixes] = list
    end
  end

  # With a Summary, each Level 1 run hands it the routes: B's
  # 198.51.100.3/32 at 10 + 5 reaches the Level 2 originator, a stand-in.
  # A Level 2 decision hands it nothing.
  def test_a_level_1_run_hands_its_routes_to_the_summary
    db = ISIS::Database.new(level: 1, clock: @clock)
    store("a", ["b"], ["49.0001"], level: 1, db: db)
    store("b", ["a"], ["49.0001"], level: 1, db: db, prefixes: [{ prefix: "198.51.100.3/32", metric: 5 }])
    adj = ISIS::Spf::Adjacency.new(circuit: "eth-b", neighbor: ISIS::Pdu.dotted_octets("0000.0000.000b"),
                                   circuit_id: 1, address: "10.0.0.11")
    orig = SummaryTarget.new([], 0)
    d = ISIS::Spf::Decision.new(system_id: "0000.0000.000a", database: db, scheduler: @scheduler, log: @log,
                                summary: ISIS::Spf::Summary.new(originator: orig, log: @log))
    d.attach(Circuit.new([[id("b"), 10, adj]]))
    d.run
    assert_equal [{ prefix: "198.51.100.3/32", metric: 15 }], orig.area_prefixes
    o2 = SummaryTarget.new([], 0)
    @decision.summary = ISIS::Spf::Summary.new(originator: o2, log: @log)
    store("b", ["a"], ["49.0002"], prefixes: [{ prefix: "198.51.100.3/32", metric: 5 }])
    @decision.run
    assert_equal 0, o2.sets
  end

  # At Level 1, a system whose own LSP Number 0 is attached adds no default
  # route: its nearest Level 2 system is itself ("Self", 7.2.9.2), though B
  # is attached too.
  def test_an_attached_system_adds_no_default_route
    db = ISIS::Database.new(level: 1, clock: @clock)
    store("a", ["b"], ["49.0001"], level: 1, db: db, attached: [:default])
    store("b", ["a"], ["49.0001"], level: 1, db: db, attached: [:default])
    adj = ISIS::Spf::Adjacency.new(circuit: "eth-b", neighbor: ISIS::Pdu.dotted_octets("0000.0000.000b"),
                                   circuit_id: 1, address: "10.0.0.11")
    d = ISIS::Spf::Decision.new(system_id: "0000.0000.000a", database: db, scheduler: @scheduler, log: @log)
    d.attach(Circuit.new([[id("b"), 10, adj]]))
    assert_nil d.run["0.0.0.0/0"]
  end
end
