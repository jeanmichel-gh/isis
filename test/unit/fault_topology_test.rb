# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/sim_host"

# The catalog's TI-LFA topologies (ISIS::Fault::TOPOLOGIES): each is run
# as an isis4r-sim file, so its systems' LSPs are the simulator's own, as
# a router would learn them, Router Capability, Prefix-SIDs and Adj-SIDs
# included. The graph is read back from the simulator's database, and
# TI-LFA computed at the entry's PLR must give what the entry expects,
# which was written from RFC 9855 by hand.
class TestFaultTopology < Minitest::Test
  T = ISIS::Spf::TiLfa

  def lsps_of(name)
    clock = ISIS::Runtime::ManualClock.new
    scheduler = ISIS::Runtime::Scheduler.new(clock)
    log = ISIS::Runtime::Log.new(clock: clock, logger: TestLogs.logger(clock), tracer: TestLogs.tracer(clock))
    sim = ISIS::Sim::Simulator.new(ISIS::Sim::Topology.from_hash(ISIS::Fault.topology_file(name)),
                                   clock: clock, scheduler: scheduler, log: log, host: SimHost.new({}, {}))
    sim.start
    4.times do
      scheduler.advance(0.5)
      sim.step(wait: 0)
    end
    sim
  end

  def id(name, i) = (ISIS::Pdu.dotted_octets(format("0000.0000.%04x", i + 1)) + "\x00").b

  def computed(name)
    e = ISIS::Fault.topology(name)
    sim = lsps_of(name)
    systems = ISIS::Fault.topology_systems(name)
    ids = systems.each_with_index.to_h { |n, i| [n, id(n, i)] }
    names = ids.invert
    graph = ISIS::Spf::Graph.from_database(sim.router.databases[1])
    t = T.new(graph, root: ids.fetch(e[:plr]))
    kind, neighbor = e[:failure]
    failure = kind == :node ? t.node(ids.fetch(neighbor)) : t.link(ids.fetch(neighbor))
    got = t.protect(failure)[ids.fetch(e[:destination])]
    sim.stop
    describe(got, names)
  end

  def describe(got, names)
    case got
    when T::Repair
      { case: got.case, first_hop: names[got.first_hop], p: names[got.p], q: names[got.q],
        segments: got.segments.map { |s| s[:node] ? [:node, names[s[:node]]] : [:adj, *s[:adj].map { names[_1] }] } }
    when T::Unprotected then { unprotected: got.reason }
    when T::Ecmp then { ecmp: got.next_hops.map { names[_1] } }
    else { none: got }
    end
  end

  ISIS::Fault.topology_names.each do |name|
    define_method(:"test_#{name}") do
      assert_equal ISIS::Fault.topology(name)[:expect], computed(name), ISIS::Fault.topology(name)[:description]
    end
  end

  def test_every_entry_names_its_section_and_its_systems_are_numbered
    ISIS::Fault.topologies.each do |e|
      assert_match(/\ARFC 9855 (\d+(\.\d+)?)/, e[:rfc], e[:name])
      systems = ISIS::Fault.topology_systems(e[:name])
      assert_includes systems, e[:plr]
      assert_includes systems, e[:destination]
      assert_includes systems, e[:failure][1]
    end
  end

  # Distinct SRGBs, so a label taken from the wrong block shows.
  def test_each_system_has_its_own_srgb
    file = ISIS::Fault.topology_file(:ti_lfa_figure_1)
    starts = file["routers"].map { _1["srgb"].first["start"] }
    assert_equal starts.uniq, starts
  end

  def test_an_unknown_topology
    e = assert_raises(ArgumentError) { ISIS::Fault.topology(:nope) }
    assert_match(/ti_lfa_figure_1/, e.message)
  end
end
