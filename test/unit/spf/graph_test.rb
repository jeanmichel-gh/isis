# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"

# Spf::Graph read from a real database: the LSPs the simulator generates
# for an SR grid, each with its Prefix-SIDs and an Adj-SID per link. Then
# TI-LFA over it, from a router in the grid.
#
#   s1 0000.0000.0009 -- r1c1 -- r1c2 -- r1c3
#                         |       |       |
#                        r2c1 -- r2c2 -- r2c3
class TestSpfGraph < Minitest::Test
  def setup
    clock = ISIS::Runtime::ManualClock.new
    scheduler = ISIS::Runtime::Scheduler.new(clock)
    wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    topo = ISIS::Sim::Topology.from_hash(
      { "simulator" => { "system_id" => "0000.0000.0009", "hostname" => "s1", "areas" => ["49.0001"], "level" => 1,
                         "interfaces" => [{ "name" => "a", "ip_addresses" => ["10.0.14.2"] }] },
        "segment_routing" => {},
        "grid" => { "rows" => 2, "columns" => 3, "metric" => 10, "loopbacks" => "10.200.0.0/24", "sids" => 101 },
        "links" => [{ "from" => "s1", "to" => "r1c1" }] }
    )
    topo.router_config[:segment_routing] = {}
    topo.router_config[:router_id] = "10.0.14.2"
    @sim = ISIS::Sim::Simulator.new(topo, clock: clock, scheduler: scheduler, log: ISIS::Runtime::Log.new(clock: clock),
                                          host: SimHost.new(wires, { "a" => "00:00:00:00:00:09" }))
    @sim.start
    4.times do
      scheduler.advance(0.5)
      @sim.step(wait: 0)
    end
    @graph = ISIS::Spf::Graph.from_database(@sim.router.databases[1])
  end

  def id(text) = (ISIS::Pdu.dotted_octets(text) + "\x00".b).b

  def test_the_grid
    grid = %w[0101 0102 0103 0201 0202 0203].map { id("0000.0001.#{_1}") }
    assert_equal (grid + [id("0000.0000.0009")]).sort, @graph.nodes.sort
    assert_equal 10, @graph.metric(id("0000.0001.0101"), id("0000.0001.0102"))
    assert_equal (101..106).to_a, grid.map { @graph.node_sids[_1] }
  end

  def test_every_grid_link_has_an_adj_sid_both_ways
    grid_links = @graph.edges.flat_map { |a, tos| tos.keys.map { [a, _1] } }
                       .reject { |pair| pair.include?(id("0000.0000.0009")) }
    assert_equal 14, grid_links.size
    grid_links.each { |pair| assert @graph.adj_sids.key?(pair), pair.inspect }
  end

  # From r1c1, the link to r1c2 and the node r1c2: every destination
  # behind them is protected, around the grid's other row.
  def test_ti_lfa_on_the_grid
    t = ISIS::Spf::TiLfa.new(@graph, root: id("0000.0001.0101"))
    r1c2 = id("0000.0001.0102")
    [t.link(r1c2), t.node(r1c2)].each do |f|
      got = t.protect(f)
      refute_empty got
      got.each_value do |r|
        next if r.is_a?(ISIS::Spf::TiLfa::Unprotected) && r.reason == :neighbor

        assert r.protected?, r.to_s
      end
    end
    r = t.repair(id("0000.0001.0103"), t.link(r1c2))
    assert_equal id("0000.0001.0201"), r.first_hop
  end
end
