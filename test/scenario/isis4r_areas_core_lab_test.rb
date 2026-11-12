# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/sim_host"

# The isis4r-areas-core example lab, from its own files, on simulated
# wires and a manual clock: a Level 2-only backbone (c0, area 49.0000),
# three borders (b1-b3, Level 1-2), three Level 1 routers (r1-r3) and
# three simulators (s1-s3), each with a 3x3 grid. Wired as
# routescope/labs/isis4r-areas-core/isis4r-areas-core.clab.yml
# wires them.
#
# It holds every number the lab's comments and scenarios rely on, so a
# change to a file that moves one fails here before it fails in a lab.
# The design is routescope docs/design/isis-areas-core.md.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestIsis4rAreasCoreLab < Minitest::Test
  EX = File.expand_path("../../routescope/labs/isis4r-areas-core", __dir__)
  STEP = 0.5

  # A wire that can be cut: a cut wire delivers nothing, as a link with
  # 100% loss. The adjacency goes when its hold time runs out.
  class Wire < ISIS::Link::SimulatedWire
    attr_accessor :cut

    def deliver(from, bytes)
      super unless cut
    end
  end

  # A host whose interface names map to wires by the clab file's links.
  class LabHost < SimHost
    def initialize(wires, node, links)
      @node = node
      @ends = links
      super(wires, Hash.new { |_, ifc| format("02:00:00:%02x:00:%02x", node.sum % 256, ifc[/\d+/].to_i) })
    end

    def link(name)
      key = @ends.fetch("#{@node}:#{name}")
      { transport: ISIS::Link::SimulatedTransport.new(@wires[key]), snpa: @macs[name],
        link_local: ["fe80::#{@node.sum % 256}:#{name[/\d+/]}"] }
    end
  end

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = Wire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    clab = YAML.safe_load_file(File.join(EX, "isis4r-areas-core.clab.yml"))
    @links = {}
    clab["topology"]["links"].each_with_index { |l, i| l["endpoints"].each { @links[_1] = i } }
    @nodes = {}
    %w[c0 b1 b2 b3 r1 r2 r3].each do |n|
      config = ISIS::Router.normalize(ISIS::ConfigFile.load(File.join(EX, n, "isisd.yml")))
      @nodes[n] = ISIS::Router.new(config, clock: @clock, scheduler: @scheduler, log: @log,
                                           host: LabHost.new(@wires, n, @links))
    end
    %w[s1 s2 s3].each do |n|
      topo = ISIS::Sim::Topology.load(File.join(EX, n, "sim.yml"))
      @nodes[n] = ISIS::Sim::Simulator.new(topo, clock: @clock, scheduler: @scheduler, log: @log,
                                                 host: LabHost.new(@wires, n, @links))
    end
    @nodes.each_value(&:start)
    run_for(30)
  end

  def run_for(seconds)
    (seconds / STEP).ceil.times do
      @scheduler.advance(STEP)
      @nodes.each_value { _1.step(wait: 0) }
    end
  end

  def cut(endpoint, on = true) = @wires[@links.fetch(endpoint)].cut = on

  def route(node, level, prefix)
    d = @nodes[node].decisions[level] or return nil
    d.routes.values.find { _1.prefix.to_s == prefix }
  end

  def via(node, level, prefix) = route(node, level, prefix)&.adjacencies&.map(&:address)

  def views(node) = ISIS::Daemon::Views.new(@nodes[node])

  # Adjacencies up at a level, as isis-cli and routescope read them.
  def up(node, level) = views(node).adjacencies.count { _1[:level] == level && _1[:state] == "up" }

  # LSPs held at a level, as show.database lists them.
  def lsps(node, level) = views(node).database.count { _1[:level] == level }

  # The route as show.routes gives it, with its up/down bit.
  def shown(node, prefix) = views(node).routes.find { _1[:prefix] == prefix }

  def att?(border, n)
    !@nodes[border].databases[1][ISIS::Pdu.lsp_id_octets("0000.0000.000#{n}.00-00")].lsp.attached.empty?
  end

  # isisd's policy.overload, as daemon/api.rb sets it.
  def overload(node, on) = @nodes[node].originators.each_value { _1.overload = on }

  # ---- the topology: baseline.yml

  def test_adjacencies_by_level
    assert_equal 0, up("c0", 1), "c0 runs no Level 1"
    assert_equal 3, up("c0", 2), "c0: the three borders"
    assert_equal [2, 2], [up("b1", 1), up("b1", 2)], "b1: s1 and r1; c0 and b2"
    assert_equal [2, 2], [up("b2", 1), up("b2", 2)], "b2: s2 and r2; c0 and b1"
    assert_equal [2, 1], [up("b3", 1), up("b3", 2)], "b3: s3 and r3; c0 only"
    %w[r1 r2 r3].each { assert_equal [2, 0], [up(_1, 1), up(_1, 2)], "#{_1}: its border and its simulator" }
  end

  def test_databases_per_level
    assert_equal 0, lsps("c0", 1), "c0 holds no Level 1 LSP"
    assert_equal 4, lsps("c0", 2), "c0, b1, b2, b3: no simulated system is at Level 2"
    assert_equal 12, lsps("r1", 1), "area 1: b1, r1, s1 and nine grid systems"
    assert_equal 0, lsps("r1", 2)
    assert_equal 4, lsps("b3", 2)
  end

  def test_area_1_in_level_2
    assert_equal 60, route("b1", 1, "10.201.0.9/32").metric
    assert_equal [70, ["10.0.12.1"]], [route("b2", 2, "10.201.0.9/32").metric, via("b2", 2, "10.201.0.9/32")]
    assert_equal [70, ["10.0.1.2"]], [route("c0", 2, "10.201.0.9/32").metric, via("c0", 2, "10.201.0.9/32")]
    assert_equal [80, ["10.0.3.1"]], [route("b3", 2, "10.201.0.9/32").metric, via("b3", 2, "10.201.0.9/32")]
  end

  def test_every_border_sets_att_and_each_r_follows_it
    %w[1 2 3].each { |n| assert att?("b#{n}", n), "b#{n}'s Level 1 LSP 00-00 has ATT" }
    { "r1" => "10.1.1.1", "r2" => "10.2.1.1", "r3" => "10.3.1.1" }.each do |r, gw|
      assert_equal [10, [gw]], [route(r, 1, "0.0.0.0/0").metric, via(r, 1, "0.0.0.0/0")], "#{r}'s default"
    end
    assert_nil route("r1", 1, "10.203.0.9/32"), "r1 knows only its own area"
  end

  # ---- leak.yml: area 1

  def test_leak_into_area_1
    @nodes["b1"].leak_prefixes = ["10.203.0.0/24"]
    run_for(5)
    r = shown("r1", "10.203.0.9/32")
    refute_nil r, "r1 has area 3's r3c3 in Level 1"
    assert_equal [1, true, ["10.1.1.1"]], [r[:level], r[:up_down], r[:next_hops].map { _1[:address] }]
    assert_equal 90, r[:metric], "b1's 80 to it at Level 2, plus r1-b1"
    assert_nil shown("r1", "10.202.0.9/32"), "only what the policy covers"
    assert_equal ["10.0.3.2"], via("c0", 2, "10.203.0.9/32"), "c0 still reaches area 3 through b3, not b1"
    assert_nil route("b2", 1, "10.203.0.9/32"), "and b2 does not see the leak"
    @nodes["b1"].leak_prefixes = []
    run_for(5)
    assert_nil shown("r1", "10.203.0.9/32"), "r1 back to its default"
  end

  # ---- summaries.yml: area 2

  def test_summaries_from_area_2
    @nodes["b2"].summaries = [{ prefix: "10.202.0.0/24", metric: 20 }, { prefix: "32.0.0.0/20" }]
    run_for(5)
    assert_equal 30, route("c0", 2, "10.202.0.0/24")&.metric, "b2's 20, plus c0-b2"
    assert_nil route("c0", 2, "10.202.0.9/32"), "the /32s it covers are gone"
    assert_equal 70, route("b2", 1, "32.0.0.0/24").metric, "60 to r3c3, plus the prefix's 10"
    assert_equal 80, route("c0", 2, "32.0.0.0/20")&.metric, "no metric: the lowest it covers, 70, plus c0-b2"
    assert_nil route("c0", 2, "32.0.0.0/24")
    @nodes["s2"].link_down("s2--r1c1")
    run_for(5)
    assert_nil route("c0", 2, "10.202.0.0/24"), "nothing it covers is reachable"
    assert_nil route("c0", 2, "32.0.0.0/20")
    @nodes["s2"].link_up("s2--r1c1")
    @nodes["b2"].summaries = []
    run_for(5)
    assert_equal 70, route("c0", 2, "10.202.0.9/32")&.metric
  end

  # ---- false-attached.yml and nearest-attached.yml: area 3

  def test_a_false_attached_bit_in_area_3
    cut("c0:eth3")
    run_for(10)
    refute att?("b3", 3), "b3 reaches no other area"
    assert_nil route("r3", 1, "0.0.0.0/0"), "r3 loses its default"
    @nodes["s3"].router_attached("r3c3", true)
    run_for(5)
    assert_equal [60, ["10.3.2.2"]], [route("r3", 1, "0.0.0.0/0")&.metric, via("r3", 1, "0.0.0.0/0")],
                 "r3 follows r3c3's ATT, through s3"
    @nodes["s3"].router_attached("r3c3", false)
    run_for(5)
    assert_nil route("r3", 1, "0.0.0.0/0")
    cut("c0:eth3", false)
    run_for(15)
    assert_equal ["10.3.1.1"], via("r3", 1, "0.0.0.0/0")
  end

  def test_the_nearest_attached_system_wins
    @nodes["s3"].router_attached("r3c3", true)
    run_for(5)
    assert_equal [10, ["10.3.1.1"]], [route("r3", 1, "0.0.0.0/0").metric, via("r3", 1, "0.0.0.0/0")], "b3 at 10, not r3c3 at 60"
    cut("b3:eth4")
    run_for(10)
    assert_equal [20, ["10.3.2.2"]], [route("r3", 1, "0.0.0.0/0").metric, via("r3", 1, "0.0.0.0/0")],
                 "b3 through s3 at 20, still nearer than r3c3"
    cut("b3:eth4", false)
    @nodes["s3"].router_attached("r3c3", false)
    run_for(15)
    assert_equal ["10.3.1.1"], via("r3", 1, "0.0.0.0/0")
  end

  # ---- core-overload.yml

  def test_overload_on_the_core
    overload("c0", true)
    run_for(5)
    assert_nil route("b3", 2, "10.201.0.9/32"), "b3 reaches area 1 only through c0"
    assert_nil route("b3", 2, "10.202.0.9/32")
    refute_nil route("b3", 2, "10.255.0.100/32"), "c0's own prefixes stay"
    assert att?("b3", 3), "c0's area is another area, so b3 keeps ATT"
    refute_nil route("r3", 1, "0.0.0.0/0")
    assert_equal ["10.0.12.1"], via("b2", 2, "10.201.0.9/32"), "b1 and b2 keep each other"
    assert_nil route("b2", 2, "10.203.0.9/32"), "and lose area 3"
    overload("c0", false)
    run_for(5)
    assert_equal 80, route("b3", 2, "10.201.0.9/32")&.metric
  end

  # ---- backbone-reroute.yml

  def test_backbone_reroute
    cut("b1:eth2")
    run_for(10)
    assert_equal [80, ["10.0.2.1"]], [route("b2", 2, "10.201.0.9/32").metric, via("b2", 2, "10.201.0.9/32")]
    cut("b1:eth2", false)
    run_for(15)
    assert_equal 70, route("b2", 2, "10.201.0.9/32").metric
  end
end
