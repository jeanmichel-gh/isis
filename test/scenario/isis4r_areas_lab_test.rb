# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/sim_host"

# The isis4r-areas example lab, from its own files, on simulated wires and
# a manual clock: three borders (b1-b3, Level 1-2), three Level 1 routers
# (r1-r3) and three simulators (s1-s3), each with a 3x3 grid. Wired as
# examples/containerlab/isis4r-areas/isis4r-areas.clab.yml wires them.
#
# It holds the numbers the lab's comments and scenarios rely on, so a
# change to a file that moves one fails here before it fails in a lab.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestIsis4rAreasLab < Minitest::Test
  EX = File.expand_path("../../examples/containerlab/isis4r-areas", __dir__)
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
    clab = YAML.safe_load_file(File.join(EX, "isis4r-areas.clab.yml"))
    @links = {}
    clab["topology"]["links"].each_with_index { |l, i| l["endpoints"].each { @links[_1] = i } }
    @nodes = {}
    %w[b1 b2 b3 r1 r2 r3].each do |n|
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

  def route(node, level, prefix) = @nodes[node].decisions[level].routes.values.find { _1.prefix.to_s == prefix }

  # Adjacencies up at a level, as isis-cli and routescope read them.
  def up(node, level)
    ISIS::Daemon::Views.new(@nodes[node]).adjacencies.count { _1[:level] == level && _1[:state] == "up" }
  end

  def att?(border, n)
    !@nodes[border].databases[1][ISIS::Pdu.lsp_id_octets("0000.0000.000#{n}.00-00")].lsp.attached.empty?
  end

  def test_adjacencies_by_level
    %w[b1 b2 b3].each do |b|
      assert_equal 2, up(b, 1), "#{b}: Level 1 with its simulator and its r"
      assert_equal 2, up(b, 2), "#{b}: Level 2 with the other two borders only"
    end
    %w[r1 r2 r3].each { assert_equal 2, up(_1, 1), "#{_1}: its border and its simulator" }
  end

  def test_each_border_carries_its_area_into_level_2
    assert_equal 60, route("b1", 1, "10.201.0.9/32").metric
    r = route("b2", 2, "10.201.0.9/32")
    assert_equal 70, r.metric
    assert_equal ["10.0.12.1"], r.adjacencies.map(&:address)
    assert_equal 70, route("b3", 2, "10.201.0.9/32").metric
    assert_equal 80, route("b2", 2, "31.0.0.0/24").metric
    assert_equal 70, route("b1", 2, "10.203.0.9/32").metric
  end

  def test_borders_set_the_attached_bit_and_r_follows_it
    %w[1 2 3].each { |n| assert att?("b#{n}", n), "b#{n}'s Level 1 LSP 00-00 has ATT" }
    d = route("r1", 1, "0.0.0.0/0")
    refute_nil d, "r1 has a default route"
    assert_equal ["10.1.1.1"], d.adjacencies.map(&:address)
    assert_nil route("r1", 1, "10.202.0.9/32"), "r1 knows only its own area"
  end

  def test_backbone_link_down_reroutes_through_b3
    cut("b1:eth1")
    run_for(10)
    r = route("b2", 2, "10.201.0.9/32")
    assert_equal 80, r.metric
    assert_equal ["10.0.23.2"], r.adjacencies.map(&:address)
    cut("b1:eth1", false)
    run_for(15)
    assert_equal 70, route("b2", 2, "10.201.0.9/32").metric
  end

  # scenarios/area-prefix-withdraw.yml: a change inside area 1 reaches
  # the other areas through b1's Level 2 LSP.
  def test_a_prefix_withdrawn_in_area_1_leaves_level_2
    @nodes["s1"].prefixes_withdraw("r3c3", "31.0.0.0/24")
    run_for(5)
    assert_nil route("b2", 2, "31.0.9.0/24")
    assert_nil route("b3", 2, "31.0.9.0/24")
    refute_nil route("b2", 2, "10.201.0.9/32"), "the rest of area 1 stays"
    @nodes["s1"].prefixes_advertise("r3c3", "31.0.0.0/24")
    run_for(5)
    assert_equal 80, route("b2", 2, "31.0.9.0/24").metric
  end

  # scenarios/grid-metric.yml: s1's link into its grid at 100, so all of
  # area 1 is 90 further from every border.
  def test_a_metric_in_area_1_moves_level_2
    @nodes["s1"].link_metric("s1--r1c1", 100)
    run_for(5)
    assert_equal 150, route("b1", 1, "10.201.0.9/32").metric
    assert_equal 160, route("b2", 2, "10.201.0.9/32").metric
    @nodes["s1"].link_metric("s1--r1c1", 10)
    run_for(5)
    assert_equal 70, route("b2", 2, "10.201.0.9/32").metric
  end

  def test_border_cut_off_clears_the_attached_bit
    cut("b1:eth1")
    cut("b1:eth2")
    run_for(10)
    refute att?("b1", 1), "b1 reaches no other area"
    assert_nil route("r1", 1, "0.0.0.0/0"), "r1 loses its default route"
    assert_nil route("b2", 2, "10.201.0.9/32"), "b2 loses area 1"
    cut("b1:eth1", false)
    cut("b1:eth2", false)
    run_for(15)
    assert att?("b1", 1)
    refute_nil route("r1", 1, "0.0.0.0/0")
    assert_equal 70, route("b2", 2, "10.201.0.9/32").metric
  end
end
