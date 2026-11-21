# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"

# The simulator puts each entry of ISIS::Fault in a simulated system's
# LSPs (Simulator#fault), and an ordinary Router, the device under test,
# learns them over its adjacency and makes the entry's finding. Then the
# fault is cleared and the finding goes. On a manual clock.
#
#   dut 0000.0000.0001 -- s1 0000.0000.0009 -- r1c1 -- r1c2 -- r1c3
#                                                |       |       |
#                                              r2c1 -- r2c2 -- r2c3
class TestSimFaultInjection < Minitest::Test
  HELLO = { hello_interval: 1, hello_multiplier: 3 }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
  end

  # The simulator and an SR grid, sids from 101, and an SR dut.
  def start
    topo = ISIS::Sim::Topology.from_hash(
      { "simulator" => { "system_id" => "0000.0000.0009", "hostname" => "s1", "areas" => ["49.0001"], "level" => 1,
                         "minimum_lsp_interval" => 1,
                         "interfaces" => [{ "name" => "a", "ip_addresses" => ["10.0.14.2"] }.merge(HELLO.transform_keys(&:to_s))] },
        "segment_routing" => {},
        "grid" => { "rows" => 2, "columns" => 3, "metric" => 10, "loopbacks" => "10.200.0.0/24", "sids" => 101 },
        "links" => [{ "from" => "s1", "to" => "r1c1" }] }
    )
    topo.router_config[:segment_routing] = { srgb: [{ start: 17_000, size: 8000 }] }
    topo.router_config[:router_id] = "10.0.14.2"
    @sim = ISIS::Sim::Simulator.new(topo, clock: @clock, scheduler: @scheduler, log: @log,
                                          host: SimHost.new(@wires, { "a" => "00:00:00:00:00:09" }))
    @dut = ISIS::Router.new({ system_id: "0000.0000.0001", hostname: "dut", minimum_lsp_interval: 1,
                              segment_routing: {}, router_id: "10.0.14.1",
                              interfaces: [{ name: "a", ip_addresses: ["10.0.14.1"], **HELLO }] },
                            clock: @clock, scheduler: @scheduler, log: @log,
                            host: SimHost.new(@wires, { "a" => "00:00:00:00:00:01" }))
    @sim.start
    @dut.start
    run_for(15)
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @sim.step(wait: 0)
      @dut.step(wait: 0)
    end
  end

  def findings = @dut.decisions[1].labels.findings.map(&:name).uniq

  # Each entry, in r2c3: the dut makes its finding, and only after it is
  # injected; cleared, the finding goes.
  def test_each_entry_reaches_the_dut
    start
    assert_empty findings, "a correct area first"
    ISIS::Fault.catalog.each do |e|
      answer = @sim.fault(e[:name], router: "r2c3")
      assert_equal [e[:name], e[:finding]], answer.values_at(:case, :finding)
      run_for(5)
      assert_equal [e[:finding]], findings, e[:name]
      @sim.fault_clear("r2c3")
      run_for(5)
      assert_empty findings, "#{e[:name]} cleared"
    end
    assert_equal ISIS::Fault.names, @sim.faults.map { _1[:case] }
  end

  # The entry's Router Capability takes the place of r2c3's own: one TLV
  # 242 in its LSP, the entry's.
  def test_the_capability_is_replaced
    start
    @sim.fault(:srgb_overlap, router: "r2c3")
    run_for(5)
    lsp = @dut.databases[1][ISIS::Pdu.lsp_id_octets("0000.0001.0203.00-00")].lsp
    caps = lsp.tlvs.select { _1.is_a?(ISIS::Tlv::RouterCapability) }
    assert_equal 1, caps.size
    ranges = caps.first.subtlvs.find { _1.is_a?(ISIS::SubTlv::SrCapabilities) }.ranges
    assert_equal 2, ranges.size
  end

  # A plan builds and injects nothing.
  def test_a_plan
    start
    plan = @sim.fault(:srgb_reserved, router: "r2c3", plan: true)
    assert plan[:plan]
    refute_empty plan[:tlvs]
    run_for(5)
    assert_empty findings
    assert_empty @sim.faults
  end

  def test_refusals
    start
    assert_raises(ArgumentError) { @sim.fault(:nope, router: "r2c3") }
    assert_raises(ArgumentError) { @sim.fault(:srgb_overlap, router: "s1") }
    assert_raises(ArgumentError) { @sim.fault(:srgb_overlap, router: "nobody") }
  end

  # Octets sent as they are: an LSP of a system nobody simulates, built by
  # the catalog, reaches the dut's database.
  def test_send
    start
    octets = ISIS::Fault.wire(:srgb_overlap, system_id: "0000.0000.0077", neighbors: { "0000.0000.0009" => 10 })
    answer = @sim.send_pdu(octets)
    assert_equal [1, "Lsp"], answer.values_at(:sent, :pdu)
    run_for(2)
    refute_nil @dut.databases[1][ISIS::Pdu.lsp_id_octets("0000.0000.0077.00-00")]
    assert_equal 1, @sim.sent.size
  end
end
