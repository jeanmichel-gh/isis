# frozen_string_literal: true

require_relative "../../test_helper"

# Two point to point circuits on a simulated wire, on one manual clock.
# Nothing waits in real time: the scheduler advances simulated seconds and
# each circuit reads what the wire delivered.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestP2pCircuit < Minitest::Test
  A_ID = "0000.0000.000a"
  B_ID = "0000.0000.000b"

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    @lines = []
    @traces = []
    TestLogs.heading(name)
    @log_a = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock, ->(l, m) { @lines << [l, m] }),
                                    tracer: TestLogs.tracer(@clock, ->(*t) { @traces << t }))
    @log_b = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @a = circuit(A_ID, "00:00:00:00:00:0a", @log_a, name: "a-eth1")
    @b = circuit(B_ID, "00:00:00:00:00:0b", @log_b, name: "b-eth1", extended_circuit_id: 7)
  end

  def circuit(id, mac, log, name:, **opts)
    ISIS::P2pCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler, log: log,
                         name: name, system_id: id, snpa: mac, **opts)
  end

  # Advance simulated time in small steps, letting each circuit read its
  # frames after every step.
  def run_for(seconds, step: 0.5, circuits: [@a, @b])
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      circuits.each(&:poll)
    end
  end

  def start_both
    @a.start
    @b.start
    [@a, @b].each(&:poll)
  end

  def transitions(log)
    log.events.select { |e| e.kind == :adjacency }.map { |e| [e.data[:from], e.data[:to]] }
  end

  def test_both_reach_up_through_initializing
    start_both
    run_for(7)
    assert @a.up?
    assert @b.up?
    assert_equal [%i[down initializing], %i[initializing up]], transitions(@log_a)
    assert_equal [%i[down initializing], %i[initializing up]], transitions(@log_b)
  end

  # Once up, the hello names the neighbour and its circuit, as RFC 5303
  # section 3.2 asks: f0, 0f, 00 Up, 00000001 our circuit, 00000000000b the
  # neighbour, 00000007 its circuit.
  def test_hello_names_the_neighbor_once_known
    start_both
    run_for(7)
    three_way = @a.build_hello.tlvs.find { |t| t.is_a?(ISIS::Tlv::ThreeWayAdjacency) }
    assert_equal "f00f" "00" "00000001" "00000000000b" "00000007", three_way.to_shex
  end

  def test_before_any_neighbor_the_hello_says_down_with_our_circuit_only
    three_way = @a.build_hello.tlvs.find { |t| t.is_a?(ISIS::Tlv::ThreeWayAdjacency) }
    assert_equal "f005" "02" "00000001", three_way.to_shex
  end

  def test_hello_holding_time_is_interval_times_multiplier
    assert_equal 30, @a.build_hello.holding_time
  end

  # Each hello restarts the holding timer, so an adjacency that keeps
  # hearing hellos outlives any single holding time.
  def test_hellos_keep_the_adjacency_up
    start_both
    run_for(70)
    assert @a.up?
    assert_equal 2, transitions(@log_a).size
  end

  # B goes silent. Its last hello left at 6 s, so A holds the adjacency
  # for B's holding time, to 36 s, then drops it and says why.
  def test_losing_the_neighbor_expires_the_adjacency
    start_both
    run_for(7)
    @b.stop
    @b.transport.close
    run_for(28)
    assert @a.up?, "35 s, still within the holding time"
    run_for(2)
    refute @a.up?
    assert_nil @a.neighbor
    last = @log_a.events.last
    assert_equal [:adjacency, :expired, :down], [last.kind, last.data[:reason], last.data[:to]]
    assert_includes last.message, "holding time of 30 s expired"
  end

  def test_no_area_in_common_forms_no_adjacency
    b = circuit(B_ID, "00:00:00:00:00:0b", @log_b, name: "b-eth1", areas: ["49.0002"])
    @a.start
    b.start
    run_for(10, circuits: [@a, b])
    refute @a.up?
    assert_nil @a.neighbor
    assert_equal :area, @log_a.events.find { |e| e.kind == :refused }.data[:reason]
  end

  def test_area_written_differently_still_matches
    b = circuit(B_ID, "00:00:00:00:00:0b", @log_b, name: "b-eth1", areas: ["490001"])
    @a.start
    b.start
    run_for(7, circuits: [@a, b])
    assert @a.up?
  end

  def test_level_2_only_neighbor_is_refused
    assert_equal :level, @a.receive_hello(hello(circuit_type: :l2), mac)
    assert_nil @a.neighbor
  end

  def test_own_hello_is_ignored
    assert_equal :own, @a.receive_hello(hello(source: A_ID), mac)
  end

  # RFC 5303 section 3.2: neighbour fields that do not name this system or
  # circuit, and a state that is not 0 to 2, discard the PDU.
  def test_three_way_refusals
    assert_equal :three_way_neighbor,
                 @a.receive_hello(hello(three_way: three_way(:initializing, neighbor_system_id: "0000.0000.00cc",
                                                                            neighbor_extended_circuit_id: 1)), mac)
    assert_equal :three_way_circuit,
                 @a.receive_hello(hello(three_way: three_way(:initializing, neighbor_system_id: A_ID,
                                                                            neighbor_extended_circuit_id: 9)), mac)
    assert_equal :three_way_state, @a.receive_hello(hello(three_way: three_way(7)), mac)
    assert_nil @a.neighbor
    assert_equal %i[three_way_neighbor three_way_circuit three_way_state],
                 @log_a.events.select { |e| e.kind == :refused }.map { |e| e.data[:reason] }
  end

  # RFC 5303 section 3.2: with no TLV 240 the link is taken to work both
  # ways, so the adjacency comes straight up.
  def test_no_three_way_tlv_comes_straight_up
    assert_equal :up, @a.receive_hello(hello(three_way: nil), mac)
    assert @a.up?
  end

  # Down on our side and Up on theirs: the neighbour has state we do not,
  # so it restarted. RFC 5303 section 3.2, "Neighbor restarted".
  def test_neighbor_reporting_up_to_a_new_adjacency_is_restarted
    assert_equal :down, @a.receive_hello(hello(three_way: three_way(:up)), mac)
    assert_nil @a.neighbor
    assert_equal :restarted, @log_a.events.last.data[:reason]
  end

  def test_a_different_neighbor_replaces_the_old_one
    @a.receive_hello(hello(three_way: nil), mac)
    @a.receive_hello(hello(source: "0000.0000.00cc", three_way: nil), mac)
    assert_equal "0000.0000.00cc", @a.neighbor.system_id_s
    assert_includes @log_a.events.map { |e| e.data[:reason] }, :replaced
  end

  def test_id_length_mismatch_is_refused
    assert_equal :id_length, @a.receive_hello(hello(source: "0000.0000.0000.000b"), mac)
  end

  def test_circuit_type_zero_is_refused
    assert_equal :circuit_type, @a.receive_hello(hello(circuit_type: 0), mac)
  end

  def test_refusals_and_state_changes_log_at_info_and_pdus_at_debug
    start_both
    run_for(7)
    assert(@lines.any? { |l, m| l == :info && m == "a-eth1 adjacency with 0000.0000.000b initializing -> up" })
    assert(@lines.any? { |l, m| l == :debug && m.include?("three-way up, received up: accept") })
    directions = @traces.map(&:first).uniq.sort
    assert_equal %i[received sent], directions
    assert(@traces.all? { |_, circuit, pdu, _| circuit == "a-eth1" && pdu.is_a?(ISIS::Pdu::P2pHello) })
  end

  # Logging is observation. The same scenario with a debug logger and
  # tracer installed, and with nothing installed, sends the same octets
  # and goes through the same states.
  def test_logging_does_not_change_behaviour
    with = scenario(logger: ->(*) {}, tracer: ->(*) {})
    without = scenario
    assert_equal without, with
  end

  private

  def scenario(logger: nil, tracer: nil)
    clock = ISIS::Runtime::ManualClock.new
    scheduler = ISIS::Runtime::Scheduler.new(clock)
    wire = ISIS::Link::SimulatedWire.new
    sent = []
    tap = ISIS::Link::SimulatedTransport.new(wire)
    logs = [ISIS::Runtime::Log.new(clock: clock, logger: logger, tracer: tracer), ISIS::Runtime::Log.new(clock: clock)]
    circuits = [[A_ID, "00:00:00:00:00:0a"], [B_ID, "00:00:00:00:00:0b"]].each_with_index.map do |(id, m), i|
      ISIS::P2pCircuit.new(transport: ISIS::Link::SimulatedTransport.new(wire), scheduler: scheduler, log: logs[i],
                           name: "c#{i}", system_id: id, snpa: m)
    end
    circuits.each(&:start)
    80.times do
      scheduler.advance(0.5)
      circuits.each(&:poll)
      while (f = tap.receive)
        sent << f.encode.unpack1("H*")
      end
      circuits[1].stop if clock.now == 20
    end
    [sent, logs.map { |l| l.events.map { |e| [e.time, e.kind, e.data] } }]
  end

  def mac
    Datalink::MAC.new("00:00:00:00:00:0b")
  end

  def three_way(state, **fields)
    ISIS::Tlv::ThreeWayAdjacency.new(state, extended_circuit_id: 7, **fields)
  end

  def hello(source: B_ID, circuit_type: :l1, areas: ["49.0001"], three_way: three_way(:down))
    tlvs = [ISIS::Tlv::AreaAddresses.new(areas), ISIS::Tlv::ProtocolsSupported.new(:ipv4)]
    tlvs << three_way if three_way
    ISIS::Pdu::P2pHello.new(circuit_type: circuit_type, source_id: source, holding_time: 30, local_circuit_id: 1,
                            tlvs: tlvs)
  end
end
