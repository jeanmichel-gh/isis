# frozen_string_literal: true

require_relative "../../test_helper"

# Two IS instances on one simulated wire should form an adjacency and both
# reach :up. Protocol time is a ManualClock, so nothing here waits in real
# time.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestCircuit < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @wire = ISIS::Link::SimulatedWire.new
    @lines = []
    @traces = []
    TestLogs.heading(name)
    @log_a = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock, ->(l, m) { @lines << [l, m] }),
                                    tracer: TestLogs.tracer(@clock, ->(*t) { @traces << t }))
    @a = circuit("0000.0000.0001", "00:00:00:00:00:01", log: @log_a, name: "a-eth0")
    @b = circuit("0000.0000.0002", "00:00:00:00:00:02",
                 log: ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock),
                                             tracer: TestLogs.tracer(@clock)), name: "b-eth0")
    @sid_a = ISIS::SystemId.new("0000.0000.0001")
    @sid_b = ISIS::SystemId.new("0000.0000.0002")
  end

  def circuit(sysid, mac, holding_time: 30, **opts)
    ISIS::Circuit.new(ISIS::Link::SimulatedTransport.new(@wire),
                      system_id: sysid, snpa: mac,
                      holding_time: holding_time, clock: @clock, **opts)
  end

  def adjacency_events
    @log_a.events.select { |e| e.kind == :adjacency }
  end

  def pump(rounds)
    rounds.times do
      @a.send_hello
      @b.send_hello
      @a.poll
      @b.poll
      return true if @a.up? && @b.up?
    end
    false
  end

  def test_both_reach_up
    assert pump(5), "adjacency did not converge"
    assert @a.up?(@sid_b), "A should see B up"
    assert @b.up?(@sid_a), "B should see A up"
  end

  def test_progresses_through_init
    # One exchange: each hears the other, but neither has been listed yet.
    @a.send_hello
    @b.send_hello
    @a.poll
    @b.poll
    assert_equal :init, @a.adjacency_state(@sid_b)
    assert_equal :init, @b.adjacency_state(@sid_a)
  end

  def test_no_adjacency_to_self
    @a.send_hello
    @a.poll # the wire does not echo A's own hello, and A ignores it anyway
    assert_nil @a.adjacency(@sid_a)
    refute @a.up?
  end

  def test_neighbor_snpa_recorded
    pump(5)
    adj = @a.adjacency(@sid_b)
    assert_equal Datalink::MAC.new("00:00:00:00:00:02"), adj.snpa
  end

  # The holding time is B's, carried in its hello (30 s here). Expiry is
  # driven by the injected clock alone, so the test advances it instead of
  # sleeping.
  def test_adjacency_expires_on_protocol_time
    pump(5)
    @clock.advance(30)
    @a.expire_adjacencies
    refute_nil @a.adjacency(@sid_b), "not expired at exactly the holding time"

    @clock.advance(0.001)
    @a.expire_adjacencies
    assert_nil @a.adjacency(@sid_b), "expired just past the holding time"
  end

  def test_a_hello_refreshes_the_adjacency
    pump(5)
    @clock.advance(20)
    @b.send_hello
    @a.poll
    @clock.advance(20) # 40 s since the first hello, 20 s since the last
    @a.expire_adjacencies
    refute_nil @a.adjacency(@sid_b)
  end

  # Each state change is an event, and the log line says why: whether B's
  # TLV 6 listed A's SNPA.
  def test_transitions_are_logged_with_their_reason
    pump(5)
    assert_equal [%i[down init], %i[init up]], adjacency_events.map { |e| [e.data[:from], e.data[:to]] }
    assert_equal ["0000.0000.0002"], adjacency_events.map { |e| e.data[:neighbor] }.uniq
    assert_includes @lines, [:info, "a-eth0 adjacency with 0000.0000.0002 down -> init: " \
                                    "its TLV 6 does not list our SNPA 00:00:00:00:00:01 yet"]
    assert_includes @lines, [:info, "a-eth0 adjacency with 0000.0000.0002 init -> up: " \
                                    "its TLV 6 lists our SNPA 00:00:00:00:00:01"]
  end

  def test_expiry_is_logged_with_the_holding_time
    pump(5)
    @clock.advance(30.001)
    @a.expire_adjacencies
    last = adjacency_events.last
    assert_equal %i[up down expired], [last.data[:from], last.data[:to], last.data[:reason]]
    assert_equal "adjacency with 0000.0000.0002 up -> down: holding time of 30 s expired", last.message
  end

  # Hellos sent and received go to the tracer as the PDU objects.
  def test_hellos_are_traced
    pump(1)
    sent = @traces.find { |t| t[0] == :sent }
    received = @traces.find { |t| t[0] == :received }
    assert_equal ["a-eth0", ISIS::Pdu::LanHello], [sent[1], sent[2].class]
    assert_equal ["a-eth0", "0000.0000.0002", "00:00:00:00:00:02"],
                 [received[1], received[2].source_id_s, received[3]]
  end

  # A hello with two octet IDs is refused, with the reason, and makes no
  # adjacency, since this circuit compares six octet System IDs.
  def test_other_id_length_is_refused_with_a_reason
    hello = ISIS::Pdu::LanHello.new(level: 1, circuit_type: :l1, source_id: "0102", holding_time: 30,
                                    priority: 64, lan_id: "0102.00",
                                    tlvs: [ISIS::Tlv::AreaAddresses.new("49.0001")])
    frame = Datalink::Frame.ieee_802_3(dst: ISIS::Link.all_iss(1), src: Datalink::MAC.new("00:00:00:00:00:09"),
                                       payload: ISIS::Link.llc.wrap(hello.encode))
    assert_nil @a.process(frame)
    assert_empty @a.adjacencies
    refused = @log_a.events.find { |e| e.kind == :refused }
    assert_equal :id_length, refused.data[:reason]
  end

  # With no log given, the circuit still runs and writes nothing.
  def test_runs_with_no_log
    a = circuit("0000.0000.0003", "00:00:00:00:00:03")
    b = circuit("0000.0000.0004", "00:00:00:00:00:04")
    3.times { [a, b].each(&:send_hello); [a, b].each(&:poll) }
    assert a.up?
    assert_equal 2, a.log.events.size
  end
end
