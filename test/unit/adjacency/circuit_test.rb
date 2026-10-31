# frozen_string_literal: true

require_relative "../../test_helper"

# Two IS instances on one simulated wire should form an adjacency and both
# reach :up. Protocol time is a ManualClock, so nothing here waits in real
# time.
class TestCircuit < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @wire = ISIS::Link::SimulatedWire.new
    @a = circuit("0000.0000.0001", "00:00:00:00:00:01")
    @b = circuit("0000.0000.0002", "00:00:00:00:00:02")
    @sid_a = ISIS::SystemId.new("0000.0000.0001")
    @sid_b = ISIS::SystemId.new("0000.0000.0002")
  end

  def circuit(sysid, mac, holding_time: 30)
    ISIS::Circuit.new(ISIS::Link::SimulatedTransport.new(@wire),
                      system_id: sysid, snpa: mac,
                      holding_time: holding_time, clock: @clock)
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
end
