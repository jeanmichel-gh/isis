# frozen_string_literal: true

require_relative "test_helper"

# Two IS instances on one shared loopback wire should form an adjacency
# and both reach :up, with no privileges and no real interface.
class TestAdjacency < Minitest::Test
  def setup
    @wire = Datalink::Backends::Loopback::Wire.new
    @a = circuit("0000.0000.0001", "00:00:00:00:00:01")
    @b = circuit("0000.0000.0002", "00:00:00:00:00:02")
    @sid_a = ISIS::SystemId.new("0000.0000.0001")
    @sid_b = ISIS::SystemId.new("0000.0000.0002")
  end

  def teardown
    @a_sock.close
    @b_sock.close
  end

  def circuit(sysid, mac)
    sock = Datalink::Socket.new("c", backend: :loopback, wire: @wire, recv_timeout: 0.05).open
    case sysid
    when "0000.0000.0001" then @a_sock = sock
    when "0000.0000.0002" then @b_sock = sock
    end
    ISIS::Circuit.new(sock, system_id: sysid, snpa: mac, holding_time: 30)
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
    @a.poll # A's own hello is not echoed back by the hub, and is ignored anyway
    assert_nil @a.adjacency(@sid_a)
    refute @a.up?
  end

  def test_neighbor_snpa_recorded
    pump(5)
    adj = @a.adjacency(@sid_b)
    assert_equal Datalink::MAC.new("00:00:00:00:00:02"), adj.snpa
  end
end
