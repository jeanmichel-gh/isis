# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/fake_bfd"

# BFD on the circuits, RFC 6213 3 and 4 and RFC 5882 4 and 10.1.2, on
# simulated time. Each system has its own Bfd mechanism and a FakeBfd in
# place of bfdd4r, so a test says when a session comes Up or goes Down on
# each side, as bfdd4r would tell each router.
module BfdCircuitTests
  A_ID = "0000.0000.000a"
  B_ID = "0000.0000.000b"
  A_IP = "10.0.12.1"
  B_IP = "10.0.12.2"

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    TestLogs.heading(name)
    @log_a = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @log_b = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @fake_a = FakeBfd.new
    @fake_b = FakeBfd.new
    @bfd_a = ISIS::Bfd.new(client: @fake_a, log: @log_a)
    @bfd_b = ISIS::Bfd.new(client: @fake_b, log: @log_b)
  end

  def run_for(seconds, step: 0.25)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      [@bfd_a, @bfd_b].each { |b| b.poll(@clock.now) }
      @circuits.each(&:poll)
    end
  end

  # Both sessions, A's view and B's, in +state+, as bfdd4r tells each.
  def bfd_both(state)
    @fake_a.tell_all(state)
    @fake_b.tell_all(state)
  end

  def adjacency_events(log)
    log.events.select { |e| e.kind == :adjacency }
  end

  def downs(log)
    adjacency_events(log).select { |e| e.data[:to] == :down }.map { |e| e.data[:reason] }
  end

  def tlv148(hello)
    hello.tlvs.find { |t| t.is_a?(ISIS::Tlv::BfdEnabled) }
  end
end

class TestBfdP2pCircuit < Minitest::Test
  include BfdCircuitTests

  def circuit(id, mac, log, bfd:, ip:, name:, **opts)
    ISIS::P2pCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler, log: log,
                         name: name, system_id: id, snpa: mac, ip_addresses: [ip], bfd: bfd,
                         bfd_interface: "eth1", **opts)
  end

  def build(a: {}, b: {})
    @a = circuit(A_ID, "00:00:00:00:00:0a", @log_a, bfd: @bfd_a, ip: A_IP, name: "a", **a)
    @b = circuit(B_ID, "00:00:00:00:00:0b", @log_b, bfd: @bfd_b, ip: B_IP, name: "b", **b)
    @circuits = [@a, @b]
    @circuits.each(&:start)
  end

  def three_way(circuit)
    circuit.build_hello.tlvs.find { |t| t.is_a?(ISIS::Tlv::ThreeWayAdjacency) }.state
  end

  # RFC 6213 3: TLV 148 in every IIH of a BFD circuit, MTID 0 and IPv4's
  # NLPID: 94 03 0000 cc.
  def test_tlv_148_sent_while_bfdd4r_answers
    build
    assert_equal "94030000cc", tlv148(@a.build_hello).to_shex
  end

  # With IPv6 too, 8e after cc.
  def test_tlv_148_names_ipv6_when_it_runs
    build(a: { protocols: %i[ipv4 ipv6] })
    assert_equal "94060000cc00008e", tlv148(@a.build_hello).to_shex
  end

  # "When sending an IIH on an interface on which BFD is NOT enabled, a
  # router MUST NOT include the BFD-enabled TLV."
  def test_no_tlv_148_without_bfd
    build(a: { bfd: nil })
    assert_nil tlv148(@a.build_hello)
  end

  # bfdd4r away: the system cannot run BFD, so no TLV 148 (RFC 5882 4.1).
  def test_no_tlv_148_while_bfdd4r_is_away
    @fake_a = FakeBfd.new(connected: false)
    @bfd_a = ISIS::Bfd.new(client: @fake_a, log: @log_a)
    build
    assert_nil tlv148(@a.build_hello)
  end

  # bfd_tlv overrides what TLV 148 says, whatever bfdd4r does.
  def test_bfd_tlv_overrides
    @fake_a = FakeBfd.new(connected: false)
    @bfd_a = ISIS::Bfd.new(client: @fake_a, log: @log_a)
    build(a: { bfd_tlv: true }, b: { bfd_tlv: false })
    assert_equal "94030000cc", tlv148(@a.build_hello).to_shex
    assert_nil tlv148(@b.build_hello)
  end

  # RFC 6213 3.2: both send TLV 148, so BFD is required, and the
  # adjacency waits in Initializing for the session; meanwhile the IIHs
  # say Down in TLV 240. The session goes to B's TLV 132 address, from A's.
  def test_required_adjacency_waits_for_bfd
    build
    run_for(10)
    assert_equal :initializing, @a.three_way_state
    assert_equal :initializing, @b.three_way_state
    assert_equal :down, three_way(@a)
    assert @a.bfd_required?(@a.neighbor)
    assert_equal "eth1", @fake_a.wanted.keys.first.first
    assert_equal({ ["eth1", B_IP] => A_IP }, @fake_a.wanted)
    assert_equal({ ["eth1", A_IP] => B_IP }, @fake_b.wanted)
    assert_equal "waiting", @a.bfd_view(@a.neighbor)

    bfd_both(:up)
    run_for(4)
    assert @a.up?
    assert @b.up?
    assert_equal :up, three_way(@a)
    assert_equal "up", @a.bfd_view(@a.neighbor)
  end

  # RFC 5882 10.1.2 and RFC 6213 3.2: Up, then the session fails: Down at
  # once, the hold timer's path with reason bfd, on both.
  def test_failure_takes_the_adjacency_down
    build
    run_for(5)
    bfd_both(:up)
    run_for(4)
    assert @a.up?
    bfd_both(:down)
    run_for(0.25)
    refute @a.up?
    refute @b.up?
    assert_equal [:bfd], downs(@log_a)
    assert_equal [:bfd], downs(@log_b)
    assert_includes @fake_a.calls, [:drop, "eth1", B_IP]
  end

  # RFC 5882 4.2: AdminDown, local or remote, never takes it down.
  def test_admin_down_does_not
    build
    run_for(5)
    bfd_both(:up)
    run_for(4)
    bfd_both(:admin_down)
    run_for(40)
    assert @a.up?, "AdminDown counts as usable, so the hold time is refreshed (RFC 5882 4.1)"
    assert_empty downs(@log_a)
  end

  # Only B's session Up: B is usable and says Initializing, which by RFC
  # 5303's table would bring A Up; A's own session is not, so A waits.
  def test_init_to_up_waits_for_our_own_session
    build
    run_for(5)
    @fake_b.tell_all(:up)
    run_for(5)
    assert_equal :initializing, @a.three_way_state
    @fake_a.tell_all(:up)
    run_for(0.25)
    assert @a.up?, "comes Up on BFD, without waiting for the next hello"
  end

  # A neighbour that sends no TLV 148 is not required, and its adjacency is
  # not blocked (RFC 5882 4.1). With bfdd4r answering, the Up adjacency
  # still has a session, as FRR asks for one, and a failure takes it down
  # (RFC 5882 10.1.2).
  def test_neighbor_without_tlv_148
    build(b: { bfd: nil })
    run_for(7)
    assert @a.up?
    refute @a.bfd_required?(@a.neighbor)
    assert_equal({ ["eth1", B_IP] => A_IP }, @fake_a.wanted)
    @fake_a.tell_all(:up)
    run_for(1)
    assert @a.up?
    @fake_a.tell_all(:down)
    run_for(0.25)
    refute @a.up?
    assert_equal [:bfd], downs(@log_a)
  end

  # Not required, a session that never came Up blocks nothing.
  def test_no_session_does_not_block_an_unrequired_adjacency
    build(b: { bfd: nil })
    run_for(40)
    assert @a.up?
    assert_equal "waiting", @a.bfd_view(@a.neighbor)
  end

  # RFC 6213 4: TLV 148 new on an Up adjacency, so BFD becomes required:
  # the hold time is not refreshed until usable. With BFD never Up, the
  # adjacency goes when its hold time runs out, 30 s, and not at once.
  def test_tlv_148_new_on_an_up_adjacency_freezes_the_hold_time
    build(b: { bfd_tlv: false })
    run_for(7)
    assert @a.up?
    @b.bfd_tlv = nil
    run_for(20)
    assert @a.bfd_required?(@a.neighbor)
    assert @a.up?, "not dropped at once"
    run_for(15)
    refute @a.up?
    assert_equal [:expired], downs(@log_a)
  end

  # The same, with BFD Up in time: the adjacency stays, and its hold time
  # is refreshed again.
  def test_tlv_148_new_and_bfd_up_in_time
    build(b: { bfd_tlv: false })
    run_for(7)
    @b.bfd_tlv = nil
    run_for(10)
    bfd_both(:up)
    run_for(40)
    assert @a.up?
    assert_empty downs(@log_a)
  end

  # :lost: bfdd4r went, so no TLV 148; BFD is no longer required on
  # either end, and the adjacency comes Up on its hellos (RFC 5882 4.1).
  def test_bfdd4r_lost_lets_the_adjacency_up
    build
    run_for(7)
    assert_equal :initializing, @a.three_way_state
    @fake_a.lose
    run_for(7)
    assert_nil tlv148(@a.build_hello)
    assert @a.up?
    assert @b.up?
  end

  # :lost on an Up adjacency takes nothing down.
  def test_bfdd4r_lost_takes_nothing_down
    build
    run_for(5)
    bfd_both(:up)
    run_for(4)
    @fake_a.lose
    @fake_b.lose
    run_for(40)
    assert @a.up?
    assert_empty downs(@log_a)
  end
end

class TestBfdLanCircuit < Minitest::Test
  include BfdCircuitTests

  def circuit(id, mac, log, bfd:, ip:, name:, **opts)
    ISIS::LanCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler, log: log,
                         name: name, system_id: id, snpa: mac, ip_addresses: [ip], bfd: bfd,
                         bfd_interface: "eth1", **opts)
  end

  def build(a: {}, b: {})
    @a = circuit(A_ID, "00:00:00:00:00:0a", @log_a, bfd: @bfd_a, ip: A_IP, name: "a", **a)
    @b = circuit(B_ID, "00:00:00:00:00:0b", @log_b, bfd: @bfd_b, ip: B_IP, name: "b", **b)
    @circuits = [@a, @b]
    @circuits.each(&:start)
  end

  def listed(circuit)
    tlv = circuit.build_hello.tlvs.find { |t| t.is_a?(ISIS::Tlv::IsNeighbors) }
    tlv ? tlv.to_hash.map(&:to_s) : []
  end

  def state(circuit)
    circuit.neighbors.values.first&.state
  end

  def test_tlv_148_in_lan_hellos
    build
    assert_equal "94030000cc", tlv148(@a.build_hello).to_shex
  end

  # RFC 6213 3.2: required and not usable, the neighbour's MAC is left out
  # of TLV 6, and Init to Up waits; once usable, both come Up.
  def test_required_adjacency_waits_and_is_not_listed
    build
    run_for(10)
    assert_equal :initializing, state(@a)
    assert_empty listed(@a)
    assert_equal({ ["eth1", B_IP] => A_IP }, @fake_a.wanted)

    bfd_both(:up)
    run_for(4)
    assert_equal :up, state(@a)
    assert_equal :up, state(@b)
    assert_equal ["00:00:00:00:00:0b"], listed(@a)
  end

  def test_failure_takes_the_adjacency_down
    build
    run_for(5)
    bfd_both(:up)
    run_for(4)
    assert_equal :up, state(@a)
    bfd_both(:down)
    run_for(0.25)
    assert_equal [:bfd], downs(@log_a)
    assert_equal [:bfd], downs(@log_b)
  end

  def test_admin_down_does_not
    build
    run_for(5)
    bfd_both(:up)
    run_for(4)
    bfd_both(:admin_down)
    run_for(40)
    assert_equal :up, state(@a)
    assert_empty downs(@log_a)
  end

  # Only B's session Up: B lists A, which would bring A Up (RFC 1142
  # 8.4.1.5); A's own session is not, so A waits.
  def test_init_to_up_waits_for_our_own_session
    build
    run_for(5)
    @fake_b.tell_all(:up)
    run_for(5)
    assert_equal ["00:00:00:00:00:0a"], listed(@b)
    assert_equal :initializing, state(@a)
    @fake_a.tell_all(:up)
    run_for(0.25)
    assert_equal :up, state(@a)
  end

  # Without TLV 148 from the neighbour: Up on hellos, a session once Up,
  # and down on its failure.
  def test_neighbor_without_tlv_148
    build(b: { bfd: nil })
    run_for(7)
    assert_equal :up, state(@a)
    assert_equal({ ["eth1", B_IP] => A_IP }, @fake_a.wanted)
    @fake_a.tell_all(:up)
    run_for(0.5)
    @fake_a.tell_all(:down)
    run_for(0.25)
    assert_equal [:bfd], downs(@log_a)
  end

  # RFC 6213 4 on a LAN: the hold time of an Up adjacency is not refreshed
  # while TLV 148 is new and BFD not usable.
  def test_tlv_148_new_on_an_up_adjacency_freezes_the_hold_time
    build(b: { bfd_tlv: false })
    run_for(7)
    assert_equal :up, state(@a)
    @b.bfd_tlv = nil
    run_for(20)
    refute_nil state(@a), "not dropped at once"
    run_for(15)
    assert_includes downs(@log_a), :expired
  end
end
