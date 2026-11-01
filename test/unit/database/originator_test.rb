# frozen_string_literal: true

require_relative "../../test_helper"

# This system's LSP, RFC 1142 clauses 7.3.5 to 7.3.7 and 7.3.16. Two
# point to point circuits on a simulated wire, each with its own
# originator, on one manual clock. The TLV expectations are our own
# arithmetic, laid out field by field.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestOriginator < Minitest::Test
  A_ID = "0000.0000.000a"
  B_ID = "0000.0000.000b"

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    TestLogs.heading(name)
    @log_a = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @log_b = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @orig_a, @a = node(A_ID, "00:00:00:00:00:0a", @log_a, "a-eth1",
                       ip_addresses: ["10.0.12.1"], prefixes: [{ prefix: "10.0.12.0/24", metric: 10 }])
    @orig_b, @b = node(B_ID, "00:00:00:00:00:0b", @log_b, "b-eth1", prefixes: [{ prefix: "192.0.2.1/32", metric: 1 }])
  end

  def node(id, mac, log, name, minimum_interval: 5, **opts)
    db = ISIS::Database.new(level: 1, clock: @clock)
    orig = ISIS::Originator.new(system_id: id, database: db, scheduler: @scheduler, log: log,
                                minimum_interval: minimum_interval, **opts)
    circuit = ISIS::P2pCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler,
                                   log: log, name: name, system_id: id, snpa: mac, database: db, originator: orig)
    [orig, circuit]
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      [@a, @b].each(&:poll)
    end
  end

  def start_both
    [@orig_a, @orig_b, @a, @b].each(&:start)
    [@a, @b].each(&:poll)
  end

  def generated(log)
    log.events.select { |e| e.kind == :origination }.map { |e| e.data[:sequence] }
  end

  def own(orig)
    orig.database[orig.lsp_id].lsp
  end

  # Before any adjacency: sequence 1 (7.3.16.1), lifetime MaxAge
  # (7.3.16.3), IS type 1, and TLVs 1, 129, 132 and 135 with no TLV 22.
  #   01 04 03 490001        area 49.0001
  #   81 01 cc               IPv4
  #   84 04 0a000c01         10.0.12.1
  #   87 08 0000000a 18 0a000c   10.0.12.0/24 metric 10
  def test_first_lsp
    @orig_a.start
    lsp = own(@orig_a)
    assert_equal [1, 1200, 1], [lsp.sequence, lsp.lifetime, lsp.is_type]
    assert_equal "0000.0000.000a.00-00", lsp.lsp_id_s
    assert_equal "010403490001" "8101cc" "84040a000c01" "87080000000a180a000c", lsp.tlvs.to_shex
    assert lsp.checksum_ok?
  end

  # Once up, each LSP names the other in TLV 22 at the circuit's metric:
  # 16 0b, 0000000000 0b 00 the neighbour, 00000a metric 10, 00.
  def test_adjacency_up_puts_the_neighbor_in_tlv_22
    start_both
    run_for(10)
    assert @a.up?
    tlv22 = own(@orig_a).tlvs.find { |t| t.is_a?(ISIS::Tlv::ExtendedIsReachability) }
    assert_equal "160b" "00000000000b00" "00000a" "00", tlv22.to_shex
    assert_equal [1, 2], generated(@log_a)
  end

  # Each side ends up holding the other's latest LSP, the one with TLV 22.
  def test_each_side_learns_the_others_lsp
    start_both
    run_for(20)
    b_lsp = @a.database[@orig_b.lsp_id]
    # The held copies have aged, so compare what the checksum covers.
    [[@a, @orig_b], [@b, @orig_a]].each do |circuit, orig|
      held = circuit.database[orig.lsp_id]
      assert_equal [own(orig).sequence, own(orig).checksum], [held.sequence, held.checksum]
      assert_equal own(orig).tlvs.to_shex, held.lsp.tlvs.to_shex
    end
    assert_empty @a.database.entries.select { |e| e.srm.any? || e.ssn.any? }, "nothing left owed"
  end

  # A new LSP sets SRM on a circuit with an adjacency up (7.3.6), and SRM
  # stays set until the neighbour acknowledges it.
  def test_a_new_lsp_sets_srm_on_an_up_circuit
    start_both
    run_for(10)
    @orig_a.prefixes << { prefix: "10.9.0.0/16", metric: 1 }
    @orig_a.changed("a prefix")
    @scheduler.run_until(@clock.now + 6)
    entry = @a.database[@orig_a.lsp_id]
    assert_equal 3, entry.sequence
    assert_includes entry.srm, "a-eth1"
    run_for(5)
    refute_includes entry.srm, "a-eth1"
    assert_equal 3, @b.database[@orig_a.lsp_id].sequence
  end

  # Two events within the minimum interval make one LSP, at the end of it.
  def test_minimum_interval_holds_events_back
    @orig_a.start
    @clock.advance(1)
    @orig_a.prefixes << { prefix: "10.9.0.0/16", metric: 1 }
    @orig_a.changed("one")
    @orig_a.changed("two")
    assert_equal [1], generated(@log_a)
    @scheduler.run_until(@clock.now + 3.9)
    assert_equal [1], generated(@log_a)
    @scheduler.run_until(@clock.now + 0.2)
    assert_equal [1, 2], generated(@log_a)
  end

  # An event that changes nothing makes no new LSP (7.3.6: "re-generate
  # changed LSP(s)").
  def test_unchanged_content_is_not_generated
    @orig_a.start
    @scheduler.run_until(@clock.now + 10)
    @orig_a.changed("nothing moved")
    assert_equal [1], generated(@log_a)
  end

  # 7.3.5: regenerated every maximumLSPGenerationInterval, changed or not,
  # and an event between does not reset that timer (7.3.6).
  def test_refresh
    @orig_a.start
    @scheduler.run_until(@clock.now + 100)
    @orig_a.prefixes << { prefix: "10.9.0.0/16", metric: 1 }
    @orig_a.changed("a prefix")
    @scheduler.run_until(@clock.now + 799)
    assert_equal [1, 2], generated(@log_a)
    @scheduler.run_until(@clock.now + 2)
    assert_equal [1, 2, 3], generated(@log_a)
    @scheduler.run_until(@clock.now + 900)
    assert_equal [1, 2, 3, 4], generated(@log_a)
  end

  # 7.3.16.1: a copy of ours with a higher sequence, from a previous
  # incarnation, moves ours past it at once.
  def test_a_newer_copy_of_ours_moves_the_sequence_past_it
    start_both
    run_for(10)
    stale = ISIS::Pdu::Lsp.new(level: 1, lsp_id: "0000.0000.000a.00-00", lifetime: 1000, sequence: 0x41,
                               tlvs: [ISIS::Tlv::AreaAddresses.new(["49.0001"])])
    assert_equal :newer, @a.receive_lsp(stale)
    assert_equal 0x42, own(@orig_a).sequence
    run_for(10)
    assert_equal 0x42, @b.database[@orig_a.lsp_id].sequence
  end

  # 7.3.16.2: the same sequence with another checksum is regenerated past
  # it too.
  def test_confusion_with_our_own_lsp_regenerates
    @orig_a.start
    copy = ISIS::Pdu::Lsp.new(level: 1, lsp_id: "0000.0000.000a.00-00", lifetime: 1000, sequence: 1, tlvs: [])
    @a.instance_variable_set(:@neighbor, nil)
    assert_equal :confused, @a.receive_lsp(copy)
    assert_equal 2, own(@orig_a).sequence
  end

  # 7.3.15.1 c: an LSP with our ID that we do not generate is refused,
  # since purging it is not implemented; and nothing is generated.
  def test_a_stale_lsp_of_ours_we_do_not_generate_is_refused
    @orig_a.start
    stale = ISIS::Pdu::Lsp.new(level: 1, lsp_id: "0000.0000.000a.00-01", lifetime: 1000, sequence: 9, tlvs: [])
    assert_equal :own, @a.receive_lsp(stale)
    assert_equal [1], generated(@log_a)
  end

  # The smallest LSP here is 36 octets: 27 of header, TLV 1 and TLV 129.
  def test_an_lsp_over_the_budget_raises
    orig, = node("0000.0000.000c", "00:00:00:00:00:0c", @log_a, "c-eth1", buffer_size: 35)
    assert_raises(ISIS::Error) { orig.start }
  end

  # Entries are packed by their encoded size: 9 octets a /32, so 28 fit in
  # one TLV 135's 255 octets and the 29th starts another.
  def test_prefixes_pack_into_repeated_tlvs
    @orig_a.prefixes = (1..29).map { |i| { prefix: "10.1.0.#{i}/32", metric: 1 } }
    @orig_a.start
    reach = own(@orig_a).tlvs.select { |t| t.is_a?(ISIS::Tlv::ExtendedIpReachability) }
    assert_equal [28, 1], reach.map { |t| t.entries.size }
  end
end
