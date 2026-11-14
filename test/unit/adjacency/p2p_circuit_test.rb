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
    assert(@lines.any? { |l, m| l == :info && m == "a-eth1 adjacency with 0000.0000.000b initializing -> up at Level 1" })
    assert(@lines.any? { |l, m| l == :debug && m.include?("three-way up, received up: accept") })
    directions = @traces.map(&:first).uniq.sort
    assert_equal %i[received sent], directions
    # Hellos, and the CSNP each side sends when the adjacency comes up.
    assert(@traces.all? { |_, circuit, _, _| circuit == "a-eth1" })
    assert_equal [ISIS::Pdu::Csnp, ISIS::Pdu::P2pHello], @traces.map { |t| t[2].class }.uniq.sort_by(&:name)
  end

  # Logging is observation. The same scenario with a debug logger and
  # tracer installed, and with nothing installed, sends the same octets
  # and goes through the same states.
  def test_logging_does_not_change_behaviour
    with = scenario(logger: ->(*) {}, tracer: ->(*) {})
    without = scenario
    assert_equal without, with
  end

  # -- The update process, RFC 1142 clause 7.3.15, on the same wire. --
  #
  # Neither circuit originates an LSP yet, so a test seeds one side's
  # database with an LSP from a third system, as if learned elsewhere.

  THIRD = "0000.0000.00cc.00-00"

  def lsp(sequence: 5, lifetime: 1200, id: THIRD)
    ISIS::Pdu::Lsp.new(level: 1, lsp_id: id, lifetime: lifetime, sequence: sequence,
                       tlvs: [ISIS::Tlv::AreaAddresses.new("49.0001")])
  end

  def seed(circuit, lsp)
    circuit.database.entry(lsp.lsp_id).store(lsp)
  end

  def held(circuit, id = THIRD)
    circuit.database[ISIS::Pdu.lsp_id_octets(id)]
  end

  def up_both
    start_both
    run_for(7)
    assert(@a.up? && @b.up?)
  end

  def sent(type)
    @traces.select { |dir, _, pdu, _| dir == :sent && pdu.is_a?(type) }.map { |t| t[2] }
  end

  # b's CSNP at adjacency up does not mention the LSP a holds, so a sets
  # SRM and sends it (7.3.15.2 c). b stores it, sets SSN (7.3.15.1 e 1) and
  # acknowledges it in a PSNP, which clears a's SRM (7.3.15.2 b 1).
  def test_an_lsp_one_side_holds_reaches_the_other_and_is_acknowledged
    seed(@a, lsp)
    up_both
    run_for(6)
    entry = held(@b)
    refute_nil entry
    assert_equal [5, lsp.checksum], [entry.sequence, entry.checksum]
    assert_empty held(@a).srm, "b's PSNP should have acknowledged it"
    assert_empty entry.ssn, "b's PSNP should have gone out"
    assert(@log_b.events.any? { |e| e.kind == :database && e.data[:lsp_id] == THIRD && e.data[:result] == :new })
  end

  # On a non-broadcast circuit SRM stays set until acknowledged, so with b's
  # PSNPs lost a sends the LSP again every minimumLSPTransmissionInterval.
  def test_an_unacknowledged_lsp_is_sent_again
    seed(@a, lsp)
    @b.level(1).define_singleton_method(:send_psnp) { nil }
    up_both
    first = sent(ISIS::Pdu::Lsp).size
    run_for(11)
    assert_operator sent(ISIS::Pdu::Lsp).size, :>=, first + 2
    refute_empty held(@a).srm
  end

  # Each copy sent has had its Remaining Lifetime counted down, and one
  # more taken off for the hop (7.3.16.3).
  def test_the_lifetime_sent_is_counted_down
    seed(@a, lsp(lifetime: 1200))
    up_both
    sent_lifetime = sent(ISIS::Pdu::Lsp).first.lifetime
    assert_operator sent_lifetime, :<, 1200
    assert_operator sent_lifetime, :>=, 1200 - 8
  end

  # b holds sequence 5, a holds 7. a's CSNP reports 7, newer, so b asks for
  # it (7.3.15.2 b 3); b's reports 5, older, so a sends 7 (b 2).
  def test_the_newer_copy_wins
    seed(@a, lsp(sequence: 7))
    seed(@b, lsp(sequence: 5))
    up_both
    run_for(6)
    assert_equal 7, held(@b).sequence
    assert_equal 7, held(@a).sequence
  end

  # An entry for an LSP b does not hold makes a sequence 0 placeholder, and
  # b's PSNP asks for it with lifetime, sequence and checksum zero, which
  # is the request FRR answers (7.3.15.2 b 4).
  def test_an_unknown_lsp_is_requested_with_a_zero_entry
    up_both
    entry = ISIS::Tlv::LspEntries::Entry.new(1100, ISIS::Pdu.lsp_id_octets(THIRD), 9, 0x1234)
    csnp = ISIS::Pdu::Csnp.new(level: 1, source_id: "0000.0000.000a.00", tlvs: [ISIS::Tlv::LspEntries.new(entry)])
    @b.receive_snp(csnp)
    assert held(@b).placeholder?
    psnp = @b.send_psnp
    # 0000 lifetime, 0000000000cc0000 the LSP ID, 00000000 sequence, 0000
    # checksum.
    assert_equal "0000" "0000000000cc0000" "00000000" "0000", psnp.tlvs.first.to_shex[4..]
  end

  # Clause 7.3.15.2 c directly: a CSNP that does not mention an LSP held in
  # its range sets SRM for it.
  def test_a_csnp_that_omits_an_lsp_sets_srm
    seed(@a, lsp)
    up_both
    held(@a).srm.clear
    @a.receive_snp(ISIS::Pdu::Csnp.new(level: 1, source_id: "0000.0000.000b.00"))
    refute_empty held(@a).srm
  end

  # +n+ LSPs from systems 0000.0000.1001 upwards, each with one TLV.
  def many_lsps(n)
    (1..n).map { |i| lsp(id: format("0000.0000.%04x.00-00", 0x1000 + i)) }
  end

  ALL_ZEROS = "0000.0000.0000.00-00"
  ALL_ONES = "ffff.ffff.ffff.ff-ff"

  # The LSP ID right after +octets+: where a CSNP's next range starts.
  def next_id(octets)
    ISIS::Pdu.lsp_id_s([format("%016x", octets.unpack1("H*").to_i(16) + 1)].pack("H*"))
  end

  # RFC 1142 clause 7.3.15.3 and section 9.10: more LSPs than one CSNP of
  # originatingL1LSPBufferSize octets holds go in "a series of individual
  # CSNPs, each referring to a subset of the complete range", ranges
  # "contiguous" that "cover the entire range of possible LSPIDs".
  def test_a_database_larger_than_one_csnp_is_sent_in_several
    lsps = many_lsps(300)
    lsps.each { |l| seed(@a, l) }
    up_both
    # The set sent at adjacency up (7.3.15.3 b): from the last that starts
    # at the bottom of the range.
    all = sent(ISIS::Pdu::Csnp)
    csnps = all.drop(all.rindex { |c| c.start_lsp_id_s == ALL_ZEROS })
    assert_operator csnps.size, :>, 1, "one CSNP cannot hold 300 entries in 1492 octets"
    csnps.each { |c| assert_operator c.encode.bytesize, :<=, 1492 }
    assert_equal ALL_ZEROS, csnps.first.start_lsp_id_s
    assert_equal ALL_ONES, csnps.last.end_lsp_id_s
    csnps.each_cons(2) { |x, y| assert_equal next_id(x.end_lsp_id), y.start_lsp_id_s, "contiguous" }
    csnps.each do |c|
      c.entries.each { |e| assert (c.start_lsp_id..c.end_lsp_id).cover?(e.lsp_id), "#{ISIS::Pdu.lsp_id_s(e.lsp_id)} in its range" }
    end
    assert_equal lsps.map(&:lsp_id).sort, csnps.flat_map { |c| c.entries.map(&:lsp_id) }.sort
  end

  # The other side, given those CSNPs, holds and asks for nothing more: its
  # database matches, and no LSP is resent for want of a mention.
  def test_several_csnps_leave_nothing_unmentioned
    many_lsps(300).each { |l| seed(@a, l) }
    up_both
    run_for(60)
    assert_equal 300, @b.database.entries.count { |e| !e.placeholder? }
    srm = @a.database.entries.select { |e| e.srm.any? }
    assert_empty srm, "every LSP acknowledged: #{srm.size} still flagged"
  end

  # Clause 7.3.15.4: a PSNP holds "as many ... with SSNflag set as will fit
  # in the PDU", clears SSN for those only, and the next scan "shall
  # commence with the next LSP which was not included in the previous
  # scan".
  def test_a_psnp_holds_what_fits_and_the_next_one_goes_on_from_there
    many_lsps(300).each { |l| seed(@b, l) }
    @b.database.entries.each { |e| e.ssn << @b.name }
    first = @b.send_psnp
    assert_operator first.encode.bytesize, :<=, 1492
    assert_operator first.entries.size, :<, 300
    flagged = @b.database.entries.count { |e| e.ssn.include?(@b.name) }
    assert_equal 300 - first.entries.size, flagged
    second = @b.send_psnp
    assert_operator second.entries.first.lsp_id, :>, first.entries.last.lsp_id, "goes on from the next LSP"
    5.times { @b.send_psnp }
    assert_equal 0, @b.database.entries.count { |e| e.ssn.include?(@b.name) }
    assert_nil @b.send_psnp
  end

  def test_an_older_lsp_received_sends_ours_back
    seed(@a, lsp(sequence: 7))
    up_both
    assert_equal :older, @a.receive_lsp(lsp(sequence: 3))
    refute_empty held(@a).srm
  end

  def test_refusals_say_why
    up_both
    bad = ISIS::Pdu.factory(ISIS::Octets.new(lsp.encode.tap { |o| o[24, 2] = "\xde\xad".b }))
    assert_equal :checksum, @a.receive_lsp(bad)
    assert_equal :id_length, @a.receive_lsp(lsp(id: "0000.0000.0000.000a.00-00"))
    reasons = @log_a.events.select { |e| e.kind == :refused }.map { |e| e.data[:reason] }
    assert_equal %i[checksum id_length], reasons.last(2)
    assert_nil held(@a)
  end

  # Clause 7.3.15 applies to circuits "over which routeing messages are to
  # be exchanged", so with no adjacency up an LSP changes nothing.
  def test_nothing_is_stored_without_an_adjacency
    frame = Datalink::Frame.ieee_802_3(dst: Datalink::MAC.new(ISIS::P2pCircuit::ALL_ISS), src: Datalink::MAC.new("00:00:00:00:00:0b"),
                                       payload: ISIS::Link.llc.wrap(lsp.encode))
    @a.receive_frame(frame)
    assert_nil held(@a)
  end

  # Losing the neighbour clears what was owed to it.
  def test_flags_clear_when_the_adjacency_goes
    seed(@a, lsp)
    @b.level(1).define_singleton_method(:send_psnp) { nil }
    up_both
    refute_empty held(@a).srm
    @b.stop
    run_for(40, circuits: [@a])
    refute @a.up?
    assert_empty held(@a).srm
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

# RFC 5304 HMAC-MD5 on a point to point circuit: hello_key for hellos,
# area_key for LSPs and SNPs. Two circuits, each with its own originator,
# on a simulated wire.
class TestP2pCircuitAuthentication < Minitest::Test
  A_ID = "0000.0000.000a"
  B_ID = "0000.0000.000b"

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    TestLogs.heading(name)
    @traces = []
  end

  def node(id, mac, name, hello_key: nil, area_key: nil)
    log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock),
                                 tracer: TestLogs.tracer(@clock, ->(*t) { @traces << [name, *t] }))
    db = ISIS::Database.new(level: 1, clock: @clock)
    orig = ISIS::Originator.new(system_id: id, database: db, scheduler: @scheduler, log: log, minimum_interval: 1,
                                area_key: area_key)
    circuit = ISIS::P2pCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler,
                                   log: log, name: name, system_id: id, snpa: mac, database: db, originator: orig,
                                   hello_key: hello_key, area_key: area_key)
    [orig, circuit]
  end

  def pair(a: {}, b: {})
    @orig_a, @a = node(A_ID, "00:00:00:00:00:0a", "a-eth1", **a)
    @orig_b, @b = node(B_ID, "00:00:00:00:00:0b", "b-eth1", **b)
    [@orig_a, @orig_b, @a, @b].each(&:start)
    15.times do
      @scheduler.advance(1)
      [@a, @b].each(&:poll)
    end
  end

  def refusals(circuit)
    circuit.log.events.select { |e| e.kind == :refused && e.data[:reason] == :authentication }.map(&:message)
  end

  def received(name, type)
    @traces.select { |n, dir, _, pdu, _| n == name && dir == :received && pdu.is_a?(type) }.map { |t| t[3] }
  end

  # Same keys both sides: up, each holds the other's LSP, and what b
  # received from a checks out under the keys.
  def test_matching_keys
    keys = { hello_key: "hk", area_key: "ak" }
    pair(a: keys, b: keys)
    assert @a.up?
    assert_equal @orig_a.sequence, @b.database[@orig_a.lsp_id].sequence
    assert_equal @orig_b.sequence, @a.database[@orig_b.lsp_id].sequence
    assert received("b-eth1", ISIS::Pdu::P2pHello).last.authentic?("hk")
    assert received("b-eth1", ISIS::Pdu::Lsp).last.authentic?("ak")
    assert received("b-eth1", ISIS::Pdu::Csnp).last.authentic?("ak")
    assert_empty refusals(@a) + refusals(@b)
  end

  # TLV 10 goes first, where FRR 8.4.4 puts it: right after the 20 octets
  # of headers (8 common, 12 point to point hello), 0a 11 36.
  def test_the_authentication_tlv_is_first
    _, c = node(A_ID, "00:00:00:00:00:0a", "a-eth1", hello_key: "hk")
    hello = c.build_hello
    assert_equal "0a1136", hello.to_shex[20 * 2, 6]
    assert ISIS::Pdu.factory(ISIS::Octets.new(hello.encode)).authentic?("hk")
  end

  # Different hello keys: no adjacency, and each side says why.
  def test_mismatched_hello_keys
    pair(a: { hello_key: "one" }, b: { hello_key: "two" })
    refute @a.up?
    refute @b.up?
    assert_match(/HMAC-MD5 digest is wrong/, refusals(@a).first)
    assert_match(/RFC 5304/, refusals(@b).first)
  end

  # A key on one side only: the keyed side refuses unauthenticated hellos
  # (8.2.4.1 c i), and the side with no key checks nothing.
  def test_a_hello_key_on_one_side
    pair(a: { hello_key: "hk" })
    refute @a.up?
    assert_match(/no Authentication Information.*8\.2\.4\.1 c i/, refusals(@a).first)
    assert_empty refusals(@b)
  end

  # Same hello keys, different area keys: up, but neither stores the
  # other's LSP, and the refusals name the LSP.
  def test_mismatched_area_keys
    pair(a: { hello_key: "hk", area_key: "one" }, b: { hello_key: "hk", area_key: "two" })
    assert @a.up?
    assert_nil @b.database[@orig_a.lsp_id]&.lsp
    assert_nil @a.database[@orig_b.lsp_id]&.lsp
    assert(refusals(@b).any? { |m| m.include?("LSP 0000.0000.000a.00-00") })
    assert(refusals(@b).any? { |m| m.start_with?("refused: Csnp") })
  end

  # A cleartext password when HMAC-MD5 is configured is refused under 8.2.4.1 c ii.
  def test_cleartext_is_refused_when_hmac_md5_is_configured
    _, c = node(A_ID, "00:00:00:00:00:0a", "a-eth1", hello_key: "hk")
    hello = ISIS::Pdu::P2pHello.new(circuit_type: :l1, source_id: B_ID, holding_time: 30, local_circuit_id: 1,
                                    tlvs: [ISIS::Tlv::Authentication.new(password: "hk"),
                                           ISIS::Tlv::AreaAddresses.new(["49.0001"])])
    parsed = ISIS::Pdu.factory(ISIS::Octets.new(hello.encode))
    assert_equal :authentication, c.receive_hello(parsed, Datalink::MAC.new("00:00:00:00:00:0b"))
    assert_match(/not HMAC-MD5.*ii/, refusals(c).first)
  end
end
