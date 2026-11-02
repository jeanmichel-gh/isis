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

  # The adjacency leaves Up by the neighbour's TLV 240, not by A's own
  # holding timer: B stops reading, its timer expires, and its next hello
  # says so. A's LSP drops B from TLV 22 (7.3.6).
  def test_leaving_up_by_the_neighbours_hello_takes_it_out_of_tlv_22
    start_both
    run_for(10)
    35.times do
      @scheduler.advance(1)
      @a.poll
    end
    refute @a.up?
    refute own(@orig_a).tlvs.any? { |t| t.is_a?(ISIS::Tlv::ExtendedIsReachability) }
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

  # With a key the LSP carries TLV 10 first and its digest checks out, and
  # an event that changes nothing still makes no new LSP.
  def test_area_key
    @orig_a.area_key = "ak"
    @orig_a.start
    lsp = ISIS::Pdu.factory(ISIS::Octets.new(own(@orig_a).encode))
    assert_equal 10, lsp.tlvs.first.type
    assert lsp.authentic?("ak")
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

  # 7.3.15.1 c: an LSP with our ID that we do not generate is purged
  # network wide at its own sequence, and nothing is generated.
  def test_a_stale_lsp_of_ours_we_do_not_generate_is_purged
    @orig_a.start
    stale = ISIS::Pdu::Lsp.new(level: 1, lsp_id: "0000.0000.000a.00-01", lifetime: 1000, sequence: 9, tlvs: [])
    assert_equal :purged, @a.receive_lsp(stale)
    held = @a.database[stale.lsp_id]
    assert_equal [9, 0], [held.sequence, held.remaining_lifetime]
    assert_equal 0, held.lsp.tlvs.size
    assert_equal [1], generated(@log_a)
  end

  # The smallest LSP here is 36 octets: 27 of header, TLV 1 and TLV 129.
  # Narrow: TLV 2 and TLV 128 in place of 22 and 135.
  #   02 0c 00 0a808080 00000000000b00   virtual flag 0, metric 10, neighbour b
  #   80 0c 0a808080 0a000c00 ffffff00   10.0.12.0/24 metric 10
  def test_narrow_metric_style
    @orig_a.metric_style = :narrow
    start_both
    run_for(10)
    tlvs = own(@orig_a).tlvs
    assert_equal [1, 129, 132, 2, 128], tlvs.map(&:type)
    assert_equal "020c" "00" "0a808080" "00000000000b00", tlvs.find { |t| t.type == 2 }.to_shex
    assert_equal "800c" "0a808080" "0a000c00" "ffffff00", tlvs.find { |t| t.type == 128 }.to_shex
  end

  # Transition sends both, narrow first.
  def test_transition_metric_style
    @orig_a.metric_style = :transition
    start_both
    run_for(10)
    assert_equal [1, 129, 132, 2, 128, 22, 135], own(@orig_a).tlvs.map(&:type)
  end

  # A metric the six bits cannot hold cannot go out narrow.
  def test_a_wide_only_metric_cannot_go_narrow
    @orig_a.metric_style = :narrow
    @orig_a.prefixes = [{ prefix: "10.0.12.0/24", metric: 64 }]
    assert_raises(ArgumentError) { @orig_a.start }
  end

  # The Virtual Flag octet counts against each TLV 2's 255: 1 + 23 * 11 is
  # 254, so a 24th neighbour would start a second TLV.
  def test_tlv_2_packing_counts_the_virtual_flag
    # Stand-in circuits, each answering one neighbour at metric 1.
    circuit = Struct.new(:is_neighbor) { def flood(_) = nil }
    (1..24).each { |i| @orig_a.attach(circuit.new([["0000000000%02x00" % i].pack("H*"), 1])) }
    @orig_a.metric_style = :narrow
    @orig_a.prefixes = []
    @orig_a.start
    assert_equal [23, 1], own(@orig_a).tlvs.select { |t| t.type == 2 }.map { |t| t.entries.size }
  end

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

# The originator at Level 2, decided by its database.
class TestOriginatorLevel2 < Minitest::Test
  # With a Level 2 database the LSP is a Level 2 LSP: PDU type 20 in the
  # fifth octet of the common header (RFC 1142 9.9) and IS type 3 in the
  # flags octet, "In a Level 2 Link State PDU, IS Type shall be 3". The
  # flags octet is the last of the 27 octet fixed header.
  def test_a_level_2_database_makes_level_2_lsps
    clock = ISIS::Runtime::ManualClock.new
    scheduler = ISIS::Runtime::Scheduler.new(clock)
    db = ISIS::Database.new(level: 2, clock: clock)
    orig = ISIS::Originator.new(system_id: "0000.0000.000a", database: db, scheduler: scheduler,
                                log: ISIS::Runtime::Log.new(clock: clock))
    assert_equal 2, orig.level
    hex = orig.build(sequence: 1).to_shex
    assert_equal "14", hex[8, 2]
    assert_equal "03", hex[52, 2]
  end
end

# Clause 7.2.11: a Level 2 LSP of a system at both levels lists the union
# of the area addresses in the Level 1 LSPs with LSP Number 0. No
# circuits: two databases and two originators on a manual clock, and other
# systems' Level 1 LSPs stored straight into the Level 1 database. The
# TLV 1 expectations are our own arithmetic: type 01, length, then each
# area as a length octet and its octets.
class TestOriginatorAreaAddresses < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock))
    @l1 = ISIS::Database.new(level: 1, clock: @clock)
    @l2 = ISIS::Database.new(level: 2, clock: @clock)
    @orig1 = ISIS::Originator.new(system_id: "0000.0000.000a", database: @l1, scheduler: @scheduler, log: @log,
                                  minimum_interval: 5, is_type: 3, level1_database: @l1)
    @orig2 = ISIS::Originator.new(system_id: "0000.0000.000a", database: @l2, scheduler: @scheduler, log: @log,
                                  minimum_interval: 5, is_type: 3, level1_database: @l1)
  end

  # Another system's Level 1 LSP with +areas+ in TLV 1, at LSP Number +number+.
  def store_l1(system, areas, number: 0, sequence: 1)
    id = ISIS::Pdu.dotted_octets(system) + [0, number].pack("CC")
    lsp = ISIS::Pdu::Lsp.new(level: 1, lsp_id: ISIS::Octets.new(id), lifetime: 1200, sequence: sequence,
                             tlvs: [ISIS::Tlv::AreaAddresses.new(areas), ISIS::Tlv::ProtocolsSupported.new([:ipv4])])
    @l1.entry(id).store(lsp)
  end

  def area_tlv(orig)
    orig.database[orig.lsp_id].lsp.tlvs.find { |t| t.is_a?(ISIS::Tlv::AreaAddresses) }.to_shex
  end

  def start
    [@orig1, @orig2].each(&:start)
  end

  #   01 08  03 490001  03 490002
  def test_the_level_2_lsp_lists_the_union
    store_l1("0000.0000.000b", ["49.0002"])
    start
    assert_equal "01080349000103490002", area_tlv(@orig2)
  end

  # The Level 1 LSP keeps the manual areas, Level 1 database or not:
  # 01 04 03 490001.
  def test_the_level_1_lsp_lists_the_manual_areas
    store_l1("0000.0000.000b", ["49.0002"])
    start
    assert_equal "010403490001", area_tlv(@orig1)
  end

  # "Level 1 LSPs with LSP number zero": an LSP Number 1 with TLV 1, which
  # 7.3.4 forbids, does not count.
  def test_only_lsp_number_zero_counts
    store_l1("0000.0000.000b", ["49.0002"], number: 1)
    start
    assert_equal "010403490001", area_tlv(@orig2)
  end

  # Areas already listed are not listed twice: 01 08 03 490001 03 490002.
  def test_an_area_is_listed_once
    store_l1("0000.0000.000b", %w[49.0002 49.0001])
    store_l1("0000.0000.000c", ["49.0002"])
    start
    assert_equal "01080349000103490002", area_tlv(@orig2)
  end

  # A Level 1 LSP stored after start changes the content, so a new Level 2
  # LSP goes out, no sooner than the minimum interval (7.3.6).
  def test_a_new_area_generates_the_level_2_lsp_again
    start
    assert_equal 1, @orig2.sequence
    store_l1("0000.0000.000b", ["49.0002"])
    @scheduler.advance(6)
    assert_equal 2, @orig2.sequence
    assert_equal "01080349000103490002", area_tlv(@orig2)
  end

  # A Level 1 LSP that brings no new area changes nothing.
  def test_an_lsp_with_known_areas_generates_nothing
    start
    store_l1("0000.0000.000b", ["49.0001"])
    @scheduler.advance(6)
    assert_equal 1, @orig2.sequence
  end

  # A purge keeps the header alone, so its areas leave the union.
  def test_a_purge_takes_its_areas_out
    entry = store_l1("0000.0000.000b", ["49.0002"])
    start
    @l1.purge(entry, "test")
    @scheduler.advance(6)
    assert_equal 2, @orig2.sequence
    assert_equal "010403490001", area_tlv(@orig2)
  end

  # Over maximumAreaAddresses, three, the lowest are kept (7.1.5), and a
  # manual area dropped is reported. 49.0001 is the highest of the four
  # here, so it goes: 01 0c 03 390001 03 390002 03 390003.
  def test_only_the_three_lowest_are_kept
    store_l1("0000.0000.000b", %w[39.0003 39.0001])
    store_l1("0000.0000.000c", ["39.0002"])
    start
    assert_equal "010c033900010339000203390003", area_tlv(@orig2)
    dropped = @log.events.select { |e| e.kind == :manual_address_dropped }
    assert_equal 1, dropped.size
    assert_match(/49\.0001/, dropped.first.message)
  end

  # Clause 7.1.5 pads the shorter with zeros: 49 sorts before 49.0001,
  # which sorts before 4a, though 4a is shorter.
  def test_comparison_pads_with_trailing_zeros
    areas = %w[4a 49.0001 49].map { |a| ISIS::AreaAddress.new(a) }
    sorted = areas.sort { |a, b| ISIS::Originator.compare_areas(a, b) }
    assert_equal %w[49 49.0001 4a], sorted.map(&:to_s)
  end
end


# Several LSP Numbers, RFC 1142 clause 7.3.4. No circuits: the database
# and the originator alone, on a manual clock.
class TestOriginatorLspNumbers < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @db = ISIS::Database.new(level: 1, clock: @clock, scheduler: @scheduler, log: @log)
    @orig = ISIS::Originator.new(system_id: "0000.0000.000a", database: @db, scheduler: @scheduler, log: @log,
                                 buffer_size: 300, minimum_interval: 1, prefixes: prefixes(60))
  end

  def prefixes(count, from: 1)
    (from...(from + count)).map { |i| { prefix: "10.1.#{i / 256}.#{i % 256}/32", metric: 1 } }
  end

  def held(number)
    @db[@orig.lsp_id(number)]
  end

  def prefixes_in(number)
    held(number).lsp.tlvs.select { |t| t.is_a?(ISIS::Tlv::ExtendedIpReachability) }.flat_map(&:to_hash)
                .map { |e| e[:prefix] }
  end

  # 60 /32s at 9 octets each are TLV 135s of 28, 28 and 4 entries: 254,
  # 254 and 38 octets. LSP 0 holds the 27 octet header, TLV 1 (6) and TLV
  # 129 (3), 36, and the first TLV 135: 290. The second does not fit
  # beside it under 300, so LSP 1 has it, 281, and LSP 2 the last, 65.
  # Worked out here, by the octet.
  def test_content_spills_into_more_lsp_numbers
    @orig.start
    assert_equal [0, 1, 2], @orig.numbers
    assert_equal [290, 281, 65], [0, 1, 2].map { |n| held(n).lsp.encode.bytesize }
    assert_equal [1, 1, 1], [0, 1, 2].map { |n| held(n).sequence }
    # TLV 1 only in LSP 0 (7.3.4 a).
    assert_equal [true, false, false], [0, 1, 2].map { |n| held(n).lsp.tlvs.any? { |t| t.type == 1 } }
    assert_equal prefixes(60).map { |p| p[:prefix] }, [0, 1, 2].flat_map { |n| prefixes_in(n) }
    assert @orig.generates?(@orig.lsp_id(2))
    refute @orig.generates?(@orig.lsp_id(3))
  end

  # One more prefix changes only the last LSP: it alone is generated
  # again, at sequence 2 (7.3.4: "It is not required to reissue the
  # unchanged LSPs").
  def test_a_change_regenerates_only_the_lsp_it_touches
    @orig.start
    @orig.prefixes += prefixes(1, from: 500)
    @scheduler.advance(2)
    @orig.changed("test")
    assert_equal [1, 1, 2], [0, 1, 2].map { |n| held(n).sequence }
  end

  # Fewer prefixes need fewer LSPs: the last is purged, kept as a header
  # with lifetime 0, and no longer generated.
  def test_an_lsp_number_no_longer_needed_is_purged
    @orig.start
    @orig.prefixes = prefixes(30)
    @scheduler.advance(2)
    @orig.changed("test")
    assert_equal [0, 1], @orig.numbers
    assert held(2).purged?
    refute @orig.generates?(@orig.lsp_id(2))
    assert(@log.events.any? { |e| e.kind == :purge && e.message.include?("LSP Number 2 is no longer needed") })
  end

  # A newer copy of LSP 1 moves LSP 1's sequence past it, and leaves the
  # others alone (7.3.16.1: the sequences per LSP Number "are
  # independent").
  def test_a_newer_copy_moves_only_its_own_sequence
    @orig.start
    newer = ISIS::Pdu::Lsp.new(level: 1, lsp_id: @orig.lsp_id_s(1), lifetime: 1000, sequence: 9, tlvs: [])
    assert_equal :regenerated, @orig.receive_own(:newer, newer)
    assert_equal [1, 10, 1], [0, 1, 2].map { |n| held(n).sequence }
  end

  # Content that fits one LSP stays in LSP 0.
  def test_one_lsp_when_it_fits
    @orig.prefixes = prefixes(3)
    @orig.start
    assert_equal [0], @orig.numbers
  end

  # What an originator asks of a circuit, recording what the database
  # held at each flood.
  class Recorder
    attr_reader :seen

    def initialize(db, ids)
      @db = db
      @ids = ids
      @seen = []
    end

    def is_neighbor
      nil
    end

    def flood(_entry)
      @seen << @ids.map { |id| @db[id]&.sequence }
    end
  end

  # Clause 7.3.4: the SRM flags of LSPs generated together "shall be set as
  # an atomic action". Every LSP is stored before the first is flooded, so
  # each flood already sees all three at their new sequence.
  def test_all_lsps_are_stored_before_any_is_flooded
    recorder = Recorder.new(@db, [0, 1, 2].map { |n| @orig.lsp_id(n) })
    @orig.attach(recorder)
    @orig.start
    assert_equal [[1, 1, 1]] * 3, recorder.seen
  end
end


# The LSP Database Overload bit, RFC 1142 7.3.19.1, in LSP Number 0 only.
# No circuits: a database and an originator on a manual clock. OL is 0x04
# in the flags octet, the last of the 27 octet fixed header (RFC 1142 9.8,
# asserted mask by mask in the LSP's own tests).
class TestOriginatorOverload < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock))
    @db = ISIS::Database.new(level: 1, clock: @clock)
    prefixes = (1..60).map { |i| { prefix: "198.18.0.#{i}/32", metric: 1 } }
    @orig = ISIS::Originator.new(system_id: "0000.0000.000a", database: @db, scheduler: @scheduler, log: @log,
                                 minimum_interval: 5, buffer_size: 300, prefixes: prefixes)
  end

  def flags(number)
    @db[@orig.lsp_id(number)].lsp.encode.getbyte(26)
  end

  # Set from the start: LSP 0 carries OL, the others do not. IS type 1.
  def test_overload_is_in_lsp_number_zero_only
    @orig = ISIS::Originator.new(system_id: "0000.0000.000a", database: @db, scheduler: @scheduler, log: @log,
                                 buffer_size: 300, prefixes: (1..60).map { |i| { prefix: "198.18.0.#{i}/32", metric: 1 } },
                                 overload: true)
    @orig.start
    assert_equal [0, 1, 2], @orig.numbers
    assert_equal [0x05, 0x01, 0x01], @orig.numbers.map { |n| flags(n) }
  end

  # Set after start: LSP 0 is generated again with OL, no sooner than the
  # minimum interval, and the other LSP Numbers are not (7.3.4), since
  # their content did not change. Cleared, it goes again.
  def test_setting_and_clearing_regenerates_lsp_zero
    @orig.start
    @scheduler.advance(10)
    @orig.overload = true
    @scheduler.advance(6)
    assert_equal [2, 1, 1], @orig.numbers.map { |n| @orig.sequence(n) }
    assert_equal 0x05, flags(0)
    @orig.overload = false
    @scheduler.advance(6)
    assert_equal [3, 1, 1], @orig.numbers.map { |n| @orig.sequence(n) }
    assert_equal 0x01, flags(0)
  end

  # Before start, setting it generates nothing.
  def test_setting_before_start_generates_nothing
    @orig.overload = true
    @scheduler.advance(10)
    assert_nil @db[@orig.lsp_id]
  end
end
