# frozen_string_literal: true

require_relative "../../test_helper"

# LAN circuits on one simulated broadcast wire, on one manual clock. RFC
# 1142 clauses 8.4.1 to 8.4.4.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestLanCircuit < Minitest::Test
  IDS = { a: "0000.0000.000a", b: "0000.0000.000b", c: "0000.0000.000c" }.freeze
  MACS = { a: "00:00:00:00:00:0a", b: "00:00:00:00:00:0b", c: "00:00:00:00:00:0c" }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    @circuits = {}
    TestLogs.heading(name)
  end

  def circuit(who, **opts)
    log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @circuits[who] = ISIS::LanCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire),
                                          scheduler: @scheduler, log: log, name: "#{who}-eth0",
                                          system_id: IDS.fetch(who), snpa: MACS.fetch(who), **opts)
  end

  def run_for(seconds, step: 0.25)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @circuits.each_value(&:poll)
    end
  end

  def start(*who)
    who.each { |w| @circuits.fetch(w).start }
    @circuits.each_value(&:poll)
  end

  def states(c)
    c.neighbors.values.to_h { |n| [n.system_id_s, n.state] }
  end

  def dis_events(c)
    c.log.events.select { |e| e.kind == :dis }
  end

  # Clause 8.4.1.5: initialising on the first hello, Up once the neighbour
  # lists our LAN address.
  # RFC 5308 section 3: hellos carry the link-local IPv6 address in TLV
  # 232, and the neighbour keeps it, for the next hops of IPv6 routes.
  def test_hellos_carry_the_link_local_ipv6_address
    circuit(:a, ipv6_addresses: ["fe80::a"])
    circuit(:b, ipv6_addresses: ["fe80::b"])
    start(:a, :b)
    run_for(3)
    assert_equal [["fe80::b"]], @circuits[:a].neighbors.values.map(&:ipv6_addresses)
  end

  def test_two_systems_come_up
    circuit(:a)
    circuit(:b)
    start(:a, :b)
    run_for(4)
    assert_equal({ "0000.0000.000b" => :up }, states(@circuits[:a]))
    assert_equal({ "0000.0000.000a" => :up }, states(@circuits[:b]))
    transitions = @circuits[:a].log.events.select { |e| e.kind == :adjacency }.map { |e| [e.data[:from], e.data[:to]] }
    assert_equal [%i[down initializing], %i[initializing up]], transitions
  end

  # Clause 8.4.1: the hello lists the LAN addresses of its neighbours in
  # TLV 6, Initialising or Up: 06 06 00000000000b.
  def test_the_hello_lists_neighbours
    circuit(:a)
    circuit(:b)
    start(:a, :b)
    run_for(1)
    tlv6 = @circuits[:a].build_hello.tlvs.find { |t| t.is_a?(ISIS::Tlv::IsNeighbors) }
    assert_equal "0606" "00000000000b", tlv6.to_shex
  end

  # Clause 8.4.4: no election for iSISHelloTimer * 2 seconds, and none
  # without an Up adjacency, so until then the LAN ID is our own with the
  # Local Circuit ID: 0000.0000.000a.01.
  def test_no_dis_before_the_wait_or_alone
    circuit(:a)
    start(:a)
    run_for(10)
    assert_nil @circuits[:a].dis
    assert_equal "0000.0000.000a.01", @circuits[:a].build_hello.lan_id_s
    assert_empty dis_events(@circuits[:a])
  end

  # Two systems Up within a second still elect nothing until
  # iSISHelloTimer * 2, 6 s, has passed since each started.
  def test_the_election_waits_even_with_an_up_neighbour
    circuit(:a)
    circuit(:b)
    start(:a, :b)
    run_for(5)
    assert_equal({ "0000.0000.000b" => :up }, states(@circuits[:a]))
    assert_nil @circuits[:a].dis
    assert_nil @circuits[:b].dis
    run_for(1.5)
    assert @circuits[:b].dis?
  end

  # Equal priority: the highest LAN address wins, so c. Every system
  # agrees, and the others report c's LAN ID.
  def test_highest_mac_breaks_a_priority_tie
    %i[a b c].each { |w| circuit(w) }
    start(:a, :b, :c)
    run_for(10)
    assert @circuits[:c].dis?
    %i[a b].each do |w|
      assert_equal "0000.0000.000c", @circuits[w].dis.system_id_s
      assert_equal "0000.0000.000c.01", @circuits[w].build_hello.lan_id_s
    end
    assert_equal "0000.0000.000c.01", @circuits[:c].build_hello.lan_id_s
  end

  # Priority comes before the address: a at 100 beats c at 64.
  def test_priority_wins
    circuit(:a, priority: 100)
    circuit(:b)
    circuit(:c)
    start(:a, :b, :c)
    run_for(10)
    assert @circuits[:a].dis?
    assert_equal "0000.0000.000a", @circuits[:c].dis.system_id_s
  end

  # A DIS sends hellos every dRISISHelloTimer, 1 s, with a holding time of
  # 10 times that; the others every iSISHelloTimer, 3 s, holding 30.
  def test_the_dis_hellos_faster
    circuit(:a)
    circuit(:b)
    start(:a, :b)
    run_for(10)
    assert_equal [10, 30], [@circuits[:b].holding_time, @circuits[:a].holding_time]
  end

  # The DIS goes silent: the others expire it after its holding time and
  # elect again, so the DIS changes and every system agrees on the new one.
  def test_a_dis_that_goes_silent_is_replaced
    %i[a b c].each { |w| circuit(w) }
    start(:a, :b, :c)
    run_for(10)
    assert @circuits[:c].dis?
    @circuits.delete(:c).stop.transport.close
    run_for(12)
    assert @circuits[:b].dis?
    assert_equal "0000.0000.000b", @circuits[:a].dis.system_id_s
    assert_equal "0000.0000.000b.01", @circuits[:a].build_hello.lan_id_s
    election = dis_events(@circuits[:a]).select { |e| e.message.start_with?("Level 1 DIS") }.last
    assert_match(/0000\.0000\.000c .* -> 0000\.0000\.000b/, election.message)
    # b's first hello after the change still carried c's LAN ID, until b
    # elected itself, so a's LAN ID followed in a second step.
    assert_match(/LAN ID 0000\.0000\.000c\.01 -> 0000\.0000\.000b\.01/, dis_events(@circuits[:a]).last.message)
  end

  # A priority change moves the DIS without anyone going down.
  def test_a_priority_change_moves_the_dis
    %i[a b].each { |w| circuit(w) }
    start(:a, :b)
    run_for(10)
    assert @circuits[:b].dis?
    @circuits[:a].priority = 100
    run_for(5)
    assert @circuits[:a].dis?
    refute @circuits[:b].dis?
    assert_equal "0000.0000.000a.01", @circuits[:b].build_hello.lan_id_s
  end

  # Clause 8.4.1.2: a Level 1 hello with no area in common makes no
  # adjacency, and the log says why.
  def test_no_area_in_common
    circuit(:a)
    circuit(:b, areas: ["49.0002"])
    start(:a, :b)
    run_for(4)
    assert_empty @circuits[:a].neighbors
    assert(@circuits[:a].log.events.any? { |e| e.kind == :refused && e.message.include?("8.4.1.2") })
  end

  # Clause 8.4.1.3: Level 2 accepts the adjacency whatever the areas, and
  # a Level 1 circuit ignores Level 2 hellos.
  def test_level_2
    circuit(:a, level: 2)
    circuit(:b, level: 2, areas: ["49.0002"])
    circuit(:c)
    start(:a, :b, :c)
    run_for(4)
    assert_equal({ "0000.0000.000b" => :up }, states(@circuits[:a]))
    assert_empty @circuits[:c].neighbors
  end

  # Clause 8.4.1.5: a neighbour that stops listing us goes back to
  # initialising.
  def test_a_neighbour_that_stops_listing_us
    circuit(:a)
    circuit(:b)
    start(:a, :b)
    run_for(4)
    hello = ISIS::Pdu::LanHello.new(level: 1, circuit_type: :l1, source_id: IDS[:b], holding_time: 30, priority: 64,
                                    lan_id: "#{IDS[:b]}.01", tlvs: [ISIS::Tlv::AreaAddresses.new(["49.0001"])])
    @circuits[:a].receive_hello(hello, Datalink::MAC.new(MACS[:b]))
    assert_equal({ "0000.0000.000b" => :initializing }, states(@circuits[:a]))
  end

  def test_hello_keys
    circuit(:a, hello_key: "k")
    circuit(:b, hello_key: "k")
    circuit(:c, hello_key: "other")
    start(:a, :b, :c)
    run_for(4)
    assert_equal({ "0000.0000.000b" => :up }, states(@circuits[:a]))
    assert(@circuits[:c].log.events.any? { |e| e.kind == :refused && e.data[:reason] == :authentication })
  end
end

# The update process on a LAN, RFC 1142 clause 7.3.15 for a broadcast
# circuit, and the pseudonode LSP of clause 7.3.8. Each system has an
# Originator, so the databases hold real LSPs: each system's own, and the
# DIS's pseudonode.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestLanUpdate < Minitest::Test
  IDS = TestLanCircuit::IDS
  MACS = TestLanCircuit::MACS
  THIRD = "0000.0000.00cc.00-00"

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    @circuits = {}
    @originators = {}
    @sent = Hash.new { |h, k| h[k] = [] }
    TestLogs.heading(name)
  end

  def node(who, metric_style: :wide, level: 1, **opts)
    sent = @sent[who]
    log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock),
                                 tracer: TestLogs.tracer(@clock, lambda { |dir, _c, pdu, _p|
                                   sent << [@clock.now, pdu] if dir == :sent
                                 }))
    database = ISIS::Database.new(level: level, clock: @clock, scheduler: @scheduler, log: log)
    @originators[who] = ISIS::Originator.new(system_id: IDS.fetch(who), database: database, scheduler: @scheduler,
                                             log: log, metric_style: metric_style, minimum_interval: 1)
    @circuits[who] = ISIS::LanCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire),
                                          scheduler: @scheduler, log: log, name: "#{who}-eth0",
                                          system_id: IDS.fetch(who), snpa: MACS.fetch(who), database: database,
                                          originator: @originators[who], level: level, **opts)
  end

  def start(*who)
    who.each do |w|
      @originators.fetch(w).start
      @circuits.fetch(w).start
    end
  end

  def run_for(seconds, step: 0.25)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @circuits.each_value(&:poll)
    end
  end

  # What a database holds, as LSP ID => sequence, without placeholders.
  def held(who)
    @circuits.fetch(who).database.entries.reject(&:placeholder?).to_h { |e| [e.lsp_id_s, e.sequence] }
  end

  def purged?(who, lsp_id)
    @circuits.fetch(who).database[ISIS::Pdu.lsp_id_octets(lsp_id)]&.purged?
  end

  def sent(who, type)
    @sent[who].select { |_, pdu| pdu.is_a?(type) }
  end

  def lsp(sequence: 5, id: THIRD)
    ISIS::Pdu::Lsp.new(level: 1, lsp_id: id, lifetime: 1200, sequence: sequence,
                       tlvs: [ISIS::Tlv::AreaAddresses.new("49.0001")])
  end

  # The IS reachability TLVs of the LSP +who+ holds under +lsp_id+, as
  # stored, so what was generated and not what would be.
  def stored_is_reachability(who, lsp_id)
    lsp = @circuits.fetch(who).database[ISIS::Pdu.lsp_id_octets(lsp_id)].lsp
    lsp.tlvs.select { |t| t.is_a?(ISIS::Tlv::ExtendedIsReachability) }
  end

  def seed(who, lsp)
    @circuits.fetch(who).database.entry(lsp.lsp_id).store(lsp)
  end

  def up(*who)
    start(*who)
    run_for(10)
    assert @circuits[who.first].dis, "no DIS elected"
  end

  # Equal priorities, so b, the higher LAN address, is DIS. Both databases
  # end up with the same three LSPs at the same sequences: a's, b's, and
  # b's pseudonode, 0000.0000.000b.01-00.
  def test_the_databases_agree
    node(:a)
    node(:b)
    up(:a, :b)
    run_for(5)
    assert @circuits[:b].dis?
    expected = %w[0000.0000.000a.00-00 0000.0000.000b.00-00 0000.0000.000b.01-00]
    assert_equal expected, held(:a).keys
    assert_equal held(:a), held(:b)
  end

  # Clause 7.3.8: no Area Addresses, and the DIS's own ID and each Up
  # neighbour's, each with a zero octet, at metric 0. TLV 22 with two 11
  # octet entries: 16 16, then 00000000000b 00, metric 000000, sub-TLV
  # length 00, and the same for a. Hex from the clause and RFC 5305 section
  # 3, worked out here.
  def test_the_pseudonode_lsp
    node(:a)
    node(:b)
    up(:a, :b)
    pseudonode = @circuits[:b].pseudonode
    assert pseudonode.active?
    assert_equal "0000.0000.000b.01-00", pseudonode.lsp_id_s
    assert_equal "1616" "00000000000b00" "000000" "00" "00000000000a00" "000000" "00", pseudonode.tlvs.map(&:to_shex).join
    refute @circuits[:a].pseudonode.active?
  end

  # Narrow metrics: TLV 2, a virtual flag octet, then per entry the four
  # metric octets, default 00 and the other three 80, S set for "not
  # supported", and the ID with its zero octet. 02 11 00, then
  # 00808080 00000000000b00 and 00808080 00000000000a00. Worked out from
  # RFC 1142 9.8.
  def test_the_pseudonode_lsp_narrow
    node(:a, metric_style: :narrow)
    node(:b, metric_style: :narrow)
    up(:a, :b)
    assert_equal "0217" "00" "00808080" "00000000000b00" "00808080" "00000000000a00",
                 @circuits[:b].pseudonode.tlvs.map(&:to_shex).join
  end

  # Clause 7.3.7: a's LSP names the pseudonode, b's LAN ID 0000.0000.000b
  # .01, at the circuit's metric 10: 16 0b 00000000000b01 00000a 00.
  def test_each_lsp_names_the_pseudonode
    node(:a)
    node(:b)
    up(:a, :b)
    run_for(2)
    [:a, :b].each do |who|
      tlv22 = stored_is_reachability(who, "#{IDS[who]}.00-00")
      assert_equal "160b" "00000000000b01" "00000a" "00", tlv22.map(&:to_shex).join, who
    end
  end

  # A DIS whose hellos carry a LAN ID with a zero circuit octet names no
  # pseudonode, so a's LSP names none until the DIS reports a real one.
  # Measured on FRR 8.4.4, whose first hellos carry a LAN ID of zeros.
  def test_no_pseudonode_named_from_a_zero_lan_id
    node(:a)
    node(:b)
    up(:a, :b)
    a = @circuits[:a]
    a.dis.lan_id = ISIS::Pdu.dotted_octets("0000.0000.0000.00")
    assert_nil a.is_neighbor
    # The same DIS reporting another LAN ID changes a's LSP (7.3.7).
    a.elect
    @scheduler.advance(2) # without reading b's hellos
    assert_empty stored_is_reachability(:a, "#{IDS[:a]}.00-00")
    a.dis.lan_id = ISIS::Pdu.dotted_octets("#{IDS[:b]}.01")
    id, metric = a.is_neighbor
    assert_equal ["00000000000b01", 10], [id.unpack1("H*"), metric]
    a.elect
    @scheduler.advance(2) # without reading b's hellos
    assert_equal "160b" "00000000000b01" "00000a" "00",
                 stored_is_reachability(:a, "#{IDS[:a]}.00-00").map(&:to_shex).join
  end

  # Clause 7.3.15.1 e 1 iv and e 2 ii: on a broadcast circuit a new or an
  # equal LSP sets no SSN, so it is not acknowledged by PSNP; the DIS's
  # CSNPs do that.
  def test_a_received_lsp_sets_no_ssn_on_a_lan
    node(:a)
    node(:b)
    up(:a, :b)
    from_b = Datalink::MAC.new(MACS[:b])
    assert_equal :new, @circuits[:a].receive_update(lsp, from_b)
    assert_equal :equal, @circuits[:a].receive_update(lsp, from_b)
    assert_empty @circuits[:a].database[ISIS::Pdu.lsp_id_octets(THIRD)].ssn
  end

  # Clause 7.3.15: "On broadcast circuits SRMflag is cleared as soon as the
  # LSP has been transmitted", so each LSP goes out once and is not sent
  # again unasked.
  def test_srm_is_cleared_once_sent
    node(:a)
    node(:b)
    up(:a, :b)
    run_for(5)
    @circuits.each_value do |c|
      c.database.entries.each { |e| assert_empty e.srm, "#{c.name} #{e.lsp_id_s}" }
    end
    before = sent(:a, ISIS::Pdu::Lsp).size
    run_for(25)
    assert_equal before, sent(:a, ISIS::Pdu::Lsp).size
  end

  # Clause 7.3.15.3 a: the DIS sends a CSNP every completeSNPInterval, and
  # the other system sends none.
  def test_the_dis_sends_csnps
    node(:a)
    node(:b)
    up(:a, :b)
    start_at = @clock.now
    run_for(30)
    times = sent(:b, ISIS::Pdu::Csnp).map(&:first).select { |t| t > start_at }
    assert_equal 3, times.size
    times.each_cons(2) { |x, y| assert_in_delta 10, y - x, 0.3 }
    assert_empty sent(:a, ISIS::Pdu::Csnp)
  end

  # Clause 7.3.15.3 a: more LSPs than one CSNP holds go in a complete set
  # of several, "separated by an interval of at least
  # minimumBroadcastLSPTransmissionInterval", every completeSNPInterval.
  def test_the_dis_sends_a_large_database_as_a_spaced_set_of_csnps
    node(:a)
    node(:b)
    up(:a, :b)
    (1..300).each { |i| seed(:b, lsp(id: format("0000.0000.%04x.00-00", 0x1000 + i))) }
    start_at = @clock.now
    run_for(12)
    csnps = sent(:b, ISIS::Pdu::Csnp).select { |t, _| t > start_at }
    first = csnps.index { |_, c| c.start_lsp_id_s == "0000.0000.0000.00-00" }
    set = csnps.drop(first)
    set = set.take(set.index { |_, c| c.end_lsp_id_s == "ffff.ffff.ffff.ff-ff" } + 1)
    assert_operator set.size, :>, 1
    set.each { |_, c| assert_operator c.encode.bytesize, :<=, 1492 }
    set.each_cons(2) { |(x, _), (y, _)| assert_operator y - x, :>=, 0.033 - 1e-9 }
    assert_equal 300, set.sum { |_, c| c.entries.count { |e| ISIS::Pdu.lsp_id_s(e.lsp_id).start_with?("0000.0000.1") } }
    # a asks for them in PSNPs that each hold what fits (7.3.15.4), and
    # the DIS sends one LSP every minimumBroadcastLSPTransmissionInterval.
    run_for(30)
    assert_equal held(:b).keys.sort, held(:a).keys.sort, "a learned every LSP"
  end

  # An LSP only the DIS holds: its CSNP lists it, a asks for it in a PSNP
  # (7.3.15.2 b 4, 7.3.15.4 a), and the DIS sends it (7.3.15.2 b 2).
  def test_the_other_system_asks_the_dis_for_what_it_lacks
    node(:a)
    node(:b)
    up(:a, :b)
    seed(:b, lsp)
    run_for(15)
    assert_equal 5, held(:a)[THIRD]
    refute_empty sent(:a, ISIS::Pdu::Psnp)
  end

  # An LSP only the other system holds: the DIS's CSNP does not mention
  # it, so that system sends it (7.3.15.2 c).
  def test_the_dis_learns_what_its_csnp_omits
    node(:a)
    node(:b)
    up(:a, :b)
    seed(:a, lsp)
    run_for(15)
    assert_equal 5, held(:b)[THIRD]
  end

  # Clause 7.3.17: only the DIS responds to a PSNP. a ignores one, even
  # one reporting an LSP older than a's, which would otherwise set SRM.
  def test_only_the_dis_responds_to_a_psnp
    node(:a)
    node(:b)
    up(:a, :b)
    seed(:a, lsp)
    psnp = ISIS::Pdu::Psnp.new(level: 1, source_id: "#{IDS[:b]}.00",
                               tlvs: [ISIS::Tlv::LspEntries.new([lsp(sequence: 1).then do |l|
                                 ISIS::Tlv::LspEntries::Entry.new(1200, l.lsp_id, 1, l.checksum)
                               end])])
    assert_equal :not_dis, @circuits[:a].receive_update(psnp, Datalink::MAC.new(MACS[:b]))
    assert_empty @circuits[:a].database[ISIS::Pdu.lsp_id_octets(THIRD)].srm
  end

  # LSPs and SNPs from a system with no adjacency Up are ignored.
  def test_nothing_is_taken_without_an_adjacency
    node(:a)
    assert_equal :no_adjacency, @circuits[:a].receive_update(lsp, Datalink::MAC.new(MACS[:b]))
    assert_nil @circuits[:a].database[ISIS::Pdu.lsp_id_octets(THIRD)]
  end

  # Clause 7.3.15.6: one LSP per minimumBroadcastLSPTransmissionInterval,
  # 33 ms, however many have SRM set.
  def test_lsps_go_out_33_ms_apart
    node(:a)
    node(:b)
    up(:a, :b)
    run_for(5)
    ids = %w[0000.0000.00c1.00-00 0000.0000.00c2.00-00 0000.0000.00c3.00-00]
    entries = ids.map { |id| seed(:b, lsp(id: id)) }
    before = sent(:b, ISIS::Pdu::Lsp).size
    entries.each { |e| @circuits[:b].flood(e) }
    run_for(0.25, step: 0.001)
    times = sent(:b, ISIS::Pdu::Lsp).drop(before).map(&:first)
    assert_equal 3, times.size
    times.each_cons(2) { |x, y| assert_in_delta 0.033, y - x, 0.002 }
  end

  # A priority change moves the DIS to a: b stops generating its
  # pseudonode (7.3.15.1 c) and purges it (7.2.3), a starts its own, and
  # both LSPs name a's LAN ID. Both databases hold b's old pseudonode as a
  # purge, lifetime 0.
  def test_a_dis_change_moves_the_pseudonode
    node(:a)
    node(:b)
    up(:a, :b)
    @circuits[:a].priority = 100
    run_for(10)
    assert @circuits[:a].dis?
    assert @circuits[:a].pseudonode.active?
    refute @circuits[:b].pseudonode.active?
    refute @circuits[:b].pseudonode.generates?(ISIS::Pdu.lsp_id_octets("0000.0000.000b.01-00"))
    [:a, :b].each do |who|
      tlv22 = stored_is_reachability(who, "#{IDS[who]}.00-00")
      assert_equal "160b" "00000000000a01" "00000a" "00", tlv22.map(&:to_shex).join, who
    end
    assert_includes held(:b).keys, "0000.0000.000a.01-00"
    assert_equal held(:a), held(:b)
    [:a, :b].each { |who| assert purged?(who, "0000.0000.000b.01-00"), who }
    refute purged?(:a, "0000.0000.000a.01-00")
    assert(@circuits[:b].log.events.any? { |e| e.kind == :purge && e.message.include?("resigned as DIS") })
  end

  # Clause 7.2.3: a DIS that takes over purges its predecessor's
  # pseudonode, here because b, the DIS, went silent and could not.
  def test_a_new_dis_purges_the_old_one_s_pseudonode
    node(:a)
    node(:b, priority: 100)
    node(:c)
    up(:a, :b, :c)
    assert @circuits[:b].dis?
    @circuits.delete(:b).stop
    run_for(35)
    assert @circuits[:c].dis?
    [:a, :c].each { |who| assert purged?(who, "0000.0000.000b.01-00"), who }
    assert(@circuits[:c].log.events.any? { |e| e.kind == :purge && e.message.include?("previous DIS") })
  end

  # A pseudonode LSP follows the adjacencies Up: c joining puts it in. c
  # learns the rest from the DIS's next CSNP, at most completeSNPInterval
  # on.
  def test_the_pseudonode_follows_the_adjacencies
    node(:a)
    node(:b)
    up(:a, :b)
    node(:c, priority: 10)
    start(:c)
    run_for(20)
    ids = stored_is_reachability(:c, "#{IDS[:b]}.01-00").flat_map { |t| t.entries.map { |e| e.neighbor.unpack1("H*") } }
    assert_equal %w[00000000000a00 00000000000b00 00000000000c00], ids.sort
    assert_equal held(:a), held(:c)
  end

  # -- Level 2: the same LAN, the Level 2 clauses (7.3.9, 7.3.10) --

  # Two Level 2 systems: the same three LSPs on both sides, every one a
  # Level 2 LSP with IS type 3 ("In a Level 2 Link State PDU, IS Type
  # shall be 3", RFC 1142 9.9), and every SNP sent a Level 2 one.
  def test_level_2_databases_agree
    node(:a, level: 2)
    node(:b, level: 2)
    up(:a, :b)
    run_for(15)
    expected = %w[0000.0000.000a.00-00 0000.0000.000b.00-00 0000.0000.000b.01-00]
    assert_equal expected, held(:a).keys
    assert_equal held(:a), held(:b)
    @circuits[:a].database.entries.each do |e|
      assert_equal [2, 3], [e.lsp.level, e.lsp.is_type], e.lsp_id_s
    end
    snps = @sent.values.flatten(1).map(&:last).select { |p| p.is_a?(ISIS::Pdu::Csnp) || p.is_a?(ISIS::Pdu::Psnp) }
    refute_empty snps
    assert(snps.all? { |p| p.level == 2 })
  end

  # A Level 1 LSP arriving on a Level 2 circuit changes nothing.
  def test_a_level_1_lsp_on_a_level_2_circuit_is_ignored
    node(:a, level: 2)
    node(:b, level: 2)
    up(:a, :b)
    assert_equal :level, @circuits[:a].receive_update(lsp, Datalink::MAC.new(MACS[:b]))
    assert_nil @circuits[:a].database[ISIS::Pdu.lsp_id_octets(THIRD)]
  end

  # The originator's database decides its level, and it has to be the
  # circuit's.
  def test_an_originator_of_another_level_is_refused
    log = ISIS::Runtime::Log.new(clock: @clock)
    database = ISIS::Database.new(level: 1, clock: @clock)
    originator = ISIS::Originator.new(system_id: IDS[:a], database: database, scheduler: @scheduler, log: log)
    error = assert_raises(ArgumentError) do
      ISIS::LanCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler, log: log,
                           name: "a-eth0", system_id: IDS[:a], snpa: MACS[:a], level: 2, originator: originator)
    end
    assert_includes error.message, "Level 1"
  end
end


# A system at both levels on one LAN: a Level 1 and a Level 2 circuit on
# the same link and LAN address, each with its own database and
# originator, as RFC 1142 clause 8.4.1 has it: "Separate adjacencies shall
# be created by the receipt of Level 1 and Level 2 LAN IIH PDUs."
class TestLanTwoLevels < Minitest::Test
  IDS = TestLanCircuit::IDS
  MACS = TestLanCircuit::MACS

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    @circuits = {}
    TestLogs.heading(name)
  end

  # +levels+ is [1], [2] or [1, 2]. A system at both levels writes IS
  # type 3 at both, and its hellos carry circuit type 3.
  def system(who, levels)
    log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    both = levels.size == 2
    levels.each do |level|
      db = ISIS::Database.new(level: level, clock: @clock, scheduler: @scheduler, log: log)
      orig = ISIS::Originator.new(system_id: IDS.fetch(who), database: db, scheduler: @scheduler, log: log,
                                  minimum_interval: 1, is_type: both ? 3 : nil)
      circuit = ISIS::LanCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler,
                                     log: log, name: "#{who}-eth0-l#{level}", system_id: IDS.fetch(who),
                                     snpa: MACS.fetch(who), level: level, database: db, originator: orig,
                                     circuit_type: both ? :l1l2 : nil)
      @circuits[[who, level]] = circuit
      orig.start
      circuit.start
    end
  end

  def run_for(seconds, step: 0.25)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @circuits.each_value(&:poll)
    end
  end

  def held(who, level)
    @circuits.fetch([who, level]).database.entries.reject(&:placeholder?).to_h { |e| [e.lsp_id_s, e.sequence] }
  end

  # Both levels agree separately, each database holds only its own
  # level's LSPs, and every LSP from a system at both levels carries IS
  # type 3, in the Level 1 database as well.
  def test_two_systems_at_both_levels
    system(:a, [1, 2])
    system(:b, [1, 2])
    run_for(25)
    [1, 2].each do |level|
      expected = %w[0000.0000.000a.00-00 0000.0000.000b.00-00 0000.0000.000b.01-00]
      assert_equal expected, held(:a, level).keys, "Level #{level}"
      assert_equal held(:a, level), held(:b, level), "Level #{level}"
      @circuits[[:a, level]].database.entries.each do |e|
        assert_equal [level, 3], [e.lsp.level, e.lsp.is_type], "#{e.lsp_id_s} at Level #{level}"
      end
    end
    assert_equal :l1l2, @circuits[[:a, 1]].build_hello.circuit_type
    assert_equal :l1l2, @circuits[[:a, 2]].build_hello.circuit_type
  end

  # A Level 1 only system beside them sees the Level 1 LSPs, IS type 3 from
  # the system at both levels and 1 from itself, and nothing of Level 2.
  def test_a_level_1_system_sees_level_1_only
    system(:a, [1, 2])
    system(:c, [1])
    run_for(25)
    l1 = @circuits[[:c, 1]].database
    assert_equal 3, l1[ISIS::Pdu.lsp_id_octets("0000.0000.000a.00-00")].lsp.is_type
    assert_equal 1, l1[ISIS::Pdu.lsp_id_octets("0000.0000.000c.00-00")].lsp.is_type
    assert_equal held(:a, 1), held(:c, 1)
    assert_equal %w[0000.0000.000a.00-00], held(:a, 2).keys
    assert_empty @circuits[[:a, 2]].up_neighbors
  end

  # A circuit type that does not include the circuit's level is refused.
  def test_a_circuit_type_without_the_level_is_refused
    log = ISIS::Runtime::Log.new(clock: @clock)
    assert_raises(ArgumentError) do
      ISIS::LanCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler, log: log,
                           name: "x", system_id: IDS[:a], snpa: MACS[:a], level: 1, circuit_type: :l2)
    end
  end
end
