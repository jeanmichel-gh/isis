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
