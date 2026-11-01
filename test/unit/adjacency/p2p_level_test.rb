# frozen_string_literal: true

require_relative "../../test_helper"

# A point to point circuit at one level or both: one adjacency, a
# P2pCircuit::Level per level, each with its own database and originator.
# Which levels the adjacency serves follows RFC 1142 clause 8.2.4.2.
#
# ISIS_LOG=info or ISIS_LOG=debug prints each test's log as it runs.
class TestP2pLevel < Minitest::Test
  IDS = { a: "0000.0000.000a", b: "0000.0000.000b" }.freeze
  MACS = { a: "00:00:00:00:00:0a", b: "00:00:00:00:00:0b" }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wire = ISIS::Link::SimulatedWire.new
    @circuits = {}
    @originators = {}
    TestLogs.heading(name)
  end

  # A system running +levels+ on its one circuit, in +areas+. One at both
  # levels writes IS type 3 in each LSP (RFC 1142 9.8).
  def node(who, levels, areas: ["49.0001"])
    log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    config = levels.to_h do |level|
      db = ISIS::Database.new(level: level, clock: @clock, scheduler: @scheduler, log: log)
      orig = ISIS::Originator.new(system_id: IDS.fetch(who), database: db, scheduler: @scheduler, log: log,
                                  areas: areas, minimum_interval: 1, is_type: levels.size == 2 ? 3 : nil)
      @originators[[who, level]] = orig
      [level, { database: db, originator: orig }]
    end
    @circuits[who] = ISIS::P2pCircuit.new(transport: ISIS::Link::SimulatedTransport.new(@wire), scheduler: @scheduler,
                                          log: log, name: "#{who}-eth1", system_id: IDS.fetch(who),
                                          snpa: MACS.fetch(who), areas: areas, levels: config)
  end

  def start
    @originators.each_value(&:start)
    @circuits.each_value(&:start)
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @circuits.each_value(&:poll)
    end
  end

  def held(who, level)
    @circuits.fetch(who).level(level).database.entries.reject(&:placeholder?).to_h { |e| [e.lsp_id_s, e.sequence] }
  end

  def usage(who)
    @circuits.fetch(who).neighbor&.usage
  end

  # Both at both levels in one area: the adjacency serves both, the hello
  # says circuit type 3, and each level's databases agree, every LSP with
  # IS type 3 and naming the neighbour: 16 0b, 00000000000b 00, metric
  # 00000a, sub-TLV length 00 (RFC 5305 section 3).
  def test_both_levels
    node(:a, [1, 2])
    node(:b, [1, 2])
    start
    run_for(15)
    assert_equal [1, 2], usage(:a)
    assert_equal :l1l2, @circuits[:a].build_hello.circuit_type
    [1, 2].each do |level|
      assert_equal %w[0000.0000.000a.00-00 0000.0000.000b.00-00], held(:a, level).keys, "Level #{level}"
      assert_equal held(:a, level), held(:b, level), "Level #{level}"
      entry = @circuits[:a].level(level).database[ISIS::Pdu.lsp_id_octets("0000.0000.000a.00-00")]
      assert_equal [level, 3], [entry.lsp.level, entry.lsp.is_type]
      tlv22 = entry.lsp.tlvs.find { |t| t.is_a?(ISIS::Tlv::ExtendedIsReachability) }
      assert_equal "160b" "00000000000b00" "00000a" "00", tlv22.to_shex, "Level #{level}"
    end
  end

  # One side at both levels, the other at Level 2 only: the adjacency
  # serves Level 2, and Level 1 stays apart, a's Level 1 LSP naming no one.
  def test_both_against_level_2_only
    node(:a, [1, 2])
    node(:b, [2])
    start
    run_for(15)
    assert_equal [2], usage(:a)
    assert_equal [2], usage(:b)
    assert_equal held(:a, 2), held(:b, 2)
    assert_equal %w[0000.0000.000a.00-00], held(:a, 1).keys
    own = @circuits[:a].level(1).database[ISIS::Pdu.lsp_id_octets("0000.0000.000a.00-00")].lsp
    assert_nil own.tlvs.find { |t| t.is_a?(ISIS::Tlv::ExtendedIsReachability) }
  end

  # The neighbour's hellos stop saying Level 1: the adjacency stays Up and
  # serves Level 2 only, and Level 1 is let go, a's new Level 1 LSP naming
  # no one.
  def test_a_level_dropped_while_up
    node(:a, [1, 2])
    node(:b, [1, 2])
    start
    run_for(15)
    assert_equal [1, 2], usage(:a)
    @circuits[:b].define_singleton_method(:circuit_type) { :l2 }
    run_for(10)
    assert_equal [2], usage(:a)
    assert @circuits[:a].up?
    own = @circuits[:a].level(1).database[ISIS::Pdu.lsp_id_octets("0000.0000.000a.00-00")].lsp
    assert_nil own.tlvs.find { |t| t.is_a?(ISIS::Tlv::ExtendedIsReachability) }
    assert(@circuits[:a].log.events.any? { |e| e.kind == :adjacency && e.message.include?("now serves Level 2") })
  end

  # Clause 8.2.4.2: no area in common, both Level 2, so "the IS shall mark
  # the adjacency as Level 2 Only".
  def test_no_area_in_common_is_level_2_only
    node(:a, [1, 2], areas: ["49.0001"])
    node(:b, [1, 2], areas: ["49.0002"])
    start
    run_for(15)
    assert_equal [2], usage(:a)
    assert_equal held(:a, 2), held(:b, 2)
    assert_equal %w[0000.0000.000a.00-00], held(:a, 1).keys
  end

  # Clause 8.2.4.2 b: no area in common and this side Level 1 only, so no
  # adjacency.
  def test_no_area_in_common_at_level_1_is_no_adjacency
    node(:a, [1], areas: ["49.0001"])
    node(:b, [1, 2], areas: ["49.0002"])
    start
    run_for(10)
    refute @circuits[:a].up?
    refute @circuits[:b].up?
  end

  # Level 1 only against Level 2 only: no level in common, no adjacency.
  def test_no_level_in_common_is_no_adjacency
    node(:a, [1])
    node(:b, [2])
    start
    run_for(10)
    refute @circuits[:a].up?
    assert(@circuits[:a].log.events.any? { |e| e.kind == :refused && e.data[:reason] == :level })
  end

  # A Level 1 LSP on an adjacency that serves Level 2 only changes nothing.
  def test_an_lsp_of_a_level_the_adjacency_does_not_serve_is_ignored
    node(:a, [1, 2])
    node(:b, [2])
    start
    run_for(10)
    lsp = ISIS::Pdu::Lsp.new(level: 1, lsp_id: "0000.0000.00cc.00-00", lifetime: 1200, sequence: 5, tlvs: [])
    @circuits[:a].receive_update(lsp)
    assert_nil @circuits[:a].level(1).database[lsp.lsp_id]
  end

  # At two levels, the single level shortcuts would have to guess.
  def test_two_levels_have_no_single_database
    node(:a, [1, 2])
    assert_raises(ArgumentError) { @circuits[:a].database }
  end
end
