# frozen_string_literal: true

require_relative "../../test_helper"

# The pseudonode LSP on its own, against a stand-in for its LAN circuit.
# RFC 1142 clause 7.3.8. LanCircuit's tests run it on a LAN.
class TestPseudonode < Minitest::Test
  Neighbor = Struct.new(:system_id)

  # What a Pseudonode asks of its circuit.
  class Lan
    attr_reader :name, :system_id, :flooded
    attr_accessor :up_neighbors

    def initialize
      @name = "lan0"
      @system_id = ISIS::Pdu.dotted_octets("0000.0000.000a")
      @up_neighbors = []
      @flooded = []
    end

    def own_lan_id
      (@system_id + "\x02".b).b
    end

    def is_neighbor
      nil
    end

    def flood(entry)
      @flooded << entry.lsp_id_s
    end
  end

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    TestLogs.heading(name)
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    @database = ISIS::Database.new(level: 1, clock: @clock)
    @lan = Lan.new
    @lan.up_neighbors = [Neighbor.new(ISIS::Pdu.dotted_octets("0000.0000.000b"))]
    @pseudonode = ISIS::Pseudonode.new(circuit: @lan, database: @database, scheduler: @scheduler, log: @log,
                                       minimum_interval: 1)
  end

  def lsp_id
    ISIS::Pdu.lsp_id_octets("0000.0000.000a.02-00")
  end

  # The LSP ID is the circuit's own LAN ID with LSP Number 0.
  def test_the_lsp_id_is_the_lan_id
    assert_equal "0000.0000.000a.02-00", @pseudonode.lsp_id_s
  end

  # Clause 7.3.8: no TLV 1, and TLV 22 with this system and each Up
  # neighbour at metric 0: 16 16, 00000000000a 00 000000 00, and the same
  # for b. Worked out from the clause and RFC 5305 section 3.
  def test_what_it_carries
    assert_equal "1616" "00000000000a00" "000000" "00" "00000000000b00" "000000" "00",
                 @pseudonode.tlvs.map(&:to_shex).join
  end

  # Clause 7.3.8, the Authentication Information field: with an area key,
  # TLV 10 first.
  def test_with_an_area_key
    keyed = ISIS::Pseudonode.new(circuit: @lan, database: @database, scheduler: @scheduler, log: @log,
                                 area_key: "k")
    assert_kind_of ISIS::Tlv::Authentication, keyed.build.tlvs.first
  end

  # Inactive until start: nothing generated, nothing claimed (7.3.15.1 c),
  # and a change does nothing.
  def test_inactive_until_started
    refute @pseudonode.generates?(lsp_id)
    @pseudonode.changed("test")
    @scheduler.advance(5)
    assert_nil @database[lsp_id]
  end

  # start generates at once and floods; stop stops claiming it.
  def test_start_and_stop
    @pseudonode.start
    assert @pseudonode.generates?(lsp_id)
    assert_equal 1, @database[lsp_id].sequence
    assert_equal ["0000.0000.000a.02-00"], @lan.flooded
    @pseudonode.stop
    refute @pseudonode.generates?(lsp_id)
  end

  # Becoming DIS again goes on from the last sequence, so the new LSP is
  # newer than the copy already flooded.
  def test_a_second_term_continues_the_sequence
    @pseudonode.start
    @pseudonode.stop
    @scheduler.advance(5)
    @pseudonode.start
    assert_equal 2, @database[lsp_id].sequence
  end

  # A neighbour coming Up changes what it carries, so it is generated
  # again.
  def test_a_change_generates_again
    @pseudonode.start
    @lan.up_neighbors += [Neighbor.new(ISIS::Pdu.dotted_octets("0000.0000.000c"))]
    @pseudonode.changed("c up")
    @scheduler.advance(2)
    assert_equal 2, @database[lsp_id].sequence
  end
end
