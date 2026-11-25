# frozen_string_literal: true

require_relative "../../test_helper"

# Spf::FlexAlgo: the winning FAD of each configured algorithm, and whether
# this system takes part, by RFC 9350 section 5.3, on a database of
# hand-built LSPs. This system is 0000.0000.0001.
class TestFlexAlgo < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @db = ISIS::Database.new(level: 1, clock: @clock)
    @log = ISIS::Runtime::Log.new(clock: @clock)
  end

  def config(*entries)
    ISIS::FlexAlgoConfig.new(entries, affinity_map: { "red" => 1 }, segment_routing: true)
  end

  def flex(*entries)
    ISIS::Spf::FlexAlgo.new(level: 1, system_id: "0000.0000.0001", database: @db, config: config(*entries), log: @log)
  end

  # System +n+'s LSP Number +number+, with a Router Capability carrying
  # +fads+.
  def store(n, fads, number: 0)
    id = format("0000.0000.%04d.00-%02d", n, number)
    cap = ISIS::Tlv::RouterCapability.new(router_id: "10.255.0.#{n}", subtlvs: fads.map { { fad: _1 } })
    lsp = ISIS::Pdu::Lsp.new(level: 1, lsp_id: id, lifetime: 1200, sequence: 1, tlvs: [cap])
    @db.entry(ISIS::Pdu.lsp_id_octets(id)).store(lsp)
  end

  # Its own FAD alone: it wins, and this system takes part from the start.
  def test_own_fad
    f = flex({ algorithm: 128, metric_type: "delay", priority: 100, exclude_any: ["red"] })
    assert_equal [128], f.participating
    s = f.statuses[128]
    assert_equal "0000.0000.0001", s.origin
    assert_equal({ algorithm: 128, participating: true,
                   winner: { metric_type: "delay", calc_type: 0, priority: 100, exclude_any: [1], origin: "0000.0000.0001" },
                   supported: true, candidates: [{ origin: "0000.0000.0001", priority: 100 }] }, s.to_hash)
  end

  # Section 5.3: with no FAD, it "MUST stop participating".
  def test_no_fad
    f = flex({ algorithm: 128, advertise: false })
    assert_empty f.participating
    assert_equal "no FAD", f.statuses[128].reason
  end

  # The greatest priority wins; on a tie, the greatest System ID.
  def test_priority_then_system_id
    store(2, [{ algorithm: 128, priority: 200 }])
    store(3, [{ algorithm: 128, priority: 200, metric_type: "te" }])
    f = flex({ algorithm: 128, priority: 100 })
    assert_equal "0000.0000.0003", f.statuses[128].origin
    assert_equal "te", f.statuses[128].winner.metric_name
    assert_equal %w[0000.0000.0003 0000.0000.0002 0000.0000.0001], f.statuses[128].candidates.map { _1[:origin] }
  end

  # A winner it cannot run stops it taking part, with the reason; a
  # losing one it cannot run does not.
  def test_unsupported_winner
    store(2, [{ algorithm: 128, priority: 200, calc_type: 1 }])
    f = flex({ algorithm: 128, priority: 100 })
    refute f.participating?(128)
    assert_equal "the winning FAD: FAD 128: calculation type 1", f.statuses[128].reason
    store(2, [{ algorithm: 128, priority: 50, calc_type: 1 }])
    f.update("test")
    assert f.participating?(128)
  end

  # An algorithm not configured is ignored, whatever its FAD.
  def test_not_configured
    store(2, [{ algorithm: 129, priority: 200 }])
    f = flex({ algorithm: 128 })
    assert_equal [128], f.statuses.keys
  end

  # A system without LSP Number 0 is left out (clause 7.2.5).
  def test_no_lsp_zero
    store(2, [{ algorithm: 128, priority: 200, calc_type: 1 }], number: 1)
    assert flex({ algorithm: 128, priority: 100 }).participating?(128)
  end

  # A change of taking part is an event of kind :flex_algo, and the
  # originator is told; the same answer twice is neither.
  def test_update_reports_and_tells_the_originator
    told = []
    f = flex({ algorithm: 128, priority: 100 })
    f.originator = Object.new.tap { |o| o.define_singleton_method(:changed) { |why| told << why } }
    refute f.update("nothing new")
    store(2, [{ algorithm: 128, priority: 200, calc_type: 1 }])
    assert f.update("LSP 0000.0000.0002.00-00")
    assert_equal ["flex-algo: taking part in none"], told
    e = @log.events.select { _1.kind == :flex_algo }.last
    assert_match(/\ALevel 1 flex-algo 128: not taking part: the winning FAD: FAD 128: calculation type 1, after LSP/,
                 e.message)
  end

  # The findings on the FADs read, by system.
  def test_findings
    store(2, [{ algorithm: 127 }])
    assert_equal [["fad_algorithm_range", "0000.0000.0002"]],
                 flex({ algorithm: 128 }).to_hash[:findings].map { _1.values_at(:name, :subject) }
  end
end
