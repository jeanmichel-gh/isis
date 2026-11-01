# frozen_string_literal: true

require_relative "../../test_helper"
require "stringio"

# The log: a logger for every line, events for every line above debug,
# and a tracer for PDUs. CLAUDE.md, "Logging and events".
class TestLog < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @lines = []
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: ->(level, message) { @lines << [level, message] })
  end

  def test_every_level_reaches_the_logger
    @log.debug("d")
    @log.info("i")
    @log.warn("w")
    @log.error("e")
    assert_equal [[:debug, "d"], [:info, "i"], [:warn, "w"], [:error, "e"]], @lines
  end

  def test_debug_is_not_kept_as_an_event
    @log.debug("each PDU")
    @log.info("adjacency up")
    assert_equal ["adjacency up"], @log.events.map(&:message)
  end

  def test_an_event_keeps_kind_circuit_and_data
    e = @log.info("up", circuit: "eth1", kind: :adjacency, neighbor: "1921.6800.1001")
    assert_equal [:info, "eth1", :adjacency, "up", { neighbor: "1921.6800.1001" }],
                 [e.level, e.circuit, e.kind, e.message, e.data]
    assert_equal [:info, "eth1 up"], @lines.last
  end

  # Wall time on events comes from the clock, so a simulated run logs
  # simulated time: 90 seconds after the ManualClock's wall start.
  def test_event_time_is_the_clocks_wall_time
    @clock.advance(90)
    assert_equal Time.utc(2026, 1, 1, 0, 1, 30), @log.info("x").time
  end

  def test_events_are_bounded
    log = ISIS::Runtime::Log.new(clock: @clock, max_events: 3)
    5.times { |i| log.info("e#{i}") }
    assert_equal %w[e2 e3 e4], log.events.map(&:message)
  end

  def test_listeners_hear_kept_events_only
    heard = []
    @log.on_event { |e| heard << e.message }
    @log.debug("not this")
    @log.warn("this")
    assert_equal ["this"], heard
  end

  def test_no_logger_and_no_tracer_is_fine
    log = ISIS::Runtime::Log.new(clock: @clock)
    log.info("nobody listening")
    log.trace(:sent, "eth1", Object.new)
    assert_equal 1, log.events.size
  end

  def test_unknown_level_is_refused
    assert_raises(ArgumentError) { @log.log(:verbose, "x") }
  end

  def test_tracer_gets_each_pdu
    seen = []
    @log.tracer = ->(*args) { seen << args }
    @log.trace(:received, "eth1", :pdu, "aa:bb")
    assert_equal [[:received, "eth1", :pdu, "aa:bb"]], seen
  end

  def test_writer_formats_and_filters_debug
    io = StringIO.new
    writer = ISIS::Runtime::Log.writer(io, clock: @clock)
    writer.call(:debug, "hidden")
    writer.call(:info, "shown")
    assert_equal "2026-01-01T00:00:00.000Z info  shown\n", io.string
    debug = StringIO.new
    ISIS::Runtime::Log.writer(debug, clock: @clock, debug: true).call(:debug, "seen")
    assert_includes debug.string, "debug seen"
  end

  # With debug, the trace carries the PDU's hex, so a line can become a
  # test fixture.
  def test_trace_writer_adds_hex_with_debug
    pdu = ISIS::Tlv::Padding.new(1)
    io = StringIO.new
    ISIS::Runtime::Log.trace_writer(io, clock: @clock, debug: true).call(:sent, "eth1", pdu, nil)
    assert_equal "2026-01-01T00:00:00.000Z eth1 > Padding, 1 octets\n  080100\n", io.string
  end
end
