# frozen_string_literal: true

# The library is under lib/, laid out as CLAUDE.md describes.
# datalink-socket and bfd4r are path dependencies during the PoC. Add
# them to the load path so tests run without bundler (and without network).
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../datalink-socket/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../bfd4r", __dir__)

require "minitest/autorun"
require "isis4r"
require "datalink/backends/loopback"

# Logs for a person watching tests run. A test hands its Runtime::Log a
# logger and a tracer from here; with ISIS_LOG unset they only feed the
# test's own sink, so the test can assert on what was logged. With
# ISIS_LOG=info (or 1) or ISIS_LOG=debug (or 2) they also print to standard
# error, and debug adds a trace of every PDU with its hex:
#
#   ISIS_LOG=debug ruby -Ilib -I../datalink-socket/lib -Itest test/unit/adjacency/p2p_circuit_test.rb -v
module TestLogs
  # ISIS_LOG=info, 1, true or yes prints info; ISIS_LOG=debug or 2 adds
  # debug lines and the PDU trace. Anything else set is reported, so a
  # value that does nothing does not look like logging that is broken.
  VALUES = { "info" => "info", "1" => "info", "true" => "info", "yes" => "info",
             "debug" => "debug", "2" => "debug" }.freeze
  RAW = ENV.fetch("ISIS_LOG", "").strip.downcase
  LEVEL = VALUES.fetch(RAW, "")
  warn "ISIS_LOG=#{RAW} is not one of #{VALUES.keys.join(', ')}; no test logs will print" if !RAW.empty? && LEVEL.empty?

  module_function

  def on?
    %w[info debug].include?(LEVEL)
  end

  def debug?
    LEVEL == "debug"
  end

  # A logger that calls +sink+, if given, and prints when ISIS_LOG is set.
  def logger(clock, sink = nil)
    printer = on? ? ISIS::Runtime::Log.writer($stderr, clock: clock, debug: debug?) : nil
    lambda do |level, message|
      sink&.call(level, message)
      printer&.call(level, message)
    end
  end

  # A tracer that calls +sink+, if given, and prints under ISIS_LOG=debug.
  def tracer(clock, sink = nil)
    printer = debug? ? ISIS::Runtime::Log.trace_writer($stderr, clock: clock, debug: true) : nil
    lambda do |*args|
      sink&.call(*args)
      printer&.call(*args)
    end
  end

  # A heading before a test's lines, so the output says which test it is.
  def heading(name)
    $stderr.puts "\n== #{name}" if on?
  end
end
