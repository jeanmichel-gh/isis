# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"
require "tmpdir"

# exe/isis-p2p-sim, run as a person would run it. Simulated time, so each
# run takes a fraction of a second and prints the same lines every time.
class TestIsisP2pSim < Minitest::Test
  EXE = File.expand_path("../../exe/isis-p2p-sim", __dir__)

  def sim(*args)
    out, status = Open3.capture2e(RbConfig.ruby, EXE, *args)
    assert status.success?, out
    out
  end

  def test_comes_up_then_expires_with_the_reason
    out = sim
    assert_includes out, "2026-01-01T00:00:03.000Z info  a adjacency with 0000.0000.000b initializing -> up"
    assert_includes out, "a adjacency with 0000.0000.000b up -> down: holding time of 30 s expired"
    assert_includes out, "end: a is down, b is down"
    refute_includes out, "debug"
  end

  def test_stays_up_when_nobody_goes_silent
    assert_includes sim("--silence-at", "-1", "--seconds", "15"), "end: a is up, b is up"
  end

  # Debug adds the handshake decisions and a trace with each PDU's hex.
  def test_debug_traces_pdus_with_hex
    out = sim("--debug", "--seconds", "1")
    assert_includes out, "debug a three-way down, received down: initialize"
    assert_includes out, "a > P2P hello l1 from 0000.0000.000a"
    assert_match(/^  831401001101/, out)
  end

  def test_holding_time_follows_the_options
    out = sim("--hello-interval", "1", "--multiplier", "3", "--silence-at", "5", "--seconds", "12")
    assert_includes out, "holding time of 3 s expired"
  end

  def test_log_to_a_file
    Dir.mktmpdir do |dir|
      path = File.join(dir, "sim.log")
      assert_empty sim("-l", path, "--seconds", "5")
      assert_includes File.read(path), "initializing -> up"
    end
  end
end
