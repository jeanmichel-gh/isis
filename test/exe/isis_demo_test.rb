# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"
require "tmpdir"

# exe/isis-demo, run as a person would run it: two LAN circuits on
# datalink-socket's loopback wire, on the real clock.
class TestIsisDemo < Minitest::Test
  EXE = File.expand_path("../../exe/isis-demo", __dir__)

  def demo(*args)
    out, status = Open3.capture2e(RbConfig.ruby, EXE, *args)
    assert status.success?, out
    out
  end

  def test_converges_and_says_why
    out = demo
    assert_includes out, "adjacency up both ways: true"
    assert_includes out, "info  a adjacency with 0000.0000.0002 init -> up: its TLV 6 lists our SNPA 00:00:00:00:00:01"
    refute_includes out, "debug"
  end

  # --debug adds the PDU trace, each hello decoded and then its hex.
  def test_debug_traces_every_hello
    out = demo("--debug")
    assert_match(/ a > L1 LAN hello l1 from 0000\.0000\.0001, holding 30/, out)
    assert_includes out, "  831b01000f01"
  end

  def test_log_goes_to_a_file
    Dir.mktmpdir do |dir|
      path = File.join(dir, "demo.log")
      out = demo("-l", path)
      refute_includes out, "info  a adjacency"
      assert_includes File.read(path), "info  a adjacency with 0000.0000.0002 down -> init"
    end
  end
end
