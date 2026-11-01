# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"

# Phase 1 gate 2, against FRR's isisd: an independent router brings the
# point to point adjacency up and holds it, and losing the neighbour
# expires it, on both sides. CLAUDE.md, "Where to start" and "Labs and
# interop".
#
# Runs only as root with FRR installed and ISIS_FRR=1:
#
#   sudo -E env "PATH=$PATH" ISIS_FRR=1 ruby -Ilib -I../datalink-socket/lib -Itest test/integration/frr_p2p_test.rb
#
# Hellos are every second with a multiplier of 3, so the holding time is
# 3 s on both sides. A failing test prints both sides' logs.
class TestFrrP2p < Minitest::Test
  def setup
    ok, why = FrrLab.available?
    # Asked for with ISIS_FRR=1 and unable to run is a failure, not a skip:
    # a skip prints its reason only under -v, and a CI job of skips is green.
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
    @lab = FrrLab.new("p2p#{Process.pid % 10_000}")
  end

  def teardown
    @lab&.stop
  end

  def both_up?
    @lab.frr_adjacency_state == "Up" && @lab.isis4r_state == "up"
  end

  def assert_eventually(message, timeout = 20, &block)
    assert @lab.wait_for(timeout, &block), "#{message}\n#{@lab.report}"
  end

  def test_adjacency_comes_up_on_both_sides
    @lab.start
    assert_eventually("adjacency did not come up on both sides") { both_up? }
    assert_includes @lab.isis4r_log, "adjacency with #{FrrLab::FRR_ID} initializing -> up"
  end

  # Ten seconds is more than three holding times: the hellos each side
  # sends keep the other's timer from running out. Being up at the end is
  # not enough, since an adjacency that flaps and comes back is up at the
  # end too, so isis4r must have come up once and never gone down.
  def test_adjacency_holds
    @lab.start
    assert_eventually("adjacency did not come up") { both_up? }
    sleep 10
    assert both_up?, "adjacency did not hold\n#{@lab.report}"
    log = @lab.isis4r_log
    refute_includes log, "-> down", "isis4r's adjacency went down while hellos kept arriving\n#{@lab.report}"
    # Any arrival at Up counts. Down goes straight to Up when FRR's hello
    # already reports Initializing (RFC 5303 3.2), so it need not pass
    # through Initializing first.
    ups = log.scan(/^\S+ info +\S+ adjacency with \S+ \w+ -> up$/).size
    assert_equal 1, ups, "isis4r came up #{ups} times, not once\n#{@lab.report}"
  end

  def test_frr_expires_isis4r_when_it_goes_silent
    @lab.start
    assert_eventually("adjacency did not come up") { both_up? }
    @lab.stop_isis4r
    assert_eventually("FRR kept the adjacency after isis4r went silent", 10) { @lab.frr_adjacency_state.nil? }
  end

  def test_isis4r_expires_frr_when_it_goes_silent
    @lab.start
    assert_eventually("adjacency did not come up") { both_up? }
    @lab.stop_frr_isisd
    assert_eventually("isis4r kept the adjacency after FRR went silent", 10) { @lab.isis4r_state == "down" }
    assert_includes @lab.isis4r_log, "holding time of 3 s expired without a hello"
  end

  # No area in common: neither side forms an adjacency, and isis4r says why.
  def test_area_mismatch_forms_no_adjacency
    @lab.start(isis4r: { areas: ["49.0002"] })
    assert_eventually("isis4r did not refuse FRR's hello", 10) { @lab.isis4r_log.include?("no area in common") }
    sleep 3
    refute_equal "up", @lab.isis4r_state, @lab.report
    refute_equal "Up", @lab.frr_adjacency_state, @lab.report
  end
end
