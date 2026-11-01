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

  # Gate 3, the receiving half: FRR lists its own LSP in a CSNP and sends
  # it only when asked, so isis4r has to request it, store it and
  # acknowledge it. Measured: FRR 8.4.4 does not flood its LSP on a point to
  # point adjacency without that request.
  def test_isis4r_learns_and_acknowledges_frrs_lsp
    @lab.start
    assert_eventually("adjacency did not come up") { both_up? }
    frr_id = "#{FrrLab::FRR_ID}.00-00"
    assert_eventually("isis4r did not learn FRR's LSP") do
      held = @lab.isis4r_database[frr_id]
      frr = @lab.frr_database[frr_id]
      held && frr && held["sequence"] == frr["sequence"] && held["checksum"] == frr["checksum"]
    end
    assert_eventually("isis4r's acknowledgment did not go out") { @lab.isis4r_database.dig(frr_id, "ssn")&.zero? }
    # Acknowledged, so FRR does not send it again: over the next ten
    # seconds isis4r receives it at most once more, if FRR refreshed it.
    before = @lab.isis4r_log.scan(/< L1 LSP #{Regexp.escape(frr_id)}/).size
    sleep 10
    after = @lab.isis4r_log.scan(/< L1 LSP #{Regexp.escape(frr_id)}/).size
    assert_operator after - before, :<=, 1, "FRR kept sending its LSP\n#{@lab.report}"
  end

  # Gate 3, the sending half: FRR learns isis4r's LSP at isis4r's sequence
  # and checksum, runs SPF over it, and installs the prefix isis4r
  # advertises, through isis4r. 192.0.2.1/32 exists only in isis4r's TLV
  # 135, so FRR can have the route from nowhere else.
  def test_frr_learns_isis4rs_prefix
    @lab.start
    assert_eventually("adjacency did not come up") { both_up? }
    own = "#{FrrLab::ISIS4R_ID}.00-00"
    assert_eventually("FRR does not hold isis4r's latest LSP", 30) do
      held = @lab.isis4r_database[own]
      frr = @lab.frr_database[own]
      held && frr && held["sequence"] >= 2 && frr["sequence"] == held["sequence"] && frr["checksum"] == held["checksum"]
    end
    # Measured on FRR 8.4.4: the route comes about 30 s after the adjacency.
    # FRR holds isis4r's LSP within a second, but its own LSP names isis4r
    # in TLV 22 only when it regenerates it, about 30 s on, and its SPF
    # needs the link in both LSPs.
    assert_eventually("FRR did not install 192.0.2.1/32 from IS-IS", 60) do
      route = @lab.frr_route("192.0.2.1/32")
      route && route["protocol"] == "isis" && route["installed"] &&
        route["nexthops"].any? { |n| n["ip"] == "10.0.12.1" && n["interfaceName"] == "veth0" }
    end
    assert_eventually("isis4r's LSP is still owed to FRR") { @lab.isis4r_database.dig(own, "srm")&.zero? }
  end

end
