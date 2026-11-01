# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"

# Phase 2 gate 1, the adjacency half, against FRR's isisd on a broadcast
# circuit: both sides come up, agree on the Level 1 DIS and its LAN ID,
# and agree again when the DIS changes. RFC 1142 clauses 8.4.1 to 8.4.4.
# The update process on a LAN, and so database agreement, is the next
# step.
#
# Runs only as root with FRR installed and ISIS_FRR=1, like
# frr_p2p_test.rb. LAN addresses are random per run, so each test sets the
# priorities that decide the election rather than leaving it to the MACs.
class TestFrrLan < Minitest::Test
  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
    @lab = FrrLab.new("lan#{Process.pid % 10_000}")
  end

  def teardown
    @lab&.stop
  end

  def assert_eventually(message, timeout = 20, &block)
    assert @lab.wait_for(timeout, &block), "#{message}\n#{@lab.report}"
  end

  def both_up?
    @lab.frr_adjacency_state == "Up" && @lab.isis4r_state == "up"
  end

  def isis4r
    @lab.isis4r_state_doc
  end

  ISIS4R_LAN_ID = "#{FrrLab::ISIS4R_ID}.01".freeze

  # isis4r at priority 100 against FRR's 64: isis4r is DIS on both sides'
  # account, and FRR reports isis4r's LAN ID.
  def test_isis4r_is_dis_and_frr_agrees
    @lab.start(network: :broadcast, isis4r: { priority: 100 })
    assert_eventually("adjacency did not come up on the LAN") { both_up? }
    assert_eventually("isis4r and FRR do not agree that isis4r is DIS") do
      isis4r["dis"] == "self" && @lab.frr_is_dis? == false && @lab.frr_lan_id == ISIS4R_LAN_ID
    end
    assert_equal ISIS4R_LAN_ID, isis4r["lan_id"]
  end

  # FRR at a higher priority than isis4r's: FRR is DIS on both sides'
  # account, and isis4r reports the LAN ID FRR's hellos carry.
  def test_frr_is_dis_and_isis4r_agrees
    @lab.start(network: :broadcast, isis4r: { priority: 10 })
    assert_eventually("adjacency did not come up on the LAN") { both_up? }
    assert_eventually("isis4r and FRR do not agree that FRR is DIS") do
      isis4r["dis"] == FrrLab::FRR_ID && @lab.frr_is_dis? == true
    end
    # Measured on FRR 8.4.4: its first hellos carry a LAN ID of zeros,
    # until its own election, and isis4r reports what the DIS reports
    # (clause 8.4.4), so wait for FRR's own. Measured once at 9 ms after
    # isis4r's election.
    pattern = /\A#{Regexp.escape(FrrLab::FRR_ID)}\.\h\h\z/
    assert_eventually("isis4r did not take up FRR's LAN ID") do
      lan_id = isis4r["neighbors"].first&.dig("lan_id")
      lan_id&.match?(pattern) && !lan_id.end_with?(".00") && isis4r["lan_id"] == lan_id
    end
  end

  # The gate's "through a DIS change": FRR's priority raised past
  # isis4r's moves the DIS to FRR, and both sides follow, with no
  # adjacency going down on the way.
  def test_both_follow_a_dis_change
    @lab.start(network: :broadcast, isis4r: { priority: 100 })
    assert_eventually("isis4r did not become DIS") { both_up? && isis4r["dis"] == "self" && @lab.frr_is_dis? == false }
    @lab.vtysh_config("interface veth0", "isis priority 127")
    assert_eventually("the DIS did not move to FRR on both sides", 10) do
      isis4r["dis"] == FrrLab::FRR_ID && @lab.frr_is_dis? == true && isis4r["lan_id"].start_with?(FrrLab::FRR_ID)
    end
    refute_includes @lab.isis4r_log, "-> down", @lab.report
    assert_match(/DIS this system .* -> #{Regexp.escape(FrrLab::FRR_ID)}/, @lab.isis4r_log)
  end

  # FRR goes silent: isis4r expires it after its holding time and, alone,
  # elects no DIS (clause 8.4.4), so its LAN ID goes back to its own.
  def test_isis4r_expires_frr_and_holds_no_dis_alone
    @lab.start(network: :broadcast, isis4r: { priority: 10 })
    assert_eventually("FRR did not become DIS") { both_up? && isis4r["dis"] == FrrLab::FRR_ID }
    @lab.stop_frr_isisd
    assert_eventually("isis4r kept FRR after it went silent", 10) { isis4r["neighbors"].empty? }
    assert_nil isis4r["dis"]
    assert_equal ISIS4R_LAN_ID, isis4r["lan_id"]
  end
end
