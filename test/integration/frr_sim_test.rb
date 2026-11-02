# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"

# The simulator against FRR's isisd on a point to point link: FRR learns
# the simulated area through its one adjacency with the simulator, holds
# every simulated LSP, names each system by its hostname, and routes to
# the far end of the grid.
#
#   FRR -- s1 (isis4r) -- r1c1 -- r1c2 -- r1c3
#                          |       |       |
#                         r2c1 -- r2c2 -- r2c3   + 30.0.0.0/24 .. 30.0.2.0/24
#
# Every metric 10, so FRR reaches r2c3's loopback, 10.200.0.6, at 50.
#
# Runs only as root with FRR installed and ISIS_FRR=1.
class TestFrrSim < Minitest::Test
  SIM = { "grid" => { "rows" => 2, "columns" => 3, "metric" => 10, "loopbacks" => "10.200.0.0/24" },
          "routers" => [{ "name" => "r2c3", "prefixes" => [{ "prefix" => "30.0.0.0/24", "count" => 3 }] }],
          "links" => [{ "from" => "s1", "to" => "r1c1" }] }.freeze

  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
    @lab = FrrLab.new("sim#{Process.pid % 10_000}")
  end

  def teardown
    @lab&.stop
  end

  def assert_eventually(message, timeout = 30, &block)
    assert @lab.wait_for(timeout, &block), "#{message}\n#{@lab.report}"
  end

  def test_frr_learns_the_simulated_area
    @lab.start(sim: SIM)
    assert_eventually("FRR's adjacency with the simulator did not come up") { @lab.frr_adjacency_state == "Up" }
    # FRR's own, the simulator's, and the six grid systems'.
    assert_eventually("FRR does not hold the eight Level 1 LSPs", 60) { @lab.frr_database(1).size == 8 }
    assert_eventually("FRR does not name r2c3") do
      @lab.vtysh("show isis hostname").lines.any? { |l| l.split.include?("r2c3") && l.include?("0000.0001.0203") }
    end
    assert_eventually("FRR has no route to r2c3's loopback", 60) do
      r = @lab.frr_route("10.200.0.6/32")
      r && r["protocol"] == "isis" && r["metric"] == 50 && r["nexthops"].any? { |n| n["ip"] == "10.0.12.1" }
    end
    assert_eventually("FRR has no route to r2c3's prefixes") do
      (r = @lab.frr_route("30.0.2.0/24")) && r["protocol"] == "isis" && r["metric"] == 60
    end
  end
end
