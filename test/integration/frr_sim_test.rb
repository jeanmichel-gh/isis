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
# isis4r runs as exe/isis4r-sim, and the tests drive it through its API,
# as routescope's scenarios do.
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

  # More LSPs than one CSNP holds (RFC 1142 7.3.15.3): 18 by 18 systems,
  # 326 LSPs with FRR's and the simulator's, over a link of 1500 octets.
  # isis4r sends its CSNPs as a set of ranges, FRR its own; both end with
  # the same database.
  BIG = { "grid" => { "rows" => 18, "columns" => 18, "metric" => 10, "loopbacks" => "10.201.0.0/16" },
          "links" => [{ "from" => "s1", "to" => "r1c1" }] }.freeze

  def test_a_database_larger_than_one_csnp
    @lab.start(sim: BIG)
    assert_eventually("FRR's adjacency with the simulator did not come up") { @lab.frr_adjacency_state == "Up" }
    assert_eventually("FRR does not hold all 326 Level 1 LSPs", 120) { @lab.frr_database(1).size == 326 }
    assert_eventually("isis4r does not hold FRR's LSP", 60) do
      Array(@lab.isisd("show.database", "level" => 1)).size == 326
    end
  end

  def frr_metric(prefix)
    r = @lab.frr_route(prefix)
    r && r["protocol"] == "isis" ? r["metric"] : nil
  end

  def sim(action, params = {})
    @lab.isisd("sim.#{action}", params)
  end

  # Each action through the API reaches FRR's routes: a metric, a link
  # down, an overload, a withdrawn group, then a flush and a restore.
  def test_frr_follows_the_actions
    @lab.start(sim: SIM)
    assert_eventually("FRR has no route to r2c3", 60) { frr_metric("10.200.0.6/32") == 50 }

    sim("link.metric", "link" => "s1--r1c1", "metric" => 40)
    assert_eventually("FRR did not follow the metric to 80") { frr_metric("10.200.0.6/32") == 80 }
    sim("link.metric", "link" => "s1--r1c1", "metric" => 10)

    # Every way from r1c1 into the rest of the grid goes down.
    sim("link.down", "link" => "r1c1--r1c2")
    sim("link.down", "link" => "r1c1--r2c1")
    assert_eventually("FRR still reaches r2c3 with r1c1 cut off") { frr_metric("10.200.0.6/32").nil? }
    assert_equal 20, frr_metric("10.200.0.1/32")
    sim("link.up", "link" => "r1c1--r1c2")
    sim("link.up", "link" => "r1c1--r2c1")
    assert_eventually("FRR did not come back to 50") { frr_metric("10.200.0.6/32") == 50 }

    # Overloaded, r1c1 carries no transit: FRR loses the grid behind it.
    sim("router.overload", "router" => "r1c1", "on" => true)
    assert_eventually("FRR still routes through an overloaded r1c1") { frr_metric("10.200.0.6/32").nil? }
    sim("router.overload", "router" => "r1c1", "on" => false)
    assert_eventually("FRR did not route through r1c1 again") { frr_metric("10.200.0.6/32") == 50 }

    sim("prefixes.withdraw", "router" => "r2c3", "prefix" => "30.0.0.0/24")
    assert_eventually("FRR kept a withdrawn group") { frr_metric("30.0.2.0/24").nil? }
    sim("prefixes.advertise", "router" => "r2c3", "prefix" => "30.0.0.0/24")
    assert_eventually("FRR did not learn the group again") { frr_metric("30.0.2.0/24") == 60 }

    # Flushed, FRR holds purges and no routes; restored, both come back.
    sim("flush")
    assert_eventually("FRR still routes to a flushed grid") { frr_metric("10.200.0.6/32").nil? }
    sim("restore")
    assert_eventually("FRR did not learn the grid again after a restore", 60) { frr_metric("10.200.0.6/32") == 50 }
  end
end
