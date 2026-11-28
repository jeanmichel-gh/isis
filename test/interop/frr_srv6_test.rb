# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"

# SRv6 between isisd and FRR's isisd on one point to point link, at Level
# 1 (docs/design/srv6.md, step 2's gate): FRR lists isisd in `show isis
# segment-routing srv6 node`, and decodes its locator, its End and
# End.DT6 SIDs and its End.X SID. Reading FRR's in return is step 3.
#
# isisd is 0000.0000.0001 with the locator fc00:0:1::/48, FRR
# 0000.0000.0002 with fc00:0:2::/48, both block 32, node 16, function 16.
#
# Runs only as root with FRR installed and ISIS_FRR=1.
class TestFrrSrv6 < Minitest::Test
  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
    @lab = FrrLab.new("s6#{Process.pid % 10_000}")
  end

  def teardown
    @lab&.stop
  end

  # FRR's locator is zebra's, so it goes in through vtysh with the line
  # that names it under router isis, once FRR is up.
  def start
    @lab.start(daemon: true, ipv6: true, frr_loopback6: "2001:db8:ff::2/128",
               isis4r: { hostname: "isisd", router_id: "10.255.0.1",
                         srv6: { locators: [{ name: "main", prefix: "fc00:0:1::/48",
                                              structure: { block: 32, node: 16, function: 16, argument: 0 } }] } },
               frr_zebra: ["segment-routing", "srv6", "locators", "locator MAIN",
                           "prefix fc00:0:2::/48 block-len 32 node-len 16 func-bits 16", "exit", "exit", "exit", "exit",
                           "router isis LAB", "segment-routing srv6", "locator MAIN"])
    assert @lab.wait_for(40) { adjacency_up? && frr_holds_isisd? }, "adjacency and LSPs\n#{probe}"
  end

  def adjacency_up?
    @lab.isisd("show.adjacencies").any? { _1["state"] == "up" } && @lab.frr_adjacency_state == "Up"
  rescue SystemCallError
    false
  end

  def frr_holds_isisd? = frr_lsp.include?("SRv6 End.X SID")

  # FRR's decode of isisd's LSP.
  def frr_lsp = @lab.vtysh("show isis database detail isisd.00-00")

  def probe
    [@lab.vtysh("show isis neighbor"), @lab.vtysh("show isis database detail"),
     @lab.vtysh("show isis segment-routing srv6 node")].join("\n")
  end

  def test_frr_reads_isisds_srv6
    start
    nodes = @lab.vtysh("show isis segment-routing srv6 node")
    # By System ID, algorithm 0. isisd sends no MSD (the design's decision
    # 5), so FRR shows 0 for each: RFC 9352 section 4.1, "If no value is
    # advertised, the supported value is 0."
    assert_match(/^ #{FrrLab::ISIS4R_ID}\s+SPF\s+0\s+0\s+0\s+0\s*$/, nodes, "FRR lists isisd as an SRv6 node")

    lsp = frr_lsp
    assert_match(/SRv6: O:0/, lsp)
    assert_match(%r{SRv6 Locator: fc00:0:1::/48 \(Metric: 0\)}, lsp)
    assert_match(/SRv6 End SID Endpoint Behavior: End, SID value: fc00:0:1::$/, lsp)
    assert_match(/SRv6 End SID Endpoint Behavior: End\.DT6, SID value: fc00:0:1:1::$/, lsp)
    assert_match(/SRv6 End\.X SID: fc00:0:1:2::, Algorithm: SPF, Weight: 0, Endpoint Behavior: End\.X, Flags: B:0, S:0, P:0/,
                 lsp)
    assert_match(/Locator Block length: 32, Locator Node length: 16, Function length: 16, Argument length: 0/, lsp)
    assert_match(%r{IPv6 Reachability: fc00:0:1::/48 \(Metric: 0\)}, lsp)

    # The locator in TLV 236 gives FRR a route to it through isisd.
    route = -> { @lab.vtysh("show ipv6 route fc00:0:1::/48") }
    assert @lab.wait_for(20) { route.call.match?(/Routing entry for fc00:0:1::\/48.*Known via "isis"/m) },
           "FRR routes to isisd's locator\n#{route.call}"
  end
end
