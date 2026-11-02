# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"

# Two FRRs in a line behind isis4r: isis4r, 10.0.12.1, to the first FRR,
# 0000.0000.0002 at 10.0.12.2, which reaches the second, 0000.0000.0003 at
# 10.0.23.3, from its veth1 at 10.0.23.2. Every link is point to point at
# FRR's default metric, 10, and isis4r's circuit is at 10.
#
# Phase 2 gate 2's level boundary and gate 3's route comparison, each with
# more than one independent router. Runs only as root with FRR installed
# and ISIS_FRR=1, as frr_p2p_test.rb does.
class TestFrrTwoRouters < Minitest::Test
  FRR2_LOOPBACK = "198.51.100.3/32"

  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
    @lab = FrrLab.new("two#{Process.pid % 10_000}")
  end

  def teardown
    @lab&.stop
  end

  def assert_eventually(message, timeout = 20, &block)
    assert @lab.wait_for(timeout, &block), "#{message}\n#{@lab.report}"
  end

  # LSP IDs in a level's database, with lifetime left, on each side.
  def isis4r_lsp_ids(level = nil)
    @lab.isis4r_database(level).select { |_, e| e["lifetime"].positive? }.keys.sort
  end

  def frr_lsp_ids(level, router: @lab.name)
    @lab.frr_database(level, router: router).reject { |_, e| e["purged"] }.keys.sort
  end

  def own(id) = "#{id}.00-00"

  # Gate 2, the level boundary. isis4r is Level 1 in 49.0001, the first FRR
  # Level 1 and 2 in 49.0001, the second Level 2 only in 49.0002. isis4r's
  # Level 1 database holds the two Level 1 LSPs of its area and nothing of
  # the second FRR; the second FRR's Level 2 database holds the two Level 2
  # LSPs and nothing of isis4r. And no route crosses into isis4r from Level
  # 2. Measured on the way, FRR 8.4.4 with its defaults: the first FRR's
  # Level 2 LSP carries only its own interfaces' prefixes, not isis4r's
  # 192.0.2.1/32, so the second FRR has no route to it; and its Level 1
  # LSP has the attached bit set.
  def test_the_level_boundary_holds
    @lab.start(frr_is_type: "level-1-2", frr2: { is_type: "level-2-only", area: "49.0002", loopback: FRR2_LOOPBACK })
    l1 = [own(FrrLab::ISIS4R_ID), own(FrrLab::FRR_ID)].sort
    assert_eventually("the Level 1 databases do not agree on the area's two LSPs", 60) do
      isis4r_lsp_ids == l1 && frr_lsp_ids(1) == l1
    end
    l2 = [own(FrrLab::FRR_ID), own(FrrLab::FRR2_ID)].sort
    assert_eventually("the second FRR's Level 2 database is not the two Level 2 LSPs", 60) do
      frr_lsp_ids(2, router: @lab.frr2_name) == l2
    end
    sleep 5
    assert_equal l1, isis4r_lsp_ids, @lab.report
    assert_empty frr_lsp_ids(1, router: @lab.frr2_name), @lab.report
    refute_includes frr_lsp_ids(2, router: @lab.frr2_name), own(FrrLab::ISIS4R_ID), @lab.report
    assert_nil @lab.isis4r_routes[FRR2_LOOPBACK], "isis4r has a Level 2 route at Level 1\n#{@lab.report}"
  end

  # The same boundary, from inside the area: the first FRR sets ATT in its
  # Level 1 LSP, as FRR 8.4.4 does once it reaches another area, so
  # isis4r's way out is a default route to it, at the link's 10 (RFC 1142
  # 7.2.9.1, RFC 1195 section 1.2).
  def test_a_level_1_system_defaults_to_the_attached_frr
    @lab.start(frr_is_type: "level-1-2", frr2: { is_type: "level-2-only", area: "49.0002", loopback: FRR2_LOOPBACK })
    assert_eventually("isis4r has no default route to the attached FRR", 60) do
      @lab.isis4r_routes["0.0.0.0/0"] ==
        { "prefix" => "0.0.0.0/0", "metric" => 10,
          "next_hops" => [{ "address" => "10.0.12.2", "circuit" => "veth0" }] }
    end
    assert_match(/^#{Regexp.escape(@lab.name)}\.00-00\s+\*\s+\d+\s+0x\h+\s+0x\h+\s+\d+\s+1\/0\/0/,
                 @lab.vtysh("show isis database"), @lab.report)
  end

  # The other way round: isis4r is the attached one (RFC 1142 7.2.9.2).
  # isis4r at both levels in 49.0001, the first FRR Level 1 only behind
  # its veth0, and the second FRR Level 2 only in 49.0002 on isis4r's
  # veth1. isis4r's Level 2 routes reach 49.0002, so its Level 1 LSP 0
  # sets ATT, FRR shows 1/0/0 for it, and FRR's way out is a default route
  # to isis4r at the link's 10. isis4r itself, attached, adds no default
  # route ("Self"). When the link to 49.0002 goes, isis4r reaches no
  # other area, clears ATT, and FRR's default route goes.
  def test_isis4r_sets_att_when_it_reaches_another_area
    @lab.start(level: "1-2", frr_is_type: "level-1",
               frr2: { is_type: "level-2-only", area: "49.0002", loopback: FRR2_LOOPBACK,
                       isis4r_link: { frr_metric: 10, isis4r_metric: 10 } })
    lsp = /^#{Regexp.escape(FrrLab::ISIS4R_ID)}\.00-00\s+\d+\s+0x\h+\s+0x\h+\s+\d+\s+(\d)\/0\/0/
    att = -> { @lab.vtysh("show isis database")[lsp, 1] }
    assert_eventually("FRR does not see ATT in isis4r's Level 1 LSP", 60) { att.call == "1" }
    assert_eventually("FRR has no default route to isis4r", 60) do
      @lab.frr_isis_routes["0.0.0.0/0"] == { "metric" => 10, "interface" => "veth0", "next_hop" => "10.0.12.1" }
    end
    assert_nil @lab.isis4r_routes(1)["0.0.0.0/0"], @lab.report
    assert_includes @lab.isis4r_log, "AttachedFlag set in the Level 1 LSP", @lab.report
    @lab.isis4r_frr2_link_down
    assert_eventually("FRR still sees ATT in isis4r's Level 1 LSP", 30) { att.call == "0" }
    assert_eventually("FRR keeps a default route to isis4r", 30) { @lab.frr_isis_routes["0.0.0.0/0"].nil? }
  end

  # Route leaking (Phase 3 gate 1), on the same topology: isis4r at both
  # levels between a Level 1 FRR and the second FRR, Level 2 in 49.0002,
  # with its loopback 198.51.100.3/32. isis4r starts leaking nothing (RFC
  # 5302 section 4's default), so the Level 1 FRR has only its default
  # route. A policy change through the control file leaks
  # 198.51.100.0/24: isis4r's Level 1 LSP carries 198.51.100.3/32 at its
  # Level 2 metric, 20, with the up/down bit, which FRR shows as "Down",
  # and FRR installs it at 30 through isis4r. A second change leaks
  # nothing again, and FRR withdraws both the advertisement and the
  # route.
  def test_a_leak_policy_change_installs_and_withdraws_at_frr
    @lab.start(level: "1-2", frr_is_type: "level-1",
               frr2: { is_type: "level-2-only", area: "49.0002", loopback: FRR2_LOOPBACK,
                       isis4r_link: { frr_metric: 10, isis4r_metric: 10 } })
    leaked = %r{Extended IP Reachability: 198\.51\.100\.3/32 \(Metric: 20\) Down}
    lsp = -> { @lab.frr_database_detail(1)["#{FrrLab::ISIS4R_ID}.00-00"].to_s }
    assert_eventually("FRR has no default route to isis4r", 60) { @lab.frr_isis_routes.key?("0.0.0.0/0") }
    assert_nil @lab.frr_isis_routes[FRR2_LOOPBACK], @lab.report
    refute_match leaked, lsp.call, @lab.report
    @lab.isis4r_control(leak: ["198.51.100.0/24"])
    assert_eventually("FRR does not hold isis4r's leaked prefix with up/down set", 30) { lsp.call.match?(leaked) }
    assert_eventually("FRR did not install the leaked prefix at 30 through isis4r", 30) do
      @lab.frr_isis_routes[FRR2_LOOPBACK] == { "metric" => 30, "interface" => "veth0", "next_hop" => "10.0.12.1" }
    end
    @lab.isis4r_control(leak: [])
    assert_eventually("FRR still holds the leaked prefix", 30) { !lsp.call.match?(leaked) }
    assert_eventually("FRR kept the route to the leaked prefix", 30) { @lab.frr_isis_routes[FRR2_LOOPBACK].nil? }
    assert_includes @lab.isis4r_log, "198.51.100.3/32 no longer leaked into Level 1", @lab.report
  end

  # Gate 3, routes computed against an independent router's on the same
  # topology, all Level 1 in one area. Each prefix the first FRR reaches
  # through the second, isis4r reaches at the first FRR's metric plus its
  # own link, 10, through the first FRR. Each prefix the first FRR reaches
  # through isis4r, the second FRR reaches at the first's metric plus 10,
  # through the first. Neither expectation is isis4r's own arithmetic: both
  # come from the FRR in the middle.
  #
  # Except the prefixes the first FRR advertises itself, the two subnets.
  # Measured on FRR 8.4.4: it lists such a prefix through its neighbour,
  # at 20, rather than its own copy, so its table does not give the
  # distance from it. Those are left out.
  def test_routes_match_the_router_in_the_middle
    @lab.start(frr2: { is_type: "level-1", loopback: FRR2_LOOPBACK })
    mine = lambda do
      @lab.frr_database_detail(1)[own(FrrLab::FRR_ID)].to_s.scan(/IP Reachability: (\S+)/).flatten
    end
    via = ->(hop) { @lab.frr_isis_routes.select { |p, r| r["next_hop"] == hop && !mine.call.include?(p) } }
    beyond = -> { via.call("10.0.23.3") }
    toward = -> { via.call("10.0.12.1") }
    assert_eventually("the first FRR reaches nothing through either side", 60) do
      beyond.call.key?(FRR2_LOOPBACK) && toward.call.key?("192.0.2.1/32")
    end
    assert_eventually("isis4r's routes beyond the first FRR do not match its", 30) do
      beyond.call.all? do |prefix, r|
        @lab.isis4r_routes[prefix] ==
          { "prefix" => prefix, "metric" => r["metric"] + 10,
            "next_hops" => [{ "address" => "10.0.12.2", "circuit" => "veth0" }] }
      end
    end
    assert_eventually("the second FRR's routes toward isis4r do not match the first's", 30) do
      far = @lab.frr_isis_routes(1, router: @lab.frr2_name)
      toward.call.all? { |prefix, r| far[prefix] == r.merge("metric" => r["metric"] + 10, "next_hop" => "10.0.23.2") }
    end
    # Our arithmetic, for the record: the second FRR's loopback at 10 in its
    # LSP, plus 10 and 10. And no default route: all one area, nobody
    # attached.
    assert_equal 30, @lab.isis4r_routes.dig(FRR2_LOOPBACK, "metric"), @lab.report
    assert_nil @lab.isis4r_routes["0.0.0.0/0"], @lab.report
  end

  # Equal cost paths. isis4r also has a link straight to the second FRR,
  # at 20 on both ends, so the second FRR's loopback is as far through the
  # first FRR as across it: the first FRR's own metric to it plus 10, or
  # its metric in the second FRR's LSP plus 20. isis4r takes both, the
  # first FRR first, the lower neighbour ID (RFC 1142 7.2.7). The second FRR
  # does the same toward isis4r's 192.0.2.1/32, which is what shows the
  # paths are really equal. When isis4r's direct link goes, the route keeps
  # only the first FRR.
  def test_equal_cost_paths_against_frr
    @lab.start(frr2: { is_type: "level-1", loopback: FRR2_LOOPBACK,
                       isis4r_link: { frr_metric: 20, isis4r_metric: 20 } })
    both = [{ "address" => "10.0.12.2", "circuit" => "veth0" }, { "address" => "10.0.13.3", "circuit" => "veth1" }]
    assert_eventually("isis4r does not reach the far loopback over both paths", 60) do
      @lab.isis4r_routes.dig(FRR2_LOOPBACK, "next_hops") == both
    end
    assert_eventually("the first FRR does not reach the far loopback", 30) do
      @lab.frr_isis_routes.key?(FRR2_LOOPBACK)
    end
    through_first = @lab.frr_isis_routes.dig(FRR2_LOOPBACK, "metric") + 10
    far_lsp = @lab.frr_database_detail(1)[own(FrrLab::FRR2_ID)].to_s
    across = far_lsp[%r{IP Reachability: 198\.51\.100\.3/32 \(Metric: (\d+)\)}, 1].to_i + 20
    assert_equal [through_first, through_first], [across, @lab.isis4r_routes.dig(FRR2_LOOPBACK, "metric")],
                 @lab.report
    assert_eventually("the second FRR does not reach 192.0.2.1/32 over both paths", 30) do
      @lab.frr_isis_next_hops(1, router: @lab.frr2_name)["192.0.2.1/32"].sort ==
        [%w[veth0 10.0.23.2], %w[veth1 10.0.13.1]]
    end
    @lab.isis4r_frr2_link_down
    assert_eventually("isis4r keeps the path whose link went down", 20) do
      @lab.isis4r_routes.dig(FRR2_LOOPBACK, "next_hops") == [both.first]
    end
    assert_equal through_first, @lab.isis4r_routes.dig(FRR2_LOOPBACK, "metric"), @lab.report
  end

  # Forwarding through a link failure (Phase 2 gate 4), on the same
  # equal cost triangle with a host behind isis4r. The kernel route to the
  # far loopback has both next hops, and the host reaches it. Then the far
  # end of isis4r's direct link goes down: isis4r's veth1 only loses
  # carrier, and the kernel would go on sending half the traffic into it.
  # When the adjacency's holding time runs out, isis4r replaces the route
  # with the one path left, the host still reaches the loopback, and no
  # route of isis4r's is left on veth1.
  def test_a_link_failure_moves_forwarding_to_the_other_path
    @lab.start(host: true, frr2: { is_type: "level-1", loopback: FRR2_LOOPBACK,
                                   isis4r_link: { frr_metric: 20, isis4r_metric: 20 } })
    far = FRR2_LOOPBACK.split("/").first
    both = ["#{far} metric 21", "nexthop via 10.0.12.2 dev veth0 weight 1",
            "nexthop via 10.0.13.3 dev veth1 weight 1"]
    assert_eventually("isis4r did not install the far loopback over both paths", 60) do
      @lab.isis4r_kernel_route(far) == both
    end
    assert_eventually("the host does not reach the far loopback", 30) { @lab.host_ping(far) }
    @lab.frr2_isis4r_link_down
    assert_eventually("isis4r did not move the far loopback to the first FRR", 20) do
      @lab.isis4r_kernel_route(far) == ["#{far} via 10.0.12.2 dev veth0 metric 21"]
    end
    refute_match(/veth1/, @lab.isis4r_kernel_routes, @lab.report)
    assert_eventually("the host does not reach the far loopback after the failure", 30) { @lab.host_ping(far) }
  end

  # Overload (RFC 1142 7.2.8.1 and 7.3.19.1) in a triangle where isis4r is
  # the cheap way between the two FRRs: its links at 10, the FRRs' own link
  # at 50. So the first FRR reaches the far loopback through isis4r, at
  # 10 + 10 + 10. Measured on FRR 8.4.4: an "isis metric" over 63 in its
  # startup file is dropped, missing from its running configuration, so
  # the expensive links here stay under it.
  def triangle(**isis4r)
    @lab.start(isis4r: isis4r, frr2: { is_type: "level-1", loopback: FRR2_LOOPBACK, link_metric: 50,
                                       isis4r_link: { frr_metric: 10, isis4r_metric: 10 } })
  end

  def test_without_overload_frr_goes_through_isis4r
    triangle
    assert_eventually("the first FRR does not reach the far loopback through isis4r at 30", 60) do
      @lab.frr_isis_routes[FRR2_LOOPBACK] == { "metric" => 30, "interface" => "veth0", "next_hop" => "10.0.12.1" }
    end
  end

  # With isis4r overloaded, FRR takes the expensive link, 50 + 10, and
  # still reaches isis4r's own prefix, which 7.2.8.1 lets it use. FRR shows
  # the bit as the OL column of isis4r's LSP.
  def test_frr_does_not_route_through_an_overloaded_isis4r
    triangle(overload: true)
    assert_eventually("the first FRR does not take its own link to the far loopback", 60) do
      @lab.frr_isis_routes[FRR2_LOOPBACK] == { "metric" => 60, "interface" => "veth1", "next_hop" => "10.0.23.3" }
    end
    assert_match(/^#{Regexp.escape(own(FrrLab::ISIS4R_ID))}\s+\d+\s+0x\h+\s+0x\h+\s+\d+\s+0\/0\/1/,
                 @lab.vtysh("show isis database"), @lab.report)
    assert_eventually("the first FRR does not reach isis4r's own prefix", 30) do
      @lab.frr_isis_routes.dig("192.0.2.1/32", "next_hop") == "10.0.12.1"
    end
  end

  # The other way: the first FRR overloaded with set-overload-bit, and
  # isis4r's direct link to the far FRR at 50, so isis4r would go through
  # the first FRR, 10 + 10 + 10, and must not: it goes direct, 50 + 10.
  # The first FRR's own prefixes stay reachable through it.
  def test_isis4r_does_not_route_through_an_overloaded_frr
    @lab.start(frr_router: ["set-overload-bit"],
               frr2: { is_type: "level-1", loopback: FRR2_LOOPBACK,
                       isis4r_link: { frr_metric: 50, isis4r_metric: 50 } })
    assert_eventually("isis4r does not go direct to the far loopback at 60", 60) do
      @lab.isis4r_routes[FRR2_LOOPBACK] ==
        { "prefix" => FRR2_LOOPBACK, "metric" => 60,
          "next_hops" => [{ "address" => "10.0.13.3", "circuit" => "veth1" }] }
    end
    assert_eventually("isis4r does not reach the first FRR's 10.0.23.0/24 through it", 30) do
      @lab.isis4r_routes.dig("10.0.23.0/24", "next_hops")&.include?({ "address" => "10.0.12.2", "circuit" => "veth0" })
    end
  end
end
