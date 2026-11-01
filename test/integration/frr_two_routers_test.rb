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
    # LSP, plus 10 and 10.
    assert_equal 30, @lab.isis4r_routes.dig(FRR2_LOOPBACK, "metric"), @lab.report
  end
end
