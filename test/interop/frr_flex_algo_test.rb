# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"

# Flex-algo between isisd and FRR's isisd on one point to point link, at
# Level 1 (docs/design/flex-algo.md, step 7): each reads the other's FAD
# and both select the same winner, each reads the other's Prefix-SID for
# 128 into its label table, and each reads the other's link attributes.
#
# isisd is 0000.0000.0001, SRGB 16000, loopback 10.255.0.1/32 with index
# 1, and 101 for 128. FRR is 0000.0000.0002, SRGB 18000, loopback
# 10.255.0.2/32 with index 2, and 102 for 128. Both name bit 1 red and
# bit 40 far, and put red on the link.
#
# Runs only as root with FRR installed and ISIS_FRR=1.
class TestFrrFlexAlgo < Minitest::Test
  K = 128

  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
    @lab = FrrLab.new("fa#{Process.pid % 10_000}")
  end

  def teardown
    @lab&.stop
  end

  # Both routers, FRR's FAD at +frr_priority+ and isisd's at 100.
  def start(frr_priority: 200)
    @lab.start(daemon: true, frr_loopback: "10.255.0.2/32",
               isis4r: { hostname: "isisd", segment_routing: { srgb: [{ start: 16_000, size: 8_000 }] },
                         affinity_map: { red: 1, far: 40 },
                         flex_algo: [{ algorithm: K, priority: 100, exclude_any: ["far"] }],
                         prefixes: [{ prefix: "10.255.0.1/32", metric: 0, sid: 1, algorithm_sids: { K => 101 } }],
                         link: { affinity: ["red"], delay: 5_000, te_metric: 100 } },
               frr_global: ["affinity-map red bit-position 1", "affinity-map far bit-position 40"],
               frr_interface: ["link-params", " enable", " metric 77", " delay 5000 min 4000 max 6000",
                               " affinity red", " exit-link-params"],
               frr_router: ["segment-routing on", "segment-routing global-block 18000 25999",
                            "segment-routing prefix 10.255.0.2/32 index 2",
                            "segment-routing prefix 10.255.0.2/32 algorithm #{K} index 102",
                            "flex-algo #{K}", " dataplane sr-mpls", " advertise-definition", " priority #{frr_priority}",
                            " affinity exclude-any far", " exit"])
    assert @lab.wait_for(40) { adjacency_up? && isisd_holds_frr? }, "adjacency and LSPs\n#{probe}"
  end

  def adjacency_up? = @lab.isisd("show.adjacencies").any? { _1["state"] == "up" } && @lab.frr_adjacency_state == "Up"
  def isisd_holds_frr? = @lab.isisd("show.database").any? { _1["lsp_id"] == "#{FrrLab::FRR_ID}.00-00" }

  def isisd_algo
    @lab.isisd("show.flex_algo")["levels"]["1"]["algorithms"].find { _1["algorithm"] == K }
  end

  # Everything both sides show of flex-algo, for a failure's message.
  def probe
    frr = ["show isis flex-algo", "show isis database detail", "show mpls table json",
           "show isis route algorithm #{K}", "show isis segment-routing node"].map { "--- FRR: #{_1}\n#{@lab.vtysh(_1)}" }
    isisd = %w[show.flex_algo show.labels].map { "--- isisd: #{_1}\n#{JSON.pretty_generate(@lab.isisd(_1, 'level' => 1))}" }
    topo = "--- isisd: show.topology\n#{JSON.pretty_generate(@lab.isisd('show.topology', 'level' => 1))}"
    [*frr, *isisd, topo].join("\n")
  rescue StandardError => e
    "probe failed: #{e.message}\n#{@lab.report}"
  end

  # FRR's FAD wins on priority; then isisd's, raised by policy.flex_algo.
  # Each time both name the same winner.
  def test_fad_read_both_ways
    start
    assert @lab.wait_for(30) { isisd_algo&.dig("winner", "origin") == FrrLab::FRR_ID }, "isisd selects FRR's FAD\n#{probe}"
    assert isisd_algo["participating"], probe
    assert_match(/Source.*#{@lab.name}|Source.*0000\.0000\.0002/, @lab.vtysh("show isis flex-algo #{K}"), probe)

    @lab.isisd("policy.flex_algo", "algorithm" => K, "priority" => 250)
    assert @lab.wait_for(30) { isisd_algo&.dig("winner", "origin") == FrrLab::ISIS4R_ID }, "isisd selects its own\n#{probe}"
    assert @lab.wait_for(30) { @lab.vtysh("show isis flex-algo #{K}").match?(/Source.*(isisd|0000\.0000\.0001)/) },
           "FRR selects isisd's FAD\n#{probe}"
  end

  # isisd's label 16102, FRR's index 102 in isisd's SRGB, pops toward FRR;
  # FRR's 18101 pops toward isisd.
  def test_prefix_sids_read_both_ways
    start
    row = nil
    assert @lab.wait_for(30) {
      row = @lab.isisd("show.labels", "level" => 1).find { _1["label"] == 16_102 }
    }, "isisd's label for FRR's Prefix-SID for #{K}\n#{probe}"
    assert_equal ["10.255.0.2/32", K, [3]], [row["fec"], row["algorithm"], row["next_hops"].map { _1["label"] }], probe
    frr = nil
    assert @lab.wait_for(30) { frr = @lab.frr_json("show mpls table")["18101"] }, "FRR's label for isisd's 101\n#{probe}"
    assert_equal [["10.0.12.1", 3]], frr["nexthops"].map { _1.values_at("nexthop", "outLabel") }, probe
  end

  # isisd reads FRR's ASLA: red, TE metric 77, minimum delay 4000. FRR
  # prints isisd's ASLA: red, TE metric 100, delay 5000.
  def test_link_attributes_read_both_ways
    start
    link = nil
    assert @lab.wait_for(30) {
      node = @lab.isisd("show.topology", "level" => 1)["nodes"].find { _1["id"] == "#{FrrLab::FRR_ID}.00" }
      link = node && node["neighbors"].find { _1["id"] == "#{FrrLab::ISIS4R_ID}.00" }
    }, "isisd's view of FRR's link\n#{probe}"
    assert_equal [[1], 77, 4_000], [link["affinity"], link["te_metric"], link.dig("delay", "min")], probe
    detail = @lab.frr_database_detail(1)["#{FrrLab::ISIS4R_ID}.00-00"].to_s
    assert_match(/ASLA|Application/, detail, probe)
  end
end
