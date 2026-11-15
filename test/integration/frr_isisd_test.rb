# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"

# isisd, the executable, against FRR's isisd on a point to point link: it
# reads its YAML file, brings the adjacency up, and its API shows what it
# learnt, named by hostname as FRR names it. This is what routescope
# reads, so the API's answers are checked against FRR's own.
#
# Runs only as root with FRR installed and ISIS_FRR=1.
class TestFrrIsisd < Minitest::Test
  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
    @lab = FrrLab.new("isisd#{Process.pid % 10_000}")
  end

  def teardown
    @lab&.stop
  end

  def assert_eventually(message, timeout = 20, &block)
    assert @lab.wait_for(timeout, &block), "#{message}\n#{@lab.report}"
  end

  def adjacency
    @lab.isisd("show.adjacencies").first
  rescue SystemCallError
    nil
  end

  def test_adjacency_routes_and_names
    @lab.start(daemon: true, isis4r: { hostname: "isis4r-a" }, frr_loopback: "198.51.100.2/32")
    assert_eventually("isisd's adjacency did not come up") { adjacency&.fetch("state") == "up" }
    assert_eventually("FRR's adjacency did not come up") { @lab.frr_adjacency_state == "Up" }
    a = adjacency
    assert_equal ["veth0", 1, FrrLab::FRR_ID, "10.0.12.2", ["49.0001"]],
                 a.values_at("interface", "level", "system_id", "address", "areas")
    # FRR's hostname, from its LSP's TLV 137, once isisd holds the LSP.
    assert_eventually("isisd does not name FRR by its hostname", 30) { adjacency&.fetch("hostname") == @lab.name }
    assert_eventually("FRR does not name isis4r", 30) do
      @lab.vtysh("show isis neighbor").lines.any? { |l| l.split.first == "isis4r-a" }
    end

    # The database: both LSPs, each named, isis4r's own marked, at FRR's
    # sequence for FRR's.
    assert_eventually("isisd's database does not hold FRR's LSP", 30) do
      @lab.isisd("show.database").any? { _1["hostname"] == @lab.name }
    end
    rows = @lab.isisd("show.database")
    own = rows.find { _1["self"] }
    assert_equal ["#{FrrLab::ISIS4R_ID}.00-00", "isis4r-a"], own.values_at("lsp_id", "hostname")
    frr = rows.find { _1["lsp_id"] == "#{FrrLab::FRR_ID}.00-00" }
    assert_eventually("the sequence isisd shows is not FRR's") do
      seq = @lab.frr_database["#{FrrLab::FRR_ID}.00-00"]&.fetch("sequence")
      @lab.isisd("show.database").find { _1["lsp_id"] == frr["lsp_id"] }&.fetch("sequence") == seq
    end

    # The route to FRR's loopback, through FRR's address on veth0.
    assert_eventually("isisd has no route to FRR's loopback", 60) do
      @lab.isisd("show.routes").any? { _1["prefix"] == "198.51.100.2/32" }
    end
    route = @lab.isisd("show.routes").find { _1["prefix"] == "198.51.100.2/32" }
    assert_equal [{ "address" => "10.0.12.2", "interface" => "veth0" }], route["next_hops"]

    # Each node's TLV 132 in show.topology: FRR's as FRR itself shows its
    # LSP, and isis4r's own. Which addresses FRR puts there is FRR's
    # choice: 10.5.1 with a loopback sent the loopback alone, measured in
    # CI 2026-11-15, where the 8.4.4 fixture without one has 10.0.12.2.
    nodes = @lab.isisd("show.topology", level: 1)["nodes"].to_h { [_1["id"], _1] }
    frr_says = @lab.frr_database_detail(1).fetch("#{FrrLab::FRR_ID}.00-00").scan(/IPv4 Interface Address: (\S+)/).flatten
    refute_empty frr_says, "FRR shows no TLV 132 in its LSP"
    assert_equal frr_says, nodes.fetch("#{FrrLab::FRR_ID}.00")["interface_addresses"]
    assert_equal ["10.0.12.1"], nodes.fetch("#{FrrLab::ISIS4R_ID}.00")["interface_addresses"]

    overview = @lab.isisd("show.overview")
    assert_equal [FrrLab::ISIS4R_ID, "isis4r-a", 1], overview.values_at("system_id", "hostname", "adjacencies_up")

    # isis-cli prints the same as a table.
    table = @lab.isis_cli("show", "adjacencies")
    assert_match(/^interface\s+level\s+network\s+system_id\s+hostname\s+state/, table)
    assert_match(/^veth0\s+1\s+point-to-point\s+#{Regexp.escape(FrrLab::FRR_ID)}\s+#{@lab.name}\s+up/, table)
  end

  # TLV 22's link addresses, RFC 5305 sections 3.2 and 3.3, both ways.
  # FRR shows isisd's entry with sub-TLV 6, 10.0.12.1, and sub-TLV 8,
  # 10.0.12.2, and isisd's show.topology gives both. Measured 2026-11-15 on
  # FRR 10.5.1: without MPLS-TE its entry carries no sub-TLVs; with
  # "mpls-te on" it carries sub-TLV 8 alone, link-params enabled on veth0
  # or not. So FRR runs MPLS-TE here, and isisd reads its sub-TLV 8.
  def test_link_addresses_both_ways
    @lab.start(daemon: true, isis4r: { hostname: "isis4r-a" }, frr_loopback: "198.51.100.2/32",
               frr_router: ["mpls-te on", "mpls-te router-address 198.51.100.2"])
    own = "#{FrrLab::ISIS4R_ID}.00-00"
    assert_eventually("FRR does not show isisd's TLV 22 sub-TLVs", 40) do
      @lab.frr_database_detail(1)[own].to_s.include?("Remote Interface IP Address(es): 10.0.12.2")
    end
    detail = @lab.frr_database_detail(1).fetch(own)
    assert_match(/Extended Reachability: #{Regexp.escape(FrrLab::FRR_ID)}\.00 \(Metric: 10\)\n\s+Local Interface IP Address\(es\): 10\.0\.12\.1\n\s+Remote Interface IP Address\(es\): 10\.0\.12\.2\n/, detail)

    neighbors = lambda do |id|
      @lab.isisd("show.topology", level: 1)["nodes"].find { _1["id"] == id }&.fetch("neighbors")
    end
    assert_equal [{ "id" => "#{FrrLab::FRR_ID}.00", "metric" => 10, "style" => "wide",
                    "interface_address" => "10.0.12.1", "neighbor_address" => "10.0.12.2" }],
                 neighbors.call("#{FrrLab::ISIS4R_ID}.00")
    assert_eventually("isisd does not read FRR's sub-TLV 8", 40) do
      neighbors.call("#{FrrLab::FRR_ID}.00")&.any? { _1["neighbor_address"] == "10.0.12.1" }
    end
    assert_equal [{ "id" => "#{FrrLab::ISIS4R_ID}.00", "metric" => 10, "style" => "wide",
                    "neighbor_address" => "10.0.12.1" }], neighbors.call("#{FrrLab::FRR_ID}.00")
  end

  # The log on standard output says what isisd started as, and the API
  # stops answering once it is stopped, its socket removed.
  def test_starts_and_stops
    @lab.start(daemon: true, isis4r: { hostname: "isis4r-a" })
    assert_eventually("isisd did not answer") { adjacency || (@lab.isisd("show.overview") rescue nil) }
    assert_includes @lab.isis4r_log, "isisd #{ISIS::VERSION} started as #{FrrLab::ISIS4R_ID} (isis4r-a), level 1, on veth0"
    @lab.stop_isis4r
    refute File.exist?(@lab.isisd_socket)
    assert_includes @lab.isis4r_log, "isisd stopping"
  end
end
