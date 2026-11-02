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

    overview = @lab.isisd("show.overview")
    assert_equal [FrrLab::ISIS4R_ID, "isis4r-a", 1], overview.values_at("system_id", "hostname", "adjacencies_up")

    # isis-cli prints the same as a table.
    table = @lab.isis_cli("show", "adjacencies")
    assert_match(/^interface\s+level\s+network\s+system_id\s+hostname\s+state/, table)
    assert_match(/^veth0\s+1\s+point-to-point\s+#{Regexp.escape(FrrLab::FRR_ID)}\s+#{@lab.name}\s+up/, table)
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
