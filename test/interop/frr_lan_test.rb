# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"

# Phase 2 gate 1 against FRR's isisd on a broadcast circuit: both sides
# come up, agree on the Level 1 DIS and its LAN ID, and agree again when
# the DIS changes (RFC 1142 clauses 8.4.1 to 8.4.4); and with either side
# as DIS the databases agree, the DIS's pseudonode LSP included, and FRR
# routes to isis4r's prefix through the pseudonode (7.3.7, 7.3.8, 7.3.15);
# and they agree again through a DIS change either way, the old DIS's
# pseudonode purged on both sides (7.2.3, 7.3.16.4).
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

  # The LSPs each side holds, as LSP ID => sequence. isis4r's placeholders,
  # sequence 0, are requests and not LSPs (7.3.15.2 b 4).
  def isis4r_lsps
    @lab.isis4r_database.reject { |_, e| e["sequence"].zero? }.transform_values { |e| e["sequence"] }
  end

  def frr_lsps
    @lab.frr_database.transform_values { |e| e["sequence"] }
  end

  # Each side's LSPs as LSP ID => [sequence, purged], so a purge on one
  # side and a live LSP on the other do not count as agreeing.
  # +level+ picks one level when both run.
  def isis4r_view(level = nil)
    @lab.isis4r_database(level).reject { |_, e| e["sequence"].zero? }
        .transform_values { |e| [e["sequence"], e["lifetime"].zero?] }
  end

  def frr_view(level = nil)
    @lab.frr_database(level).transform_values { |e| [e["sequence"], e["purged"]] }
  end

  def frr_routes_isis4rs_prefix?
    route = @lab.frr_route("192.0.2.1/32")
    route && route["protocol"] == "isis" && route["installed"] &&
      route["nexthops"].any? { |n| n["ip"] == "10.0.12.1" && n["interfaceName"] == "veth0" }
  end

  # FRR holds isis4r's LSP naming the pseudonode +lan_id+ at metric 10
  # (7.3.7). Asserted on its own because the route does not show it:
  # measured on FRR 8.4.4, FRR installs 192.0.2.1/32 even when isis4r's LSP
  # names no pseudonode at all, so its SPF does not check the link from
  # isis4r back to the pseudonode.
  def assert_frr_holds_isis4r_naming(lan_id)
    line = "Extended Reachability: #{lan_id} (Metric: 10)"
    assert_eventually("FRR does not hold isis4r's LSP naming #{lan_id}") do
      @lab.frr_database_detail["#{FrrLab::ISIS4R_ID}.00-00"]&.include?(line)
    end
  end

  # isis4r as DIS: it sends the CSNPs and generates the pseudonode LSP,
  # and both databases hold the same three LSPs at the same sequences.
  # FRR's SPF reaches isis4r only through that pseudonode, so the route
  # to 192.0.2.1/32, which only isis4r advertises, shows FRR used it.
  def test_databases_agree_with_isis4r_as_dis
    @lab.start(network: :broadcast, isis4r: { priority: 100 })
    assert_eventually("isis4r did not become DIS") { both_up? && isis4r["dis"] == "self" }
    expected = ["#{FrrLab::ISIS4R_ID}.00-00", "#{FrrLab::ISIS4R_ID}.01-00", "#{FrrLab::FRR_ID}.00-00"].sort
    assert_eventually("the databases do not agree", 30) do
      isis4r_lsps.keys.sort == expected && isis4r_lsps == frr_lsps
    end
    assert_frr_holds_isis4r_naming(ISIS4R_LAN_ID)
    assert_eventually("FRR did not route to 192.0.2.1/32 through isis4r's pseudonode", 60) do
      frr_routes_isis4rs_prefix?
    end
  end

  # FRR as DIS: FRR's CSNPs and pseudonode LSP, and isis4r asks for what
  # it lacks in PSNPs. The same agreement, with FRR's pseudonode in place
  # of isis4r's, and isis4r's LSP naming it.
  def test_databases_agree_with_frr_as_dis
    @lab.start(network: :broadcast, isis4r: { priority: 10 })
    assert_eventually("FRR did not become DIS") { both_up? && isis4r["dis"] == FrrLab::FRR_ID }
    pattern = /\A#{Regexp.escape(FrrLab::FRR_ID)}\.(\h\h)-00\z/
    assert_eventually("the databases do not agree", 30) do
      lsps = isis4r_lsps
      pseudonodes = lsps.keys.grep(pattern).reject { |id| id.end_with?(".00-00") }
      lsps.size == 3 && pseudonodes.size == 1 && lsps.key?("#{FrrLab::ISIS4R_ID}.00-00") && lsps == frr_lsps
    end
    assert_frr_holds_isis4r_naming(isis4r["lan_id"])
    assert_eventually("FRR did not route to 192.0.2.1/32 through its pseudonode", 60) do
      frr_routes_isis4rs_prefix?
    end
  end

  # Routes computed across the LAN. isis4r to the pseudonode is 10, the
  # pseudonode to FRR 0 (RFC 1142 7.2.3), and FRR's loopback 10 in FRR's
  # LSP: 20 through 10.0.12.2, the address FRR's hellos carry. Our
  # arithmetic, the same whichever side is DIS.
  def assert_isis4r_reaches_frrs_loopback(dis)
    assert_eventually("the DIS is not #{dis}") { both_up? && isis4r["dis"] == dis }
    assert_eventually("isis4r does not reach 198.51.100.2/32 at 20 with #{dis} as DIS", 60) do
      @lab.isis4r_routes["198.51.100.2/32"] ==
        { "prefix" => "198.51.100.2/32", "metric" => 20,
          "next_hops" => [{ "address" => "10.0.12.2", "circuit" => "veth0" }] }
    end
  end

  def test_routes_computed_with_isis4r_as_dis
    @lab.start(network: :broadcast, frr_loopback: "198.51.100.2/32", isis4r: { priority: 100 })
    assert_isis4r_reaches_frrs_loopback("self")
  end

  def test_routes_computed_with_frr_as_dis
    @lab.start(network: :broadcast, frr_loopback: "198.51.100.2/32", isis4r: { priority: 10 })
    assert_isis4r_reaches_frrs_loopback(FrrLab::FRR_ID)
  end

  # isis4r is DIS, then FRR's priority goes past it: isis4r resigns and
  # purges its pseudonode (7.2.3), FRR generates its own, and both sides
  # hold the same LSPs, isis4r's old pseudonode as a purge on both.
  def test_databases_agree_through_a_dis_change_to_frr
    @lab.start(network: :broadcast, isis4r: { priority: 100 })
    assert_eventually("isis4r did not become DIS") { both_up? && isis4r["dis"] == "self" }
    old = "#{FrrLab::ISIS4R_ID}.01-00"
    assert_eventually("the databases do not agree before the change", 30) do
      isis4r_view.key?(old) && isis4r_view == frr_view
    end
    @lab.vtysh_config("interface veth0", "isis priority 127")
    assert_eventually("the DIS did not move to FRR") { isis4r["dis"] == FrrLab::FRR_ID && @lab.frr_is_dis? }
    assert_eventually("the databases do not agree after the change", 30) do
      view = isis4r_view
      view[old]&.last && view.keys.grep(/\A#{Regexp.escape(FrrLab::FRR_ID)}\.(?!00)\h\h-00\z/).size == 1 &&
        view == frr_view
    end
    assert_frr_holds_isis4r_naming(isis4r["lan_id"])
    assert_match(/purged: this system resigned as DIS/, @lab.isis4r_log)
  end

  # FRR is DIS, then its priority drops below isis4r's: isis4r takes over
  # and purges FRR's pseudonode (7.2.3), FRR purges it too on resigning,
  # and both sides agree, FRR's old pseudonode a purge on both.
  def test_databases_agree_through_a_dis_change_to_isis4r
    @lab.start(network: :broadcast, isis4r: { priority: 10 })
    assert_eventually("FRR did not become DIS") { both_up? && isis4r["dis"] == FrrLab::FRR_ID }
    pattern = /\A#{Regexp.escape(FrrLab::FRR_ID)}\.(?!00)\h\h-00\z/
    assert_eventually("the databases do not agree before the change", 30) do
      isis4r_view.keys.grep(pattern).size == 1 && isis4r_view == frr_view
    end
    old = isis4r_view.keys.grep(pattern).first
    @lab.vtysh_config("interface veth0", "isis priority 1")
    assert_eventually("the DIS did not move to isis4r") { isis4r["dis"] == "self" && @lab.frr_is_dis? == false }
    assert_eventually("the databases do not agree after the change", 30) do
      view = isis4r_view
      view[old]&.last && view.key?("#{FrrLab::ISIS4R_ID}.01-00") && !view["#{FrrLab::ISIS4R_ID}.01-00"].last &&
        view == frr_view
    end
    assert_frr_holds_isis4r_naming(ISIS4R_LAN_ID)
  end

  # -- Level 2: FRR "is-type level-2-only", isis4r's circuit at Level 2 --

  # The same agreement at Level 2 with isis4r as DIS, isis4r's Level 2
  # pseudonode included (7.3.10), and FRR routes to isis4r's prefix
  # through it.
  def test_level_2_databases_agree_with_isis4r_as_dis
    @lab.start(network: :broadcast, level: 2, isis4r: { priority: 100 })
    assert_eventually("isis4r did not become the Level 2 DIS") { both_up? && isis4r["dis"] == "self" }
    expected = ["#{FrrLab::ISIS4R_ID}.00-00", "#{FrrLab::ISIS4R_ID}.01-00", "#{FrrLab::FRR_ID}.00-00"].sort
    assert_eventually("the Level 2 databases do not agree", 30) do
      isis4r_view.keys.sort == expected && isis4r_view == frr_view
    end
    assert_frr_holds_isis4r_naming(ISIS4R_LAN_ID)
    assert_eventually("FRR did not route to 192.0.2.1/32 at Level 2", 60) { frr_routes_isis4rs_prefix? }
    assert_includes @lab.vtysh("show isis database"), "Level-2", @lab.report
  end

  # And through a DIS change to FRR at Level 2, isis4r's old Level 2
  # pseudonode a purge on both sides.
  def test_level_2_databases_agree_through_a_dis_change_to_frr
    @lab.start(network: :broadcast, level: 2, isis4r: { priority: 100 })
    assert_eventually("isis4r did not become the Level 2 DIS") { both_up? && isis4r["dis"] == "self" }
    old = "#{FrrLab::ISIS4R_ID}.01-00"
    assert_eventually("the databases do not agree before the change", 30) do
      isis4r_view.key?(old) && isis4r_view == frr_view
    end
    @lab.vtysh_config("interface veth0", "isis priority 127")
    assert_eventually("the Level 2 DIS did not move to FRR") { isis4r["dis"] == FrrLab::FRR_ID }
    assert_eventually("the databases do not agree after the change", 30) do
      view = isis4r_view
      view[old]&.last && view.keys.grep(/\A#{Regexp.escape(FrrLab::FRR_ID)}\.(?!00)\h\h-00\z/).size == 1 &&
        view == frr_view
    end
  end

  # -- Both levels: FRR level-1-2, isis4r a circuit per level on veth0 --

  # isis4r runs both levels on the one interface, hellos of circuit type 3
  # at each (RFC 1142 9.5, 9.6), and is DIS at both. FRR forms an
  # adjacency at each level, each level's databases agree on their own,
  # isis4r's pseudonode included at each, and every LSP isis4r generates
  # carries IS type 3, its Level 1 one too (9.8).
  def test_both_levels_agree_on_one_interface
    @lab.start(network: :broadcast, level: "1-2", isis4r: { priority: 100 })
    assert_eventually("isis4r did not become DIS at both levels") do
      [1, 2].all? { |l| @lab.isis4r_level_doc(l)["dis"] == "self" }
    end
    assert_eventually("FRR did not come up at both levels") do
      lines = @lab.vtysh("show isis neighbor").lines.grep(/veth0/)
      [1, 2].all? { |l| lines.any? { |x| x.split[2] == l.to_s && x.split[3] == "Up" } }
    end
    # FRR 8.4.4 forms both adjacencies whatever circuit type the hellos
    # carry (measured), so the circuit type is asserted from what FRR
    # reports: "Circuit type: L1L2" for each level's adjacency.
    detail = @lab.vtysh("show isis neighbor detail")
    assert_equal 2, detail.scan("Circuit type: L1L2").size, @lab.report
    expected = ["#{FrrLab::ISIS4R_ID}.00-00", "#{FrrLab::ISIS4R_ID}.01-00", "#{FrrLab::FRR_ID}.00-00"].sort
    [1, 2].each do |level|
      assert_eventually("the Level #{level} databases do not agree", 30) do
        isis4r_view(level).keys.sort == expected && isis4r_view(level) == frr_view(level)
      end
      own = @lab.isis4r_database(level).select { |id, _| id.start_with?(FrrLab::ISIS4R_ID) }
      assert(own.values.all? { |e| e["is_type"] == 3 }, "Level #{level}: #{own}\n#{@lab.report}")
    end
    assert_eventually("FRR did not route to 192.0.2.1/32", 60) { frr_routes_isis4rs_prefix? }
  end
end

