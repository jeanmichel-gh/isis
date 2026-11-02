# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"

# Phase 1 gate 2, against FRR's isisd: an independent router brings the
# point to point adjacency up and holds it, and losing the neighbour
# expires it, on both sides. CLAUDE.md, "Where to start" and "Labs and
# interop".
#
# Runs only as root with FRR installed and ISIS_FRR=1:
#
#   sudo -E env "PATH=$PATH" ISIS_FRR=1 ruby -Ilib -I../datalink-socket/lib -Itest test/integration/frr_p2p_test.rb
#
# Hellos are every second with a multiplier of 3, so the holding time is
# 3 s on both sides. A failing test prints both sides' logs.
class TestFrrP2p < Minitest::Test
  def setup
    ok, why = FrrLab.available?
    # Asked for with ISIS_FRR=1 and unable to run is a failure, not a skip:
    # a skip prints its reason only under -v, and a CI job of skips is green.
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
    @lab = FrrLab.new("p2p#{Process.pid % 10_000}")
  end

  def teardown
    @lab&.stop
  end

  def both_up?
    @lab.frr_adjacency_state == "Up" && @lab.isis4r_state == "up"
  end

  def assert_eventually(message, timeout = 20, &block)
    assert @lab.wait_for(timeout, &block), "#{message}\n#{@lab.report}"
  end

  def test_adjacency_comes_up_on_both_sides
    @lab.start
    assert_eventually("adjacency did not come up on both sides") { both_up? }
    assert_includes @lab.isis4r_log, "adjacency with #{FrrLab::FRR_ID} initializing -> up"
  end

  # Ten seconds is more than three holding times: the hellos each side
  # sends keep the other's timer from running out. Being up at the end is
  # not enough, since an adjacency that flaps and comes back is up at the
  # end too, so isis4r must have come up once and never gone down.
  def test_adjacency_holds
    @lab.start
    assert_eventually("adjacency did not come up") { both_up? }
    sleep 10
    assert both_up?, "adjacency did not hold\n#{@lab.report}"
    log = @lab.isis4r_log
    refute_includes log, "-> down", "isis4r's adjacency went down while hellos kept arriving\n#{@lab.report}"
    # Any arrival at Up counts. Down goes straight to Up when FRR's hello
    # already reports Initializing (RFC 5303 3.2), so it need not pass
    # through Initializing first.
    ups = log.scan(/^\S+ info +\S+ adjacency with \S+ \w+ -> up at Level 1$/).size
    assert_equal 1, ups, "isis4r came up #{ups} times, not once\n#{@lab.report}"
  end

  def test_frr_expires_isis4r_when_it_goes_silent
    @lab.start
    assert_eventually("adjacency did not come up") { both_up? }
    @lab.stop_isis4r
    assert_eventually("FRR kept the adjacency after isis4r went silent", 10) { @lab.frr_adjacency_state.nil? }
  end

  def test_isis4r_expires_frr_when_it_goes_silent
    @lab.start
    assert_eventually("adjacency did not come up") { both_up? }
    @lab.stop_frr_isisd
    assert_eventually("isis4r kept the adjacency after FRR went silent", 10) { @lab.isis4r_state == "down" }
    assert_includes @lab.isis4r_log, "holding time of 3 s expired without a hello"
  end

  # No area in common: neither side forms an adjacency, and isis4r says why.
  def test_area_mismatch_forms_no_adjacency
    @lab.start(isis4r: { areas: ["49.0002"] })
    assert_eventually("isis4r did not refuse FRR's hello", 10) { @lab.isis4r_log.include?("no area in common") }
    sleep 3
    refute_equal "up", @lab.isis4r_state, @lab.report
    refute_equal "Up", @lab.frr_adjacency_state, @lab.report
  end

  # Gate 3, the receiving half: FRR lists its own LSP in a CSNP and sends
  # it only when asked, so isis4r has to request it, store it and
  # acknowledge it. Measured: FRR 8.4.4 does not flood its LSP on a point to
  # point adjacency without that request.
  def test_isis4r_learns_and_acknowledges_frrs_lsp
    @lab.start
    assert_eventually("adjacency did not come up") { both_up? }
    frr_id = "#{FrrLab::FRR_ID}.00-00"
    assert_eventually("isis4r did not learn FRR's LSP") do
      held = @lab.isis4r_database[frr_id]
      frr = @lab.frr_database[frr_id]
      held && frr && held["sequence"] == frr["sequence"] && held["checksum"] == frr["checksum"]
    end
    assert_eventually("isis4r's acknowledgment did not go out") { @lab.isis4r_database.dig(frr_id, "ssn")&.zero? }
    # Acknowledged, so FRR does not send it again: over the next ten
    # seconds isis4r receives it at most once more, if FRR refreshed it.
    before = @lab.isis4r_log.scan(/< L1 LSP #{Regexp.escape(frr_id)}/).size
    sleep 10
    after = @lab.isis4r_log.scan(/< L1 LSP #{Regexp.escape(frr_id)}/).size
    assert_operator after - before, :<=, 1, "FRR kept sending its LSP\n#{@lab.report}"
  end

  # Gate 3, the sending half: FRR learns isis4r's LSP at isis4r's sequence
  # and checksum, runs SPF over it, and installs the prefix isis4r
  # advertises, through isis4r. 192.0.2.1/32 exists only in isis4r's TLV
  # 135, so FRR can have the route from nowhere else.
  def test_frr_learns_isis4rs_prefix
    @lab.start
    assert_eventually("adjacency did not come up") { both_up? }
    own = "#{FrrLab::ISIS4R_ID}.00-00"
    assert_eventually("FRR does not hold isis4r's latest LSP", 30) do
      held = @lab.isis4r_database[own]
      frr = @lab.frr_database[own]
      held && frr && held["sequence"] >= 2 && frr["sequence"] == held["sequence"] && frr["checksum"] == held["checksum"]
    end
    # Measured on FRR 8.4.4: the route comes about 30 s after the adjacency.
    # FRR holds isis4r's LSP within a second, but its own LSP names isis4r
    # in TLV 22 only when it regenerates it, about 30 s on, and its SPF
    # needs the link in both LSPs.
    assert_eventually("FRR did not install 192.0.2.1/32 from IS-IS", 60) do
      route = @lab.frr_route("192.0.2.1/32")
      route && route["protocol"] == "isis" && route["installed"] &&
        route["nexthops"].any? { |n| n["ip"] == "10.0.12.1" && n["interfaceName"] == "veth0" }
    end
    assert_eventually("isis4r's LSP is still owed to FRR") { @lab.isis4r_database.dig(own, "srm")&.zero? }
  end

  # The same with narrow metrics on both sides: FRR's "metric-style
  # narrow" reads only TLVs 2 and 128, so the route can only come from
  # isis4r's narrow encoding. Its metric is the link's 10 plus the
  # prefix's 5.
  def test_frr_learns_isis4rs_prefix_with_narrow_metrics
    @lab.start(isis4r: { metric_style: "narrow" }, frr_router: ["metric-style narrow"])
    assert_eventually("adjacency did not come up") { both_up? }
    assert_eventually("FRR did not install 192.0.2.1/32 from narrow metrics", 60) do
      route = @lab.frr_route("192.0.2.1/32")
      route && route["protocol"] == "isis" && route["installed"] && route["metric"] == 15 &&
        route["nexthops"].any? { |n| n["ip"] == "10.0.12.1" }
    end
  end


  # External routes (RFC 1195 section 5.3.5, RFC 5302 section 2.2): isis4r
  # sends two external prefixes in TLV 130 at Level 1, both narrow.
  # 198.18.5.0/24 is of the internal metric type at 5, and FRR installs it
  # at 5 + 10 through isis4r. 198.18.6.0/24 is of the external type at 7,
  # I/E set, 0x47. Measured on FRR 8.4.4: FRR reads that octet's value as
  # 71, its low seven bits, where RFC 1195 gives the value six and bit 7
  # the metric type, so it installs the route at 81. The test asks only
  # that FRR installs it through isis4r.
  #
  # Measured on the way: FRR 8.4.4 never sends TLV 130. Redistributed
  # connected routes with metric-style narrow go in TLV 128, at either
  # level, so no FRR LSP here exercises isis4r's reading of TLV 130; the
  # unit tests do, against our own arithmetic.
  def test_frr_installs_isis4rs_external_prefixes
    externals = [{ prefix: "198.18.5.0/24", metric: 5 }, { prefix: "198.18.6.0/24", metric: 7, external: true }]
    @lab.start(isis4r: { metric_style: "narrow", external_prefixes: externals }, frr_router: ["metric-style narrow"])
    assert_eventually("FRR did not install 198.18.5.0/24 at 15 through isis4r", 60) do
      @lab.frr_isis_routes["198.18.5.0/24"] == { "metric" => 15, "interface" => "veth0", "next_hop" => "10.0.12.1" }
    end
    assert_eventually("FRR did not install 198.18.6.0/24 through isis4r", 30) do
      @lab.frr_isis_routes.dig("198.18.6.0/24", "next_hop") == "10.0.12.1"
    end
  end

  # FRR's redistributed connected route, 198.18.5.0/24 on a link that is
  # not in IS-IS, arrives in TLV 128 at FRR's metric 0, and isis4r reaches
  # it at its link's 10 through FRR.
  def test_isis4r_routes_to_frrs_redistributed_prefix
    @lab.start(isis4r: { metric_style: "narrow" }, frr_connected: "198.18.5.1/24",
               frr_router: ["metric-style narrow", "redistribute ipv4 connected level-1"])
    assert_eventually("isis4r does not reach 198.18.5.0/24 through FRR", 60) do
      @lab.isis4r_routes["198.18.5.0/24"] ==
        { "prefix" => "198.18.5.0/24", "metric" => 10,
          "next_hops" => [{ "address" => "10.0.12.2", "circuit" => "veth0" }] }
    end
  end

  # Gate 3, authentication. FRR's "isis password md5" keys the hellos and
  # "area-password md5 ... authenticate snp validate" keys and checks the
  # Level 1 LSPs and SNPs, RFC 5304 HMAC-MD5 both.
  HELLO_KEY = "isis4r-hello"
  AREA_KEY = "isis4r-area"
  FRR_KEYS = { frr_interface: ["isis password md5 #{HELLO_KEY}"],
               frr_router: ["area-password md5 #{AREA_KEY} authenticate snp validate"] }.freeze

  # Matching keys: up, FRR installs isis4r's prefix, which it can only
  # do having accepted isis4r's authenticated LSP, and isis4r stores FRR's.
  def test_authentication_succeeds_with_matching_keys
    @lab.start(isis4r: { hello_key: HELLO_KEY, area_key: AREA_KEY }, **FRR_KEYS)
    assert_eventually("adjacency did not come up with matching keys") { both_up? }
    assert_eventually("FRR did not install 192.0.2.1/32 from isis4r's authenticated LSP", 60) do
      route = @lab.frr_route("192.0.2.1/32")
      route && route["protocol"] == "isis" && route["installed"]
    end
    frr_id = "#{FrrLab::FRR_ID}.00-00"
    assert_eventually("isis4r did not store FRR's authenticated LSP") do
      @lab.isis4r_database.dig(frr_id, "sequence") == @lab.frr_database.dig(frr_id, "sequence")
    end
    # Measured on FRR 8.4.4: its first LSP after start can go out with no
    # TLV 10 although the area password is configured, and isis4r refuses
    # that one under 7.3.15.1 a 3 i, rightly. With matching keys nothing
    # may fail on its digest, and no hello may be refused.
    log = @lab.isis4r_log
    refute_includes log, "digest is wrong", @lab.report
    refute_includes log, "hello refused", @lab.report
  end

  # A wrong hello key: no adjacency on either side, and isis4r says why.
  def test_hello_authentication_fails_with_the_wrong_key
    @lab.start(isis4r: { hello_key: "not-#{HELLO_KEY}", area_key: AREA_KEY }, **FRR_KEYS)
    assert_eventually("isis4r did not refuse FRR's hello", 10) do
      @lab.isis4r_log.include?("hello refused: the HMAC-MD5 digest is wrong")
    end
    sleep 4
    refute_equal "up", @lab.isis4r_state, @lab.report
    refute_equal "Up", @lab.frr_adjacency_state, @lab.report
  end

  # The right hello key and a wrong area key: up, but FRR never holds
  # isis4r's LSP, and isis4r refuses FRR's LSP and SNPs, saying why.
  def test_area_authentication_fails_with_the_wrong_key
    @lab.start(isis4r: { hello_key: HELLO_KEY, area_key: "not-#{AREA_KEY}" }, **FRR_KEYS)
    assert_eventually("adjacency did not come up with matching hello keys") { both_up? }
    assert_eventually("isis4r did not refuse FRR's CSNP", 15) do
      @lab.isis4r_log.include?("refused: Csnp: the HMAC-MD5 digest is wrong")
    end
    sleep 10
    assert_nil @lab.frr_database["#{FrrLab::ISIS4R_ID}.00-00"], "FRR stored isis4r's LSP\n#{@lab.report}"
    assert_nil @lab.isis4r_database.dig("#{FrrLab::FRR_ID}.00-00", "checksum")&.nonzero?, @lab.report
  end

  # -- Both levels: FRR level-1-2, isis4r's circuit at Level 1 and 2 --

  # Each side's LSPs at +level+ as LSP ID => sequence.
  def isis4r_lsps(level)
    @lab.isis4r_database(level).reject { |_, e| e["sequence"].zero? }.transform_values { |e| e["sequence"] }
  end

  def frr_lsps(level)
    @lab.frr_database(level).transform_values { |e| e["sequence"] }
  end

  # The levels FRR has an adjacency Up at on veth0, from `show isis
  # neighbor`, whose third column is the level. Measured on FRR 8.4.4: a
  # point to point adjacency at both levels is one line with level 3.
  def frr_up_levels
    lines = @lab.vtysh("show isis neighbor").lines.grep(/veth0/).select { |l| l.split[3] == "Up" }
    lines.flat_map { |l| { "1" => [1], "2" => [2], "3" => [1, 2] }.fetch(l.split[2], []) }.sort
  end

  # One adjacency serving both levels (RFC 1142 9.7, circuit type 3).
  # Each level's databases agree, and isis4r's LSPs carry IS type 3 at
  # both (9.8).
  def test_both_levels_on_one_adjacency
    @lab.start(level: "1-2")
    assert_eventually("FRR did not come up at both levels") { frr_up_levels == [1, 2] }
    assert_eventually("isis4r's adjacency does not serve both levels") do
      @lab.isis4r_state_doc.dig("neighbor", "usage") == [1, 2]
    end
    assert_includes @lab.vtysh("show isis neighbor detail"), "Circuit type: L1L2", @lab.report
    [1, 2].each do |level|
      assert_eventually("the Level #{level} databases do not agree", 40) do
        mine = isis4r_lsps(level)
        mine.keys.sort == ["#{FrrLab::FRR_ID}.00-00", "#{FrrLab::ISIS4R_ID}.00-00"].sort && mine == frr_lsps(level)
      end
      assert_equal 3, @lab.isis4r_database(level).dig("#{FrrLab::ISIS4R_ID}.00-00", "is_type"), @lab.report
    end
    assert_eventually("FRR did not install 192.0.2.1/32", 60) do
      route = @lab.frr_route("192.0.2.1/32")
      route && route["protocol"] == "isis" && route["installed"]
    end
  end

  # No area in common, both at both levels: "the IS shall mark the
  # adjacency as Level 2 Only" (8.2.4.2). The Level 2 databases agree, and
  # the level boundary holds: neither side's Level 1 LSP reaches the other.
  def test_no_area_in_common_is_level_2_only
    @lab.start(level: "1-2", isis4r: { areas: ["49.0002"] })
    # Measured on FRR 8.4.4: `show isis neighbor` still lists this
    # adjacency at level 3, though FRR does not take isis4r's Level 1 LSP
    # over it, so the level column is not read here.
    assert_eventually("FRR did not come up") { @lab.frr_adjacency_state == "Up" }
    assert_eventually("isis4r's adjacency is not Level 2 only") do
      @lab.isis4r_state_doc.dig("neighbor", "usage") == [2]
    end
    assert_eventually("the Level 2 databases do not agree", 40) do
      mine = isis4r_lsps(2)
      mine.keys.sort == ["#{FrrLab::FRR_ID}.00-00", "#{FrrLab::ISIS4R_ID}.00-00"].sort && mine == frr_lsps(2)
    end
    sleep 5
    assert_equal ["#{FrrLab::ISIS4R_ID}.00-00"], isis4r_lsps(1).keys, @lab.report
    refute frr_lsps(1).key?("#{FrrLab::ISIS4R_ID}.00-00"), @lab.report
  end

  # Routes computed (RFC 1142 7.2, Annex C.2), on the same two systems.
  # FRR's loopback, 198.51.100.2/32, is in FRR's LSP at 10, and the link
  # is at 10 each way, so isis4r reaches it at 20 through 10.0.12.2. FRR,
  # computing the other way, reaches isis4r's 192.0.2.1/32 at 10 + 5
  # through 10.0.12.1. Our arithmetic, and each side's number is checked
  # against the other's LSP as FRR prints it.
  def test_routes_computed_agree_with_frr
    @lab.start(frr_loopback: "198.51.100.2/32")
    assert_eventually("adjacency did not come up") { both_up? }
    assert_eventually("FRR does not reach 192.0.2.1/32 through isis4r", 60) do
      @lab.frr_isis_routes["192.0.2.1/32"] == { "metric" => 15, "interface" => "veth0", "next_hop" => "10.0.12.1" }
    end
    frr_lsp = @lab.frr_database_detail(1)["#{FrrLab::FRR_ID}.00-00"].to_s
    assert_match %r{Extended IP Reachability: 198\.51\.100\.2/32 \(Metric: 10\)}, frr_lsp, @lab.report
    assert_eventually("isis4r does not reach 198.51.100.2/32 at 20 through FRR", 30) do
      @lab.isis4r_routes["198.51.100.2/32"] ==
        { "prefix" => "198.51.100.2/32", "metric" => 20,
          "next_hops" => [{ "address" => "10.0.12.2", "circuit" => "veth0" }] }
    end
    # Measured on FRR 8.4.4: FRR lists the shared subnet, 10.0.12.0/24, at
    # 20 through isis4r, its own at 10 not shown. isis4r keeps its own,
    # at 10, as local.
    assert_equal({ "prefix" => "10.0.12.0/24", "metric" => 10, "next_hops" => [] },
                 @lab.isis4r_routes["10.0.12.0/24"], @lab.report)
  end

  # Each side's distance starts with its own metric on the link, so the
  # routes may differ each way (RFC 1142 7.2.8.2: "It is permissible for
  # two endpoints to report different defined values of the same metric
  # for the same link. In this case, routes may be asymmetric"). FRR at 30
  # reaches 192.0.2.1/32 at 30 + 5, and isis4r, at 10, still reaches the
  # loopback at 10 + 10. When FRR's isisd stops, the route goes with the
  # adjacency.
  def test_asymmetric_metrics_and_a_lost_neighbour
    @lab.start(frr_loopback: "198.51.100.2/32", frr_interface: ["isis metric 30"])
    assert_eventually("FRR does not reach 192.0.2.1/32 at 35", 60) do
      @lab.frr_isis_routes.dig("192.0.2.1/32", "metric") == 35
    end
    assert_eventually("isis4r does not reach 198.51.100.2/32 at 20", 30) do
      @lab.isis4r_routes.dig("198.51.100.2/32", "metric") == 20
    end
    @lab.stop_frr_isisd
    assert_eventually("isis4r keeps a route through FRR", 20) { @lab.isis4r_routes["198.51.100.2/32"].nil? }
    assert_includes @lab.isis4r_log, "route 198.51.100.2/32 removed", @lab.report
  end

  # Routes installed (Phase 2 gate 4): a host behind isis4r, 203.0.113.2,
  # pings FRR's loopback. The request goes through isis4r's kernel on the
  # route the netlink adapter installed, the only route there to
  # 198.51.100.2, and the reply comes back on FRR's route to the host's
  # subnet, which isis4r advertises. When FRR's isisd stops, the route
  # leaves the kernel with the adjacency, and nothing of isis4r's is left.
  def test_a_host_reaches_frr_through_isis4rs_installed_route
    @lab.start(frr_loopback: "198.51.100.2/32", host: true)
    assert_eventually("isis4r did not install 198.51.100.2 through FRR", 60) do
      @lab.isis4r_kernel_routes.match?(/^198\.51\.100\.2 via 10\.0\.12\.2 dev veth0 metric 21\b/)
    end
    assert_eventually("FRR does not reach the host's subnet through isis4r", 60) do
      @lab.frr_isis_routes["203.0.113.0/24"] == { "metric" => 20, "interface" => "veth0", "next_hop" => "10.0.12.1" }
    end
    assert_eventually("the host did not reach FRR's loopback through isis4r", 10) { @lab.host_ping("198.51.100.2") }
    @lab.stop_frr_isisd
    assert_eventually("isis4r left routes in its kernel", 20) { @lab.isis4r_kernel_routes.strip.empty? }
    refute @lab.host_ping("198.51.100.2"), @lab.report
  end

  # isis4r stopping takes its routes out of the kernel, so a stopped
  # isis4r does not leave traffic going to a neighbour it no longer
  # watches.
  def test_isis4r_stopping_removes_its_routes
    @lab.start(frr_loopback: "198.51.100.2/32", host: true)
    assert_eventually("isis4r did not install 198.51.100.2", 60) do
      @lab.isis4r_kernel_routes.include?("198.51.100.2 via 10.0.12.2")
    end
    @lab.stop_isis4r
    assert_equal "", @lab.isis4r_kernel_routes.strip, @lab.report
  end

  # The same in IPv6: the host, 2001:db8:203::2, pings FRR's IPv6
  # loopback through isis4r, whose route goes through FRR's link-local
  # address.
  def test_a_host_reaches_frr_over_ipv6_through_isis4r
    unless File.exist?("/proc/sys/net/ipv6")
      skip "the kernel has no IPv6 (ISIS_SKIP_IPV6=1)" if ENV["ISIS_SKIP_IPV6"] == "1"
      flunk "the kernel has no IPv6; set ISIS_SKIP_IPV6=1 to skip this test on purpose"
    end
    @lab.start(ipv6: true, frr_loopback6: "2001:db8:ff::2/128", host: true)
    assert_eventually("isis4r did not install 2001:db8:ff::2 through FRR's link-local address", 60) do
      @lab.isis4r_kernel_routes("-6").include?("2001:db8:ff::2 via #{@lab.frr_link_local} dev veth0 metric 21")
    end
    assert_eventually("the host did not reach FRR's IPv6 loopback through isis4r", 60) do
      @lab.host_ping("2001:db8:ff::2")
    end
  end

  # IPv6 (RFC 5308) on the same adjacency. FRR's loopback, 2001:db8:ff::2/128,
  # is in FRR's LSP at 10, so isis4r reaches it at 10 + 10 through FRR's
  # link-local address, which FRR's hellos carry in TLV 232. FRR reaches
  # isis4r's 2001:db8:1::1/128 at 10 + 5 and installs it through isis4r's
  # link-local address. Our arithmetic.
  #
  # A kernel without IPv6 cannot run it. That fails the test, as any lab
  # that cannot run does, unless ISIS_SKIP_IPV6=1 says so on purpose: the
  # sandbox this was written in has no IPv6, and CI's runners do.
  def test_ipv6_routes_both_ways
    unless File.exist?("/proc/sys/net/ipv6")
      skip "the kernel has no IPv6 (ISIS_SKIP_IPV6=1)" if ENV["ISIS_SKIP_IPV6"] == "1"
      flunk "the kernel has no IPv6; set ISIS_SKIP_IPV6=1 to skip this test on purpose"
    end
    @lab.start(ipv6: true, frr_loopback6: "2001:db8:ff::2/128")
    assert_eventually("adjacency did not come up") { both_up? }
    assert_eventually("isis4r does not reach 2001:db8:ff::2/128 through FRR's link-local address", 60) do
      @lab.isis4r_routes["2001:db8:ff::2/128"] ==
        { "prefix" => "2001:db8:ff::2/128", "metric" => 20,
          "next_hops" => [{ "address" => @lab.frr_link_local, "circuit" => "veth0" }] }
    end
    assert_eventually("FRR did not install 2001:db8:1::1/128 through isis4r", 60) do
      route = @lab.frr_json("show ipv6 route 2001:db8:1::1/128").fetch("2001:db8:1::1/128", []).first
      route && route["protocol"] == "isis" && route["installed"] && route["metric"] == 15 &&
        route["nexthops"].any? { |h| h["ip"] == @lab.isis4r_link_local }
    end
  end

  # Area addresses at Level 2 (RFC 1142 7.2.11): FRR's Level 1 LSP lists
  # 49.0001 and 49.0002, its two nets, and isis4r's lists 49.0001. So
  # isis4r's Level 2 LSP, as FRR holds it, lists the union, both, while
  # its Level 1 LSP keeps the manual area alone (7.3.7). Measured on FRR
  # 8.4.4 the other way round, isis4r at 49.0001 and 49.0002 and FRR at
  # 49.0001: FRR's Level 2 LSP lists 49.0001 alone, its manual area, so
  # FRR does not do this and the test reads isis4r's LSP only.
  def test_the_level_2_lsp_lists_the_areas_of_the_level_1_area
    @lab.start(level: "1-2", frr_router: ["net 49.0002.#{FrrLab::FRR_ID}.00"])
    assert_eventually("FRR did not come up at both levels") { frr_up_levels == [1, 2] }
    lsp = "#{FrrLab::ISIS4R_ID}.00-00"
    areas = ->(level) { @lab.frr_database_detail(level)[lsp].to_s.scan(/Area Address: (\S+)/).flatten.sort }
    assert_eventually("FRR does not hold isis4r's Level 2 LSP with both areas", 40) do
      areas.call(2) == ["49.0001", "49.0002"]
    end
    assert_eventually("FRR does not hold isis4r's Level 1 LSP", 20) { !areas.call(1).empty? }
    assert_equal ["49.0001"], areas.call(1), @lab.report
  end

  # Several LSP Numbers (RFC 1142 7.3.4): 60 more /32s and a 300 octet
  # budget spread isis4r's advertisements over four LSPs once the
  # adjacency is in TLV 22. LSP 0 is the header and TLVs 1, 129, 132 and
  # 22, 55 octets, which leaves no room for a TLV 135 of 28 entries, 253;
  # so LSPs 1 and 2 take one full TLV 135 each and LSP 3 the last six
  # entries. Our arithmetic. FRR holds every one at isis4r's sequence, and
  # installs the last prefix, which only LSP 3 carries.
  def test_frr_learns_every_lsp_number
    extra = (1..60).map { |i| { prefix: "198.18.0.#{i}/32", metric: 1 } }
    @lab.start(isis4r: { prefixes: FrrLab::ISIS4R_PREFIXES + extra, lsp_buffer_size: 300 })
    assert_eventually("adjacency did not come up") { both_up? }
    own = /\A#{Regexp.escape(FrrLab::ISIS4R_ID)}\.00-/
    assert_eventually("isis4r did not name FRR in its LSP") do
      @lab.isis4r_database.dig("#{FrrLab::ISIS4R_ID}.00-00", "sequence").to_i >= 2
    end
    ids = @lab.isis4r_database.select { |id, e| id.match?(own) && e["lifetime"].positive? }.keys.sort
    assert_equal 4, ids.size, @lab.report
    assert_eventually("FRR does not hold every LSP Number at isis4r's sequence", 30) do
      ids.all? { |id| @lab.frr_database.dig(id, "sequence") == @lab.isis4r_database.dig(id, "sequence") }
    end
    assert_eventually("FRR did not install 198.18.0.60/32 from the last LSP", 60) do
      route = @lab.frr_route("198.18.0.60/32")
      route && route["protocol"] == "isis" && route["installed"]
    end
  end
end

