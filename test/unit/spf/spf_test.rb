# frozen_string_literal: true

require_relative "../../test_helper"

# The calculation of RFC 1142 Annex C.2 over hand built databases. System
# A, 0000.0000.000a, computes. Every expected metric is our own arithmetic:
# the circuit's metric to the first hop, plus each link's, plus the
# prefix's.
class TestSpf < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @db = ISIS::Database.new(level: 1, clock: @clock)
  end

  def id(letter, pseudonode = 0)
    (ISIS::Pdu.dotted_octets("0000.0000.000#{letter}") + [pseudonode].pack("C")).b
  end

  def adj(letter, circuit: "eth-#{letter}", lan_address: nil)
    ISIS::Spf::Adjacency.new(circuit: circuit, neighbor: ISIS::Pdu.dotted_octets("0000.0000.000#{letter}"),
                             circuit_id: 1, lan_address: lan_address, address: "10.0.0.#{letter.hex}")
  end

  # Store the LSP of +node+, a letter or [letter, pseudonode], with +links+
  # to other nodes and +prefixes+, wide unless +narrow+.
  def lsp(node, links: {}, prefixes: {}, number: 0, overload: false, narrow: false, lifetime: 1200)
    letter, pseudonode = Array(node)
    lsp_id = id(letter, pseudonode || 0) + [number].pack("C")
    tlvs = []
    unless links.empty?
      tlvs << if narrow
                entries = links.map do |n, m|
                  metrics = ISIS::Tlv::NarrowMetrics.build(metric: m, ie_octets: ISIS::Tlv::IsReachability::IE_OCTETS)
                  ISIS::Tlv::IsReachability::Entry.new(metrics: metrics, neighbor: id(*Array(n)))
                end
                ISIS::Tlv::IsReachability.new(entries)
              else
                ISIS::Tlv::ExtendedIsReachability.new(links.map do |n, m|
                  ISIS::Tlv::ExtendedIsReachability::Entry.new(neighbor: id(*Array(n)), metric: m)
                end)
              end
    end
    unless prefixes.empty?
      list = prefixes.map { |p, m| { prefix: p, metric: m } }
      tlvs << (narrow ? ISIS::Tlv::IpInternalReachability.new(list) : ISIS::Tlv::ExtendedIpReachability.new(list))
    end
    pdu = ISIS::Pdu::Lsp.new(level: 1, lsp_id: ISIS::Octets.new(lsp_id), lifetime: lifetime, sequence: 1,
                             tlvs: tlvs, overload: overload)
    @db.entry(lsp_id).store(pdu)
  end

  def spf(adjacencies, broadcast: [], **opts)
    ISIS::Spf::Calculation.new(database: @db, system_id: "0000.0000.000a", adjacencies: adjacencies,
                               broadcast: broadcast, **opts).run
  end

  def route(calc, prefix)
    calc.routes[prefix]&.to_s
  end

  # A, B and C in a line, 10 a link; C's prefix at 1: 10 + 10 + 1.
  def line
    lsp("a", links: { "b" => 10 })
    lsp("b", links: { "a" => 10, "c" => 10 })
    lsp("c", links: { "b" => 10 }, prefixes: { "192.0.2.3/32" => 1 })
  end

  def test_a_line
    line
    calc = spf([[id("b"), 10, adj("b")]])
    assert_equal "192.0.2.3/32 metric 21 via 10.0.0.11 via eth-b", route(calc, "192.0.2.3/32")
    assert_equal [0, 10, 20], calc.paths.values.map(&:distance)
  end

  # A's own prefix is local: no adjacency, its own metric.
  def test_an_own_prefix_is_local
    lsp("a", prefixes: { "10.0.12.0/24" => 10 })
    calc = spf([])
    assert_equal "10.0.12.0/24 metric 10 local", route(calc, "10.0.12.0/24")
  end

  # A diamond, A to D through B and through C at 20 each: both first hops,
  # in neighbour ID order (7.2.7).
  def diamond
    lsp("a", links: { "b" => 10, "c" => 10 })
    lsp("b", links: { "a" => 10, "d" => 10 })
    lsp("c", links: { "a" => 10, "d" => 10 })
    lsp("d", links: { "b" => 10, "c" => 10 }, prefixes: { "192.0.2.4/32" => 1 })
    [[id("c"), 10, adj("c")], [id("b"), 10, adj("b")]]
  end

  def test_equal_cost_paths_share_the_route
    calc = spf(diamond)
    assert_equal "192.0.2.4/32 metric 21 via 10.0.0.11 via eth-b, 10.0.0.12 via eth-c", route(calc, "192.0.2.4/32")
  end

  # maximumPathSplits 1 keeps the lower neighbour ID, B (7.2.7).
  def test_excess_paths_are_removed_by_neighbour_id
    calc = spf(diamond, max_path_splits: 1)
    assert_equal "192.0.2.4/32 metric 21 via 10.0.0.11 via eth-b", route(calc, "192.0.2.4/32")
  end

  # The first hops are kept in 7.2.7's order whatever order they were found
  # in. D is at 10 through C (5 + 5) and through B (10 + 0), and C, at 5,
  # reaches it first; B, the lower neighbour ID, still comes first, and is
  # the one kept with maximumPathSplits 1.
  def test_first_hops_are_ranked_not_found
    lsp("a", links: { "b" => 10, "c" => 5 })
    lsp("b", links: { "a" => 10, "d" => 0 })
    lsp("c", links: { "a" => 5, "d" => 5 })
    lsp("d", links: { "b" => 0, "c" => 5 }, prefixes: { "192.0.2.4/32" => 1 })
    adjacencies = [[id("b"), 10, adj("b")], [id("c"), 5, adj("c")]]
    assert_equal "192.0.2.4/32 metric 11 via 10.0.0.11 via eth-b, 10.0.0.12 via eth-c",
                 route(spf(adjacencies), "192.0.2.4/32")
    assert_equal "192.0.2.4/32 metric 11 via 10.0.0.11 via eth-b",
                 route(spf(adjacencies, max_path_splits: 1), "192.0.2.4/32")
  end

  # One prefix from two systems at one cost: both first hops.
  def test_a_prefix_from_two_systems_at_one_cost
    lsp("a", links: { "b" => 10, "c" => 10 })
    lsp("b", links: { "a" => 10 }, prefixes: { "192.0.2.9/32" => 1 })
    lsp("c", links: { "a" => 10 }, prefixes: { "192.0.2.9/32" => 1 })
    calc = spf([[id("b"), 10, adj("b")], [id("c"), 10, adj("c")]])
    assert_equal "192.0.2.9/32 metric 11 via 10.0.0.11 via eth-b, 10.0.0.12 via eth-c", route(calc, "192.0.2.9/32")
  end

  # Step 0 too keeps to MaxPathMetric: an adjacency at 2000 is over the
  # narrow 1023, so B is not reached.
  def test_an_adjacency_over_max_path_metric_is_not_used
    lsp("a", links: { "b" => 2000 })
    lsp("b", links: { "a" => 2000 }, prefixes: { "192.0.2.2/32" => 0 })
    calc = spf([[id("b"), 2000, adj("b")]], max_path_metric: ISIS::Spf::MAX_PATH_METRIC_NARROW)
    refute calc.paths.key?(id("b"))
  end

  # A prefix A advertises itself stays local at an equal cost: 20 here,
  # and 10 + 10 through B.
  def test_an_own_prefix_stays_local_at_an_equal_cost
    lsp("a", links: { "b" => 10 }, prefixes: { "10.0.12.0/24" => 20 })
    lsp("b", links: { "a" => 10 }, prefixes: { "10.0.12.0/24" => 10 })
    calc = spf([[id("b"), 10, adj("b")]])
    assert_equal "10.0.12.0/24 metric 20 local", route(calc, "10.0.12.0/24")
  end

  # A shorter path replaces a longer one: A to B direct is 10, through C
  # 1 + 1, so B's prefix is at 2 + 1 through C.
  def test_a_shorter_path_replaces
    lsp("a", links: { "b" => 10, "c" => 1 })
    lsp("b", links: { "a" => 10, "c" => 1 }, prefixes: { "192.0.2.2/32" => 1 })
    lsp("c", links: { "a" => 1, "b" => 1 })
    calc = spf([[id("b"), 10, adj("b")], [id("c"), 1, adj("c")]])
    assert_equal "192.0.2.2/32 metric 3 via 10.0.0.12 via eth-c", route(calc, "192.0.2.2/32")
  end

  # Clause 7.2.8.2: B reports C, C does not report B, so the link is not
  # used and C is not reached.
  def test_a_link_reported_one_way_is_not_used
    lsp("a", links: { "b" => 10 })
    lsp("b", links: { "a" => 10, "c" => 10 })
    lsp("c", prefixes: { "192.0.2.3/32" => 1 })
    calc = spf([[id("b"), 10, adj("b")]])
    assert_nil route(calc, "192.0.2.3/32")
    refute calc.paths.key?(id("c"))
  end

  # Clause 7.2.8.1: B is overloaded, so its links are not used past it,
  # but its own prefix is reached.
  def test_an_overloaded_system_is_a_leaf
    line
    lsp("b", links: { "a" => 10, "c" => 10 }, prefixes: { "192.0.2.2/32" => 1 }, overload: true)
    calc = spf([[id("b"), 10, adj("b")]])
    assert_equal "192.0.2.2/32 metric 11 via 10.0.0.11 via eth-b", route(calc, "192.0.2.2/32")
    assert_nil route(calc, "192.0.2.3/32")
  end

  # Clause 7.2.5: the overload bit is taken from LSP Number 0 only.
  def test_the_overload_bit_of_another_lsp_number_is_ignored
    line
    lsp("b", number: 1, overload: true)
    calc = spf([[id("b"), 10, adj("b")]])
    assert_equal "192.0.2.3/32 metric 21 via 10.0.0.11 via eth-b", route(calc, "192.0.2.3/32")
  end

  # Clause 7.2.5: with no LSP Number 0 for C, its LSP 1 is not processed.
  def test_no_lsp_number_zero_no_system
    lsp("a", links: { "b" => 10 })
    lsp("b", links: { "a" => 10, "c" => 10 })
    lsp("c", links: { "b" => 10 }, prefixes: { "192.0.2.3/32" => 1 }, number: 1)
    calc = spf([[id("b"), 10, adj("b")]])
    assert_nil route(calc, "192.0.2.3/32")
  end

  # Nor an LSP Number 0 whose lifetime ran out, a purge.
  def test_a_purged_lsp_number_zero_no_system
    line
    lsp("c", links: { "b" => 10 }, prefixes: { "192.0.2.4/32" => 1 }, number: 1)
    @db.purge(@db[id("c") + "\x00".b], "test")
    calc = spf([[id("b"), 10, adj("b")]])
    assert_nil route(calc, "192.0.2.4/32")
  end

  # Step 1 a: the links and prefixes of every LSP Number of a system count
  # once LSP 0 is there.
  def test_other_lsp_numbers_count
    line
    lsp("c", prefixes: { "192.0.2.33/32" => 2 }, number: 1)
    calc = spf([[id("b"), 10, adj("b")]])
    assert_equal "192.0.2.33/32 metric 22 via 10.0.0.11 via eth-b", route(calc, "192.0.2.33/32")
  end

  # RFC 5305 section 3: a link at 2^24 - 1 is not used.
  def test_a_link_at_the_maximum_metric_is_not_used
    lsp("a", links: { "b" => 10 })
    lsp("b", links: { "a" => 10, "c" => 0xFFFFFF })
    lsp("c", links: { "b" => 0xFFFFFF }, prefixes: { "192.0.2.3/32" => 1 })
    calc = spf([[id("b"), 10, adj("b")]])
    assert_nil route(calc, "192.0.2.3/32")
  end

  # RFC 5305 section 4: a prefix over MAX_PATH_METRIC is not used.
  def test_a_prefix_over_the_maximum_path_metric_is_not_used
    lsp("a", links: { "b" => 10 })
    lsp("b", links: { "a" => 10 }, prefixes: { "192.0.2.2/32" => 0xFE000001, "192.0.2.22/32" => 0xFE000000 - 10 })
    calc = spf([[id("b"), 10, adj("b")]])
    assert_nil route(calc, "192.0.2.2/32")
    assert_equal 0xFE000000, calc.routes["192.0.2.22/32"].metric
  end

  # Step 1 b: a path over MaxPathMetric is not used. Narrow, 1023: B's
  # prefix at 10 + 63 is in, and C, at 10 + 1020, is not on PATHS.
  def test_a_path_over_max_path_metric_is_not_used
    lsp("a", links: { "b" => 10 })
    lsp("b", links: { "a" => 10, "c" => 1020 }, prefixes: { "192.0.2.2/32" => 63 })
    lsp("c", links: { "b" => 1020 }, prefixes: { "192.0.2.3/32" => 0 })
    calc = spf([[id("b"), 10, adj("b")]], max_path_metric: ISIS::Spf::MAX_PATH_METRIC_NARROW)
    assert_equal 73, calc.routes["192.0.2.2/32"].metric
    assert_nil route(calc, "192.0.2.3/32")
    assert_equal [0, 10], calc.paths.values.map(&:distance)
  end

  # Narrow metrics: TLV 2 and TLV 128, the default metric.
  def test_narrow_metrics
    lsp("a", links: { "b" => 10 }, narrow: true)
    lsp("b", links: { "a" => 10, "c" => 10 }, narrow: true)
    lsp("c", links: { "b" => 10 }, prefixes: { "192.0.2.3/32" => 1 }, narrow: true)
    calc = spf([[id("b"), 10, adj("b")]])
    assert_equal "192.0.2.3/32 metric 21 via 10.0.0.11 via eth-b", route(calc, "192.0.2.3/32")
  end

  # Both encodings in one system: the lower metric counts, whichever comes
  # first. B's link to C is 10 wide in LSP 0 and 30 narrow in LSP 1, and
  # C's prefix 5 narrow in LSP 0 and 1 wide in LSP 1.
  def test_the_lower_of_narrow_and_wide
    lsp("a", links: { "b" => 10 })
    lsp("b", links: { "a" => 10, "c" => 10 })
    lsp("b", links: { "c" => 30 }, number: 1, narrow: true)
    lsp("c", links: { "b" => 10 }, prefixes: { "192.0.2.3/32" => 5 }, narrow: true)
    lsp("c", prefixes: { "192.0.2.3/32" => 1 }, number: 1)
    calc = spf([[id("b"), 10, adj("b")]])
    assert_equal 21, calc.routes["192.0.2.3/32"].metric
  end

  # A LAN, B.01 the pseudonode, listing A, B and C at 0 (7.2.3). A's
  # adjacency to C is not Up, so step 0 i reaches C through the DIS, B:
  # 10 + C's prefix at 1.
  def test_step_0_reaches_a_lan_system_through_the_dis
    lsp("a", links: { ["b", 1] => 10 })
    lsp(["b", 1], links: { "a" => 0, "b" => 0, "c" => 0 })
    lsp("b", links: { ["b", 1] => 10 })
    lsp("c", links: { ["b", 1] => 10 }, prefixes: { "192.0.2.3/32" => 1 })
    dis = adj("b")
    calc = spf([[id("b"), 10, dis]], broadcast: [[id("b", 1), 10, dis]])
    assert_equal "192.0.2.3/32 metric 11 via 10.0.0.11 via eth-b", route(calc, "192.0.2.3/32")
  end

  # A pseudonode reached through a neighbour's LSP: A to B 10, B to B.01
  # 10, B.01 to C 0 (7.2.3), so C is at 20 and its prefix at 21.
  def test_a_pseudonode_beyond_a_neighbour
    lsp("a", links: { "b" => 10 })
    lsp("b", links: { "a" => 10, ["b", 1] => 10 })
    lsp(["b", 1], links: { "b" => 0, "c" => 0 })
    lsp("c", links: { ["b", 1] => 10 }, prefixes: { "192.0.2.3/32" => 1 })
    calc = spf([[id("b"), 10, adj("b")]])
    assert_equal "192.0.2.3/32 metric 21 via 10.0.0.11 via eth-b", route(calc, "192.0.2.3/32")
  end

  # Step 2 a 1: at one distance a pseudonode goes on PATHS first. Here N,
  # 0000.0000.000b, is at 10 directly, and C.01 at 10 through C (5 + 5),
  # with a zero link to N. Taking C.01 first gives N both first hops; N
  # first, its lower ID, would leave C's.
  def test_a_pseudonode_goes_on_paths_first
    lsp("a", links: { "b" => 10, "c" => 5 })
    lsp("c", links: { "a" => 5, ["c", 1] => 5 })
    lsp(["c", 1], links: { "c" => 0, "b" => 0 })
    lsp("b", links: { "a" => 10, ["c", 1] => 0 }, prefixes: { "192.0.2.2/32" => 1 })
    calc = spf([[id("b"), 10, adj("b")], [id("c"), 5, adj("c")]])
    assert_equal "192.0.2.2/32 metric 11 via 10.0.0.11 via eth-b, 10.0.0.12 via eth-c", route(calc, "192.0.2.2/32")
  end
end
