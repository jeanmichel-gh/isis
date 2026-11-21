# frozen_string_literal: true

require_relative "../../test_helper"

# Spf::TiLfa, RFC 9855, on graphs written by hand: the RFC's own two
# figures with the answers it gives, each case of its section 5, and what
# leaves a destination unprotected. Then a property: on random
# topologies, every repair, forwarded hop by hop through every router's
# tables from before the failure, reaches its destination without
# crossing the failure; and with every SID present, every destination
# still reachable is protected.
class TestSpfTiLfa < Minitest::Test
  G = ISIS::Spf::Graph
  T = ISIS::Spf::TiLfa

  # A graph of +links+, { [a, b] => metric } both ways, with a Node-SID
  # for every node and an Adj-SID for every adjacency unless told.
  def graph(links, node_sids: nil, overloaded: [])
    nodes = links.keys.flatten.uniq
    adj = links.keys.flat_map { |a, b| [[a, b], [b, a]] }.each_with_index.to_h { |k, i| [k, 15_000 + i] }
    sids = node_sids || nodes.each_with_index.to_h { |n, i| [n, i + 1] }
    G.symmetric(links, node_sids: sids, adj_sids: adj, overloaded: overloaded)
  end

  def segments(r) = r.segments.map { |s| s[:node] ? [:node, s[:node]] : [:adj, *s[:adj]] }

  # RFC 9855 section 5, Figure 1: "1k" on the starred links, 1 on the
  # others.
  FIGURE1 = { %w[S N1] => 1, %w[N1 D] => 1, %w[S N2] => 1, %w[S N3] => 1000, %w[N1 R1] => 1, %w[N1 R2] => 1,
              %w[D R3] => 1, %w[N2 R1] => 1, %w[R1 R2] => 1000, %w[R2 R3] => 1000, %w[N3 R1] => 1000 }.freeze

  # "the TI-LFA RL of S for destination D considering the failure of node
  # N1 is: <Node-SID(R1), Adj-SID(R1-R2), Adj-SID(R2-R3)>", leaving for
  # N2, the path's first hop.
  def test_rfc_figure_1
    t = T.new(graph(FIGURE1), root: "S")
    r = t.repair("D", t.node("N1"))
    assert_equal [[:node, "R1"], [:adj, "R1", "R2"], [:adj, "R2", "R3"]], segments(r)
    assert_equal ["N2", "R1", "R3", :p_and_q_apart], [r.first_hop, r.p, r.q, r.case]
    assert_equal %w[S N2 R1 R2 R3 D], r.path
  end

  # Section 9, Figure 2: "all the metrics are equal to 1 except
  # R2-R7,R7-R8,R8-R4,R7-R9, which have a metric of 1000"; R2 protects
  # against node R3: "the RL computed by R2 will be [adj-sid(R7-R8),
  # adj-sid(R8-R4)], and the outgoing interface will be to R7".
  FIGURE2 = { %w[S R2] => 1, %w[R2 R3] => 1, %w[R3 R4] => 1, %w[R4 R5] => 1, %w[R5 D] => 1,
              %w[R2 R7] => 1000, %w[R3 R7] => 1, %w[R3 R8] => 1, %w[R7 R8] => 1000, %w[R8 R4] => 1000,
              %w[R7 R9] => 1000, %w[R8 R10] => 1, %w[R9 R10] => 1 }.freeze

  def test_rfc_figure_2
    t = T.new(graph(FIGURE2), root: "R2")
    r = t.repair("D", t.node("R3"))
    assert_equal [[:adj, "R7", "R8"], [:adj, "R8", "R4"]], segments(r)
    assert_equal ["R7", "R7", "R4"], [r.first_hop, r.p, r.q]
  end

  # 5.1: the neighbour on the post-convergence path is in P and Q: no
  # segment.
  def test_a_neighbor
    t = T.new(graph({ %w[S F] => 1, %w[F D] => 1, %w[S N] => 2, %w[N D] => 1 }), root: "S")
    r = t.repair("D", t.link("F"))
    assert_equal ["N", [], :neighbor], [r.first_hop, segments(r), r.case]
  end

  # 5.2: B is in A's P-space and in Q(D), A is not in Q(D).
  def test_a_pq_node
    t = T.new(graph({ %w[S F] => 1, %w[F D] => 1, %w[S A] => 1, %w[A B] => 1, %w[B D] => 3 }), root: "S")
    r = t.repair("D", t.link("F"))
    assert_equal ["A", [[:node, "B"]], :pq_node], [r.first_hop, segments(r), r.case]
  end

  # 5.3: P is B, Q is D, adjacent.
  def test_p_and_q_adjacent
    t = T.new(graph({ %w[S F] => 1, %w[F D] => 1, %w[S A] => 1, %w[A B] => 1, %w[B D] => 5 }), root: "S")
    r = t.repair("D", t.link("F"))
    assert_equal [[:node, "B"], [:adj, "B", "D"]], segments(r)
    assert_equal :p_and_q_adjacent, r.case
  end

  # Another primary first hop survives: ECMP, no repair list.
  def test_ecmp
    t = T.new(graph({ %w[S F] => 1, %w[F D] => 1, %w[S A] => 1, %w[A D] => 1 }), root: "S")
    e = t.protect(t.link("F"))["D"]
    assert_instance_of T::Ecmp, e
    assert_equal ["A"], e.next_hops
  end

  # What protect returns: each destination with N1 among its primary
  # first hops, and none other. R1 is reached at 2 through N1 and through
  # N2, so N2 still serves it: ECMP.
  def test_protect_lists_what_the_failure_cuts
    t = T.new(graph(FIGURE1), root: "S")
    got = t.protect(t.link("N1"))
    assert_equal %w[D N1 R1 R2 R3], got.keys.sort
    assert_instance_of T::Ecmp, got["R1"]
    assert(got.values_at("D", "N1", "R2", "R3").all? { _1.is_a?(T::Repair) })
  end

  def test_no_path
    t = T.new(graph({ %w[S F] => 1, %w[F D] => 1 }), root: "S")
    assert_equal :no_path, t.repair("D", t.link("F")).reason
  end

  def test_no_sid
    g = graph(FIGURE1, node_sids: { "D" => 9 })
    t = T.new(g, root: "S")
    assert_equal :no_sid, t.repair("D", t.node("N1")).reason
  end

  def test_too_deep
    t = T.new(graph(FIGURE1), root: "S", max_depth: 3)
    assert_equal :too_deep, t.repair("D", t.node("N1")).reason
  end

  # Clause 7.2.8.1: B overloaded carries no transit, so nothing is left.
  def test_overload
    t = T.new(graph({ %w[S F] => 1, %w[F D] => 1, %w[S A] => 1, %w[A B] => 1, %w[B D] => 5 }, overloaded: %w[B]),
              root: "S")
    assert_equal :no_path, t.repair("D", t.link("F")).reason
  end

  # Node protection of the neighbour's own address: nothing can.
  def test_the_neighbor_itself
    t = T.new(graph(FIGURE1), root: "S")
    assert_equal :neighbor, t.repair("N1", t.node("N1")).reason
  end

  # A link counts when both ends report it.
  def test_one_way_links_do_not_count
    g = G.new({ %w[S A] => 1, %w[A S] => 1, %w[A B] => 1 })
    assert_equal %w[A S], g.nodes.sort
  end

  # ---- the property ----

  # Every equal-cost path from +from+ to +to+, as the routers' tables
  # before the failure have them, reaches +to+ and never crosses it.
  def avoids?(g, from, to, failure)
    tree = g.tree(to, reverse: true)
    return false unless tree.reached?(from)

    stack = [from]
    seen = {}
    while (v = stack.pop)
      next if v == to || seen[v]

      seen[v] = true
      tree.parents[v].each do |u|
        return false if failure.crossed?(v, u)

        stack << u
      end
    end
    true
  end

  # The repair, followed hop by hop: to the first hop, through each
  # segment, then to the destination.
  def delivers?(g, root, r)
    f = r.failure
    return false if f.crossed?(root, r.first_hop)

    at = r.first_hop
    r.segments.each do |s|
      if s[:node]
        return false unless avoids?(g, at, s[:node], f)

        at = s[:node]
      else
        a, b = s[:adj]
        return false unless at == a && g.metric(a, b) && !f.crossed?(a, b)

        at = b
      end
    end
    avoids?(g, at, r.destination, f)
  end

  # A connected graph of +n+ nodes: a random tree, then more links, each
  # direction its own metric a third of the time.
  def random_graph(rng, n)
    names = (0...n).map { "n#{_1}" }
    links = {}
    add = lambda do |a, b|
      m = rng.rand(1..10)
      links[[a, b]] = m
      links[[b, a]] = rng.rand(3).zero? ? rng.rand(1..10) : m
    end
    (1...n).each { |i| add.(names[i], names[rng.rand(i)]) }
    rng.rand(n).times do
      a, b = names.sample(2, random: rng)
      add.(a, b) unless links.key?([a, b])
    end
    adj = links.keys.each_with_index.to_h { |k, i| [k, 15_000 + i] }
    G.new(links, node_sids: names.each_with_index.to_h { |x, i| [x, i] }, adj_sids: adj)
  end

  def test_every_repair_delivers_and_every_reachable_destination_is_protected
    rng = Random.new(9855)
    repairs = 0
    300.times do
      g = random_graph(rng, rng.rand(4..12))
      t = T.new(g, root: "n0", max_depth: 100)
      g.neighbors("n0").each do |nb|
        [t.link(nb), t.node(nb)].each do |f|
          t.protect(f).each_value do |r|
            case r
            when T::Repair
              assert delivers?(g, "n0", r), "#{r} does not deliver, #{f}, #{g.edges}"
              repairs += 1
            when T::Unprotected
              assert_includes %i[no_path neighbor], r.reason, "#{r}, #{f}"
              refute g.tree("n0", failure: f).reached?(r.destination), "#{r} has a path" if r.reason == :no_path
            end
          end
        end
      end
    end
    assert_operator repairs, :>, 500, "the property ran on enough repairs"
  end
end
