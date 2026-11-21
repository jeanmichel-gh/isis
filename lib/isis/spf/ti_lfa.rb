# frozen_string_literal: true

module ISIS
  module Spf
    # TI-LFA, RFC 9855: for a failure next to this system, the Point of
    # Local Repair, a repair path to each destination it cuts, computed
    # before the failure. Pure calculation over a Graph; installing the
    # repairs is the forwarding's (routescope docs/design/ti-lfa.md, step
    # 2).
    #
    # The repair follows the post-convergence path, "SPT_new(R, X)" (section
    # 3), as a list of segments (section 5). The first node of that path in
    # both the P-space of the path's first hop and Q(D, X) is a PQ node, and
    # the shortest repair. Without one, P is the last node of the path in
    # that P-space, and Q the first node after P in Q(D, X); the destination
    # is always in Q(D, X), so there is one. Then, as section 5 lists:
    #
    # * 5.1, P is the first hop and in Q: no segment, just that neighbour.
    # * 5.2, P is in Q: a node segment to P.
    # * 5.3, Q follows P on the path: a node segment to P, then the
    #   Adj-SID from P to Q.
    # * 5.4, Q further on: a node segment to P, then the Adj-SIDs along
    #   the path from P to Q. Section 3 allows "Adjacency SIDs only"; a
    #   shorter list is left for later (ti-lfa.md, decision 1).
    #
    # When P is the first hop, the packet goes to it directly and the node
    # segment to P is left out.
    #
    # P-space here is the first hop's own: RFC 9855 section 4.1 excludes
    # "neighbors that are not on the post-convergence path" from the
    # extended P-space, and the path has one first hop. Pseudonodes are
    # never P or Q: they have no Node-SID; an Adj-SID across a LAN is the
    # LAN-Adj-SID of the system past it.
    #
    # A failure is a link to a neighbour, or the neighbour itself. Both
    # are computed here; which an interface protects is configuration
    # (step 2), and node protection's link fallback is step 3.
    class TiLfa
      # Labels a push may carry: Linux refuses 31 (ti-lfa.md, "What
      # exists"). The repair list's segments and the destination's own.
      MAX_DEPTH = 30

      # A repair: the neighbour the packet leaves for, the segments in
      # order (each { node: } or { adj: [from, to] }), the case of section
      # 5, P and Q, and the post-convergence path.
      Repair = Struct.new(:destination, :failure, :first_hop, :segments, :case, :p, :q, :path) do
        def protected? = true

        def to_s
          list = segments.map { |s| s[:node] ? "Node-SID(#{s[:node]})" : "Adj-SID(#{s[:adj].join('-')})" }
          "#{destination}: via #{first_hop}, <#{list.join(', ')}> (#{self.case})"
        end
      end

      # No repair, and why: :no_path (the failure cuts the destination
      # off), :no_sid (a segment's node or adjacency has no SID),
      # :too_deep (more than MAX_DEPTH labels), :neighbor (node protection
      # of the neighbour's own address, which nothing can).
      Unprotected = Struct.new(:destination, :failure, :reason) do
        def protected? = false

        def to_s = "#{destination}: unprotected, #{reason}"
      end

      # Another primary next hop survives the failure: ECMP, no repair list.
      Ecmp = Struct.new(:destination, :failure, :next_hops) do
        def protected? = true

        def to_s = "#{destination}: another primary next hop, #{next_hops.join(', ')}"
      end

      attr_reader :graph, :root

      def initialize(graph, root:, max_depth: MAX_DEPTH)
        @graph = graph
        @root = root
        @max_depth = max_depth
        @primary = graph.tree(root)
      end

      def link(neighbor) = Graph::Failure.new(:link, @root, neighbor)

      def node(neighbor) = Graph::Failure.new(:node, @root, neighbor)

      # Each destination whose every primary first hop is +neighbor+, with
      # what protects it against +failure+ (#link or #node). A destination
      # with another primary first hop is Ecmp.
      def protect(failure)
        @graph.nodes.reject { |d| d == @root || @graph.pseudonode?(d) }.sort_by(&:to_s).filter_map do |d|
          hops = first_hops(d)
          next unless hops.include?(failure.b)

          others = hops - [failure.b]
          next [d, Ecmp.new(d, failure, others)] unless others.empty?

          [d, repair(d, failure)]
        end.to_h
      end

      # The primary first hops toward +destination+, every equal-cost one.
      def first_hops(destination)
        return [] unless @primary.reached?(destination)

        @first_hops ||= {}
        @first_hops[destination] ||= @primary.parents[destination].flat_map do |p|
          p == @root ? [destination] : first_hops(p)
        end.uniq
      end

      # The repair toward +destination+ against +failure+.
      def repair(destination, failure)
        return Unprotected.new(destination, failure, :neighbor) if failure.node? && destination == failure.b

        post = @graph.tree(@root, failure: failure)
        return Unprotected.new(destination, failure, :no_path) unless post.reached?(destination)

        path = post.path(destination)
        first = path[1]
        p_space = @graph.avoiding(@graph.tree(first), failure)
        q_space = @graph.avoiding(@graph.tree(destination, reverse: true), failure)
        real = ->(k) { !@graph.pseudonode?(path[k]) }
        pq = (1...path.size).find { |k| real.(k) && p_space.include?(path[k]) && q_space.include?(path[k]) }
        i = pq || (1...path.size).select { |k| real.(k) && p_space.include?(path[k]) }.max
        j = pq || (i...path.size).find { |k| real.(k) && q_space.include?(path[k]) }
        segments = i == 1 ? [] : [{ node: path[i] }]
        segments += adjacencies(path[i..j])
        kind = if j == i then i == 1 ? :neighbor : :pq_node
               elsif adjacent?(path, i, j) then :p_and_q_adjacent
               else :p_and_q_apart
               end
        reason = check(segments)
        return Unprotected.new(destination, failure, reason) if reason

        Repair.new(destination, failure, first, segments, kind, path[i], path[j], path)
      end

      private

      # The Adj-SIDs along +nodes+, from system to system; a pseudonode
      # between two is crossed with the LAN-Adj-SID of the system past it.
      def adjacencies(nodes)
        systems = nodes.reject { |n| @graph.pseudonode?(n) }
        systems.each_cons(2).map { |a, b| { adj: [a, b] } }
      end

      # Q follows P with only a pseudonode, or nothing, between.
      def adjacent?(path, i, j)
        path[(i + 1)...j].all? { |n| @graph.pseudonode?(n) }
      end

      def check(segments)
        segments.each do |s|
          return :no_sid if s[:node] && !@graph.node_sids.key?(s[:node])
          return :no_sid if s[:adj] && !@graph.adj_sids.key?(s[:adj])
        end
        return :too_deep if segments.size + 1 > @max_depth

        nil
      end
    end
  end
end
