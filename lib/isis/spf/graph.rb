# frozen_string_literal: true

module ISIS
  module Spf
    # One level's topology as a graph, for calculations Spf::Calculation
    # does not make: rooted at any node, run backwards toward a node, run
    # with a link or a node removed, and keeping every equal-cost parent,
    # unpruned. TI-LFA needs all four (RFC 9855 sections 2.1 and 3;
    # routescope docs/design/ti-lfa.md, "The computation").
    #
    # A node is any value: a 7 octet node ID when read from a database,
    # a name in a test. A link counts only when both ends report it
    # (clause 7.2.8.2), each direction with its own metric. An overloaded
    # node is never transit (7.2.8.1), only a root or an end. A link at
    # the maximum link metric is not read (RFC 5305 section 3, as
    # Calculation).
    #
    # The SIDs a repair list needs ride along: each node's Node-SID, the
    # index of its Prefix-SID with the N flag (RFC 8667 section 2.1.1.2),
    # and each adjacency's Adj-SID label, a LAN's included (section 2.2),
    # keyed [from, to] by system.
    class Graph
      # A shortest path tree: each node's distance and every parent at that
      # distance. Rooted at +root+ forward, a parent is the node before; run
      # backward toward +root+, it is the next node toward it.
      Tree = Struct.new(:root, :dist, :parents, :reverse) do
        def reached?(node) = dist.key?(node)

        # One path from the root to +node+, forward, or from +node+ to the
        # root, backward; at each equal-cost split the parent that sorts
        # first, so the same graph always gives the same path.
        def path(node)
          return nil unless reached?(node)

          list = [node]
          list << parents[list.last].min_by(&:to_s) until list.last == root
          reverse ? list : list.reverse
        end
      end

      # What is removed: a link between +a+ and +b+, both directions, or
      # the node +b+, beside +a+, the root.
      Failure = Struct.new(:kind, :a, :b) do
        def node? = kind == :node

        def link? = kind == :link

        # True when going from +from+ to +to+ uses what failed.
        def crossed?(from, to)
          return [from, to].include?(b) if node?

          [from, to].sort_by(&:to_s) == [a, b].sort_by(&:to_s)
        end

        def to_s = node? ? "node #{b}" : "link #{a}-#{b}"
      end

      attr_reader :edges, :overloaded, :node_sids, :adj_sids, :pseudonodes

      # How many trees were computed, for a reader that times the work.
      attr_reader :trees

      # +links+ is { [from, to] => metric }, one entry per direction.
      def initialize(links, overloaded: [], node_sids: {}, adj_sids: {}, pseudonodes: [])
        @edges = Hash.new { |h, k| h[k] = {} }
        links.each do |(from, to), metric|
          @edges[from][to] = metric if links.key?([to, from])
        end
        @edges.default_proc = nil
        @overloaded = overloaded.to_a
        @node_sids = node_sids
        @adj_sids = adj_sids
        @pseudonodes = pseudonodes.to_a
        @trees = 0
      end

      # A graph from links given once each, both directions at one metric.
      def self.symmetric(links, **opts)
        new(links.each_with_object({}) { |((a, b), m), h| h[[a, b]] = m; h[[b, a]] = m }, **opts)
      end

      # The graph of one level's database: every system and pseudonode
      # with an LSP Number 0, read as Calculation reads them.
      def self.from_database(database)
        reader = Calculation.new(database: database, system_id: "0000.0000.0000", adjacencies: [])
        ids = database.entries.select { |e| e.lsp && !e.purged? }.map { |e| e.lsp_id.byteslice(0, 7) }.uniq
        links = {}
        overloaded = []
        node_sids = {}
        adj_sids = {}
        pseudonodes = []
        ids.each do |id|
          info = reader.node(id) or next
          pseudonodes << id unless id.getbyte(-1).zero?
          overloaded << id if info[:overload]
          info[:links].each { |n, metric| links[[id, n]] = metric }
          info[:prefixes].each_value do |offer|
            sid = offer.sid
            node_sids[id] ||= sid.index if sid&.index && sid.flag?("N")
          end
          read_adj_sids(reader.lsps(id), id, adj_sids)
        end
        new(links, overloaded: overloaded, node_sids: node_sids, adj_sids: adj_sids, pseudonodes: pseudonodes)
      end

      # Each IPv4 Adj-SID label (F clear, V and L set) in +lsps+' TLV 22:
      # to the neighbor, or across a LAN to the system a LAN-Adj-SID names.
      def self.read_adj_sids(lsps, id, found)
        lsps.each do |lsp|
          lsp.tlvs.grep(Tlv::ExtendedIsReachability).each do |tlv|
            tlv.entries.each do |e|
              e.subtlvs&.each do |s|
                next unless s.is_a?(SubTlv::AdjSid) && !s.flag?("F") && s.label
                next if s.is_a?(SubTlv::LanAdjSid) && s.neighbor.nil?

                to = s.is_a?(SubTlv::LanAdjSid) ? (Pdu.dotted_octets(s.neighbor.to_s) + "\x00".b).b : e.neighbor.b
                found[[id, to]] ||= s.label
              end
            end
          end
        end
      end

      def nodes
        (@edges.keys + @edges.values.flat_map(&:keys)).uniq
      end

      def neighbors(node)
        (@edges[node] || {}).keys
      end

      def metric(from, to)
        @edges.dig(from, to)
      end

      def pseudonode?(node) = @pseudonodes.include?(node)

      # Dijkstra from +root+, or with +reverse+ toward it, without
      # +failure+ when given. Every equal-cost parent is kept.
      def tree(root, failure: nil, reverse: false)
        @trees += 1
        dist = { root => 0 }
        parents = { root => [] }
        tent = { root => 0 }
        done = {}
        until tent.empty?
          node, d = tent.min_by { |n, v| [v, n.to_s] }
          tent.delete(node)
          done[node] = true
          # Forward, the node is transit for what lies past it; backward,
          # it is transit for what lies before it. Either way not when
          # overloaded, unless it is the root.
          next if node != root && @overloaded.include?(node)

          each_step(node, reverse) do |other, m|
            next if done[other]
            from, to = reverse ? [other, node] : [node, other]
            next if failure&.crossed?(from, to)

            nd = d + m
            if !dist.key?(other) || nd < dist[other]
              dist[other] = nd
              parents[other] = [node]
              tent[other] = nd
            elsif nd == dist[other]
              parents[other] |= [node]
            end
          end
        end
        Tree.new(root, dist, parents, reverse)
      end

      # The nodes of +tree+ that no equal-cost path of it takes through
      # +failure+: P-space for a forward tree, Q-space for a backward one
      # (RFC 9855 section 2.1, "including equal-cost path splits"). The
      # failed node itself is never in it.
      def avoiding(tree, failure)
        crossed = {}
        tree.dist.sort_by { |n, d| [d, n.to_s] }.each do |node, _|
          crossed[node] = tree.parents[node].any? do |p|
            from, to = tree.reverse ? [node, p] : [p, node]
            crossed[p] || failure.crossed?(from, to)
          end
          crossed[node] = true if failure.node? && node == failure.b
        end
        crossed.reject { |_, c| c }.keys
      end

      private

      def each_step(node, reverse, &block)
        if reverse
          @edges.each { |from, tos| yield(from, tos[node]) if tos.key?(node) }
        else
          (@edges[node] || {}).each(&block)
        end
      end
    end
  end
end
