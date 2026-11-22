# frozen_string_literal: true

module ISIS
  module Spf
    # TI-LFA's backups for one level's routes, after an SPF run: for each
    # adjacency on an interface with ti_lfa, each route whose primary next
    # hops all go through that neighbour gets a backup, a next hop and the
    # labels to push, or the reason it has none (docs/ti-lfa.md; routescope
    # docs/design/ti-lfa.md, step 2). It computes and changes nothing; the
    # forwarding installs nothing of it yet.
    #
    # The labels, top first, as RFC 9855 section 7.1 has them for an MPLS
    # data plane:
    #
    # * each segment of the repair (TiLfa): a Node-SID, as its index in
    #   the SRGB of the neighbour the packet leaves for (RFC 8660 section
    #   2.10.1), or an Adj-SID's label;
    # * then the route's own Prefix-SID, "pushed again with a label value
    #   computed according to the Segment Routing Global Block (SRGB) of
    #   Q, where Q is the endpoint of the RL" (7.1 rule 2). Not when Q
    #   advertises the prefix itself: the packet arrives there as it would
    #   with the label popped. A route with no Prefix-SID has the repair's
    #   labels alone, and goes on from Q as IP.
    #
    # A label route for a Prefix-SID backs up with the same labels.
    #
    # With ti_lfa: node, the failure is the neighbour itself. A route the
    # node failure leaves unprotected takes the link failure's backup
    # where there is one, a fallback: the neighbour's own prefixes always
    # do, since nothing avoids the node they are on. As FRR's
    # "node-protection link-fallback".
    class Backups
      # A route's backup: the adjacency it leaves on, the labels top first,
      # and the repair it encodes. +fallback+ is true for a link backup
      # taken because node protection found none.
      Backup = Struct.new(:adjacency, :labels, :repair, :fallback) do
        def protected? = true

        # :node or :link, what it protects against.
        def protects = repair.failure.kind
      end

      # A route with no backup, and why: TiLfa's reasons, and :no_label
      # when a label cannot be had from an SRGB.
      Unprotected = Struct.new(:reason, :failure) do
        def protected? = false
      end

      # Another primary next hop is left.
      Ecmp = Struct.new(:failure, :fallback) do
        def protected? = true
      end

      # What one protected adjacency gave: +fallback+ counts the routes
      # protected against the link because the node left them unprotected.
      Summary = Struct.new(:interface, :neighbor, :mode, :protected, :ecmp, :unprotected, :fallback)

      attr_reader :routes, :labels, :summaries, :trees, :seconds

      # +routes+, prefix => Route, and +labels+, the run's Spf::Labels;
      # +adjacencies+, [node ID, metric, Adjacency] for each adjacency Up;
      # +interfaces+, name => :link or :node, the interfaces with ti_lfa (a
      # list of names is :link for each); +clock+ times the work.
      def initialize(database:, system_id:, routes:, labels:, adjacencies:, interfaces:, clock: nil)
        @database = database
        @root = (Pdu.dotted_octets(system_id) + "\x00".b).b
        @all = routes
        @table = labels
        @adjacencies = adjacencies
        @interfaces = interfaces.is_a?(Hash) ? interfaces : interfaces.to_h { [_1, :link] }
        @clock = clock
        @routes = {}
        @labels = {}
        @summaries = []
        @trees = 0
        @seconds = 0.0
      end

      def compute
        started = @clock&.now
        graph = Graph.from_database(@database)
        ti = TiLfa.new(graph, root: @root)
        @adjacencies.each do |node, _metric, adj|
          mode = @interfaces[adj.circuit] or next

          protect(graph, ti, node.b, adj, mode)
        end
        @trees = graph.trees
        @seconds = @clock ? @clock.now - started : 0.0
        self
      end

      # The backup of the label route +label+, or nil.
      def label(label)
        @labels[label]
      end

      private

      def protect(graph, ti, neighbor, adj, mode)
        link = ti.link(neighbor)
        found_link = ti.protect(link)
        node = mode == :node ? ti.node(neighbor) : nil
        found_node = node ? ti.protect(node) : nil
        summary = Summary.new(adj.circuit, adj.neighbor, mode, 0, 0, Hash.new(0), 0)
        @all.each_value do |route|
          next if route.local? || route.origin.nil?
          next unless route.adjacencies.any? { _1.neighbor.b == adj.neighbor.b && _1.circuit == adj.circuit }

          backup = backup_of(graph, route, (found_node || found_link)[route.origin.b], node || link)
          if node && !backup.protected?
            fallback = backup_of(graph, route, found_link[route.origin.b], link)
            if fallback.protected?
              fallback.fallback = true
              summary.fallback += 1
              backup = fallback
            end
          end
          @routes[route.prefix] = backup
          count(summary, backup)
          label_backup(route, backup)
        end
        @summaries << summary
      end

      def backup_of(graph, route, result, failure)
        # Another primary next hop on another adjacency survives.
        return Ecmp.new(failure) if route.adjacencies.any? { _1.neighbor.b != failure.b.byteslice(0, 6) }

        case result
        when TiLfa::Repair then encode(graph, route, result)
        when TiLfa::Unprotected then Unprotected.new(result.reason, failure)
        when TiLfa::Ecmp then Ecmp.new(failure)
        else Unprotected.new(:no_path, failure)
        end
      end

      # The repair as labels, or Unprotected :no_label.
      def encode(graph, route, repair)
        adj = first_adjacency(repair.first_hop) or return Unprotected.new(:no_path, repair.failure)
        out = repair.segments.map do |s|
          if s[:node]
            node_label(repair.first_hop, graph.node_sids[s[:node]])
          else
            graph.adj_sids[s[:adj]]
          end
        end
        index = route.sid&.index
        out << node_label(repair.q, index) if index && repair.q != route.origin.b
        return Unprotected.new(:no_label, repair.failure) if out.any?(&:nil?)

        Backup.new(adj, out, repair)
      end

      # Index +index+ in +node+'s SRGB, as the label table read it.
      def node_label(node, index)
        return nil if index.nil?

        @table&.nodes&.[](node)&.label(index)
      end

      def first_adjacency(node)
        @adjacencies.find { |n, _, _| n.b == node }&.last
      end

      def label_backup(route, backup)
        return unless @table

        @table.entries.each_value do |e|
          @labels[e.label] = backup if e.kind == :prefix_sid && e.fec == route.prefix
        end
      end

      def count(summary, backup)
        case backup
        when Backup then summary.protected += 1
        when Ecmp then summary.ecmp += 1
        else summary.unprotected[backup.reason] += 1
        end
      end
    end
  end
end
