# frozen_string_literal: true

module ISIS
  module Spf
    # The MPLS label table one level's routes give, for segment routing
    # (RFC 8667 with RFC 8660's MPLS data plane). Computed after each SPF
    # run from the routes, the LSP database and this system's own blocks;
    # it changes neither. Installing it is a forwarding adapter's job, later
    # (docs/design/sr-mpls.md, PR 4).
    #
    # For a route whose prefix has a Prefix-SID of index I:
    #
    # * The in-label is I in this system's SRGB (RFC 8660 section 2.4).
    # * Toward each next hop N: when N advertised the prefix and P is clear,
    #   the label is popped, implicit null (RFC 8667 section 2.1.1.3: "any
    #   upstream neighbor of the Prefix-SID originator MUST pop the
    #   Prefix-SID"); with P and E set, explicit null, 0 for IPv4 and 2 for
    #   IPv6; otherwise I in N's SRGB (RFC 8660 section 2.10.1: "Calculate
    #   the outgoing label as specified in Section 2.4 using the SRGB of
    #   neighbor N"). A neighbor with no SRGB, or one too small for I,
    #   gives that next hop no label: section 2.10.1 has the packet go
    #   another way or plain, so the IP route still takes it.
    # * A prefix of this system's own gets a label only with P set, since
    #   with PHP no neighbor sends one. FRR 10.2.1 installs none either
    #   (docs/design/sr-mpls.md, "Measured on FRR 10.2.1").
    #
    # Each Adj-SID this system gave out pops and leaves on its adjacency
    # (RFC 8660 section 2.11, NEXT).
    #
    # What cannot be computed is a problem, kept with the table and not
    # raised: two prefixes with one index (both dropped; RFC 8660 section
    # 2.5's tie-breaking is not done), an index past this system's SRGB, a
    # Prefix-SID that is a label rather than an index, an algorithm its
    # origin does not run, a neighbor without an SRGB.
    class Labels
      IMPLICIT_NULL = 3
      EXPLICIT_NULL = { ipv4: 0, ipv6: 2 }.freeze

      # One in-label: +op+ is :swap, :php (popped before the owner, every
      # next hop implicit null) or :pop; +kind+ :prefix_sid or :adj_sid;
      # +fec+ the prefix, or the neighbor's System ID; +hops+ a list of
      # [Spf::Adjacency, out-label].
      Entry = Struct.new(:label, :op, :kind, :fec, :hops)

      # A node's SR state as its LSPs give it: the SRGB as [first, last]
      # ranges, in order, and the algorithms it runs.
      Node = Struct.new(:srgb, :algorithms) do
        # RFC 8660 section 2.4: index I across the ranges, or nil past the
        # end.
        def label(index)
          Labels.label_at(srgb, index)
        end
      end

      attr_reader :entries, :out_labels, :problems, :nodes

      # +own+ is this system's SegmentRouting; +paths+ the SPF's, whose keys
      # are the nodes reachable at this level.
      def initialize(own:, database:, paths:)
        @own = own
        @database = database
        @paths = paths
        @entries = {}
        @out_labels = {}
        @problems = []
        @nodes = {}
      end

      # Index I in +srgb+, a list of [first, last]: RFC 8660 section 2.4's
      # loop, "label = I - temp + Ll(j)".
      def self.label_at(srgb, index)
        return nil if index.nil? || index.negative?

        temp = 0
        srgb.each do |first, last|
          return index - temp + first if index - temp <= last - first

          temp += last - first + 1
        end
        nil
      end

      # Builds the table from +routes+, prefix => Route, and +adjacencies+,
      # the circuits' Spf::Adjacency list. Returns self.
      def build(routes, adjacencies)
        read_nodes
        own = @own.srgb.map { |first, size| [first, first + size - 1] }
        by_index = Hash.new { |h, k| h[k] = [] }
        routes.each_value do |r|
          next unless (index = usable_index(r))

          by_index[index] << r
        end
        by_index.each do |index, list|
          if list.map(&:prefix).uniq.size > 1
            problem("index #{index} is the Prefix-SID of #{list.map(&:prefix).sort.join(' and ')}: both left out " \
                    "(RFC 8660 section 2.5's tie-breaking is not done)")
            next
          end
          route = list.first
          label = Labels.label_at(own, index)
          unless label
            problem("#{route.prefix}: index #{index} is past this system's SRGB")
            next
          end
          prefix_entry(route, index, label)
        end
        adjacencies.each { |a| adj_entry(a) }
        self
      end

      # The out-label toward one adjacency of a route, or nil.
      def out_label(prefix, adjacency)
        @out_labels.dig(prefix, [adjacency.circuit, adjacency.neighbor.b])
      end

      private

      # Each reachable system's SRGB and algorithms. RFC 8667 section 3.1:
      # a router "SHOULD select the first advertisement in the
      # lowest-numbered LSP"; RFC 7981 section 3: a capability from a system
      # "not currently reachable" is not used, which the paths decide. An
      # SRGB that breaks RFC 8660 section 2.3's rules "MUST be completely
      # ignored", and its node "treated as if it does not have an SRGB".
      def read_nodes
        @paths.each_key do |node|
          next unless node.getbyte(-1).zero?

          lsps = @database.entries.select { |e| e.lsp && !e.purged? && e.lsp_id.byteslice(0, 7) == node }
                          .sort_by { |e| e.lsp_id.getbyte(-1) }.map(&:lsp)
          caps = lsps.flat_map { |l| l.tlvs.select { _1.is_a?(Tlv::RouterCapability) } }
          gb = caps.flat_map { |t| t.subtlvs.select { _1.is_a?(SubTlv::SrCapabilities) } }.first
          next unless gb

          algos = caps.flat_map { |t| t.subtlvs.select { _1.is_a?(SubTlv::SrAlgorithm) } }.first&.algorithms || [0]
          srgb = valid_srgb(gb.ranges) ? gb.ranges : nil
          problem("#{SystemId.from_bytes(node.byteslice(0, 6))}: its SRGB #{gb.ranges.inspect} is not valid, ignored") unless srgb
          @nodes[node] = Node.new(srgb, algos)
        end
      end

      def valid_srgb(ranges)
        return false if ranges.empty?

        ranges.all? { |a, b| a >= 16 && b <= 0xfffff && a <= b } &&
          ranges.combination(2).none? { |(a, b), (c, d)| a <= d && c <= b }
      end

      # The route's Prefix-SID index, or nil when it has none it can use.
      def usable_index(route)
        sid = route.sid or return nil
        unless sid.index
          problem("#{route.prefix}: its Prefix-SID is a label, not an index; not used")
          return nil
        end
        origin = route.origin && @nodes[route.origin]
        if origin && !origin.algorithms.include?(sid.algorithm)
          problem("#{route.prefix}: algorithm #{sid.algorithm} is not one its origin runs (RFC 8667 section 2.1)")
          return nil
        end
        sid.index
      end

      def prefix_entry(route, index, label)
        sid = route.sid
        if route.local?
          return unless sid.flag?(:p)

          @entries[label] = Entry.new(label, :pop, :prefix_sid, route.prefix, [])
          return
        end
        hops = route.adjacencies.filter_map do |a|
          out = out_for(route, a, index)
          [a, out] if out
        end
        return if hops.empty?

        hops.each { |a, out| (@out_labels[route.prefix] ||= {})[[a.circuit, a.neighbor.b]] = out }
        op = hops.all? { |_, out| out == IMPLICIT_NULL } ? :php : :swap
        @entries[label] = Entry.new(label, op, :prefix_sid, route.prefix, hops)
      end

      def out_for(route, adjacency, index)
        sid = route.sid
        owner = route.origin && adjacency.neighbor.b == route.origin.byteslice(0, 6)
        if owner && !sid.flag?(:p)
          IMPLICIT_NULL
        elsif owner && sid.flag?(:e)
          EXPLICIT_NULL.fetch(route.family)
        else
          node = @nodes[(adjacency.neighbor.b + "\x00".b).b]
          label = node&.srgb && node.label(index)
          problem("#{route.prefix}: neighbor #{SystemId.from_bytes(adjacency.neighbor.b)} " \
                  "#{node&.srgb ? "has no label for index #{index}" : 'has no SRGB'}; that next hop gets none") unless label
          label
        end
      end

      def adj_entry(adjacency)
        label = @own.adj_labels[[adjacency.circuit, adjacency.neighbor.b, :ipv4]] or return
        @entries[label] = Entry.new(label, :pop, :adj_sid, adjacency.neighbor.b, [[adjacency, IMPLICIT_NULL]])
      end

      def problem(text)
        @problems << text unless @problems.include?(text)
      end
    end
  end
end
