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
    # What breaks a clause is a finding, from ISIS::Validation, acted on
    # under the receive policy (+policy+, :rfc by default): an SRGB that
    # breaks RFC 8660 section 2.3, a second SR-Capabilities, a Prefix-SID
    # with an invalid V and L, or that is a label, or for an algorithm its
    # origin does not run, two prefixes with one index. Each finding's text
    # is also a problem.
    #
    # What cannot be computed, though no sender broke a clause, is a
    # problem only: an index past this system's SRGB, a neighbor without an
    # SRGB. Both are kept with the table and not raised.
    class Labels
      IMPLICIT_NULL = 3
      EXPLICIT_NULL = { ipv4: 0, ipv6: 2 }.freeze

      # One in-label: +op+ is :swap, :php (popped before the owner, every
      # next hop implicit null) or :pop; +kind+ :prefix_sid or :adj_sid;
      # +fec+ the prefix, or the neighbor's System ID; +hops+ a list of
      # [Spf::Adjacency, out-label].
      Entry = Struct.new(:label, :op, :kind, :fec, :hops)

      # A node's SR state as its LSPs give it: the SRGB as [first, last]
      # ranges, in order, and the algorithms it runs. For the views, also
      # its Router ID and SRLB from TLV 242, and its Node-SID: +sid+ the
      # index, +prefix+ the prefix it is on. Each is nil when not
      # advertised.
      # +ignored+ is true when a :strict policy refused the node's SR data.
      Node = Struct.new(:srgb, :algorithms, :router_id, :srlb, :sid, :prefix, :ignored) do
        # RFC 8660 section 2.4: index I across the ranges, or nil past the
        # end.
        def label(index)
          Labels.label_at(srgb, index)
        end
      end

      attr_reader :entries, :out_labels, :problems, :nodes, :findings, :policy

      # +own+ is this system's SegmentRouting; +paths+ the SPF's, whose keys
      # are the nodes reachable at this level.
      def initialize(own:, database:, paths:, policy: nil)
        @own = own
        @policy = Validation.policy(policy || (own.receive_policy if own.respond_to?(:receive_policy)))
        @findings = []
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
            found(Validation.prefix_sid_duplicate(index, list.map(&:prefix).uniq))
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
          all_gb = caps.flat_map { |t| t.subtlvs.select { _1.is_a?(SubTlv::SrCapabilities) } }
          gb = all_gb.first
          next unless gb

          id = SystemId.from_bytes(node.byteslice(0, 6)).to_s
          algos = caps.flat_map { |t| t.subtlvs.select { _1.is_a?(SubTlv::SrAlgorithm) } }.first&.algorithms || [0]
          seen = Validation.sr_capabilities(all_gb.size, id) + Validation.srgb(gb.ranges, id)
          seen.each { found(_1) }
          actions = seen.map { Validation.action(_1, @policy) }
          ignored = actions.include?(:ignore_node)
          srgb = gb.ranges.empty? || ignored || actions.include?(:ignore_srgb) ? nil : gb.ranges
          problem("#{id}: it advertises no SRGB range, ignored") if gb.ranges.empty?
          srlb = caps.flat_map { |t| t.subtlvs.select { _1.is_a?(SubTlv::SrLocalBlock) } }.first&.ranges
          sid, prefix = ignored ? nil : node_sid(lsps, algos)
          @nodes[node] = Node.new(srgb, algos, caps.first.router_id&.to_s, srlb, sid, prefix, ignored)
        end
      end

      # The node's Node-SID: the first Prefix-SID for algorithm 0 with the
      # N flag and an index, in its lowest-numbered LSP first. [index,
      # prefix], or nil. RFC 8667 section 2.1.1.1: N marks the prefix as
      # one that identifies the node.
      def node_sid(lsps, algorithms)
        lsps.each do |lsp|
          lsp.tlvs.each do |t|
            next unless t.is_a?(Tlv::ExtendedIpReachability) || t.is_a?(Tlv::Ipv6Reachability)

            t.entries.each do |e|
              s = e.subtlvs&.find { _1.is_a?(SubTlv::PrefixSid) && _1.algorithm.zero? }
              next unless s && e.prefix && s.flag?("N")
              next if Validation.prefix_sid(s, algorithms, e.prefix).any? { Validation.action(_1, @policy) != :use }

              return [s.index, e.prefix] if s.index
            end
          end
        end
        nil
      end

      # The route's Prefix-SID index, or nil when it has none it can use.
      def usable_index(route)
        sid = route.sid or return nil
        origin = route.origin && @nodes[route.origin]
        return nil if origin&.ignored

        seen = Validation.prefix_sid(sid, origin&.algorithms, route.prefix)
        seen.each { found(_1) }
        return nil if seen.any? { Validation.action(_1, @policy) != :use }

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

      # A finding, once, and its text as a problem.
      def found(finding)
        return if @findings.include?(finding)

        @findings << finding
        problem(finding.to_s)
      end
    end
  end
end
