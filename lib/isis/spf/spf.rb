# frozen_string_literal: true

module ISIS
  # The shortest path calculation of RFC 1142 Annex C.2, for one level and
  # the default metric, over one link state database. It computes and
  # returns; it changes nothing. Spf::Decision runs it when the database
  # changes.
  #
  # Nodes are 7 octet IDs, the System ID and a pseudonode octet, as Annex
  # C.2.1 has them for the level 1 algorithm. The links of a node come from
  # TLV 22 and TLV 2 in all of its LSPs, and its IPv4 prefixes from TLV 135
  # and TLV 128. A node with both a narrow and a wide entry for one
  # neighbour or one prefix counts the lower metric. Prefixes are the "End
  # system neighbours" of Annex C.2.4 step 1: leaves, which an overloaded
  # node still reaches (7.2.8.1).
  #
  # It also finds the nearest attached Level 2 system, clause 7.2.9.1's
  # set R: "the set, R, of attached level 2 Intermediate system(s) for
  # metric k such that the total cost to R for metric k is minimal", where
  # attached is the default metric's ATT bit in the system's LSP Number 0
  # (7.2.5). RFC 1195 section 1.2: Level 1 routers send traffic for
  # outside their area only to "level 2 routers ... which indicate in
  # their level 1 LSPs that they are "attached"".
  #
  # Not here yet: the delay, expense and error metrics (7.2.2 makes them
  # optional), external routes and TLV 130, and IPv6.
  module Spf
    # RFC 1142 annex: "MaxPathMetric 1023. Maximum total metric value for a
    # complete path". For narrow metrics.
    MAX_PATH_METRIC_NARROW = 1023
    # RFC 5305 section 3: "we have chosen MAX_PATH_METRIC to be
    # 4,261,412,864 (0xFE000000, 2^32 - 2^25)". For wide metrics.
    MAX_PATH_METRIC = 0xFE000000
    # RFC 5305 section 3: "If a link is advertised with the maximum link
    # metric (2^24 - 1), this link MUST NOT be considered during the normal
    # SPF computation."
    MAX_LINK_METRIC = 0xFFFFFF
    # RFC 1142 annex: "maximumPathSplits-Default INTEGER ::= 2".
    MAXIMUM_PATH_SPLITS = 2

    # One adjacency this system may forward on: the circuit's name, the
    # neighbour's System ID, the circuit ID and LAN address 7.2.7 ranks by,
    # and the neighbour's IPv4 address from its hellos (RFC 1195 TLV 132),
    # nil when it sent none.
    Adjacency = Struct.new(:circuit, :neighbor, :circuit_id, :lan_address, :address, keyword_init: true) do
      # Clause 7.2.7's order after the metric sum: "neighbour ID", then
      # "circuit ID", then "lANAddress", lower first.
      def rank
        [neighbor.b, circuit_id.to_i, lan_address.to_s.b]
      end

      def to_s
        "#{address || neighbor.unpack1('H*').scan(/.{1,4}/).join('.')} via #{circuit}"
      end
    end

    # The route to +prefix+: its metric and the adjacencies it may use. A
    # route to a prefix this system advertises itself has none and is
    # local.
    Route = Struct.new(:prefix, :metric, :adjacencies) do
      def local?
        adjacencies.empty?
      end

      def to_s
        local? ? "#{prefix} metric #{metric} local" : "#{prefix} metric #{metric} via #{adjacencies.join(', ')}"
      end
    end

    # A node on PATHS: its distance and the adjacencies to it, empty for
    # this system, Annex C.2.4 step 0 a's W.
    Path = Struct.new(:distance, :adjacencies)

    # One run. +adjacencies+ is [node ID, metric, Adjacency] for each
    # adjacency Up (step 0 b), and +broadcast+ is [pseudonode ID, metric,
    # Adjacency to the DIS] for each broadcast circuit with a DIS other
    # than this system (step 0 i).
    class Calculation
      attr_reader :paths, :routes, :attached

      def initialize(database:, system_id:, adjacencies:, broadcast: [], max_path_splits: MAXIMUM_PATH_SPLITS,
                     max_path_metric: MAX_PATH_METRIC)
        @database = database
        @self_id = (Pdu.dotted_octets(system_id) + "\x00".b).b
        @adjacencies = adjacencies
        @broadcast = broadcast
        @max_path_splits = max_path_splits
        @max_path_metric = max_path_metric
        @paths = {}
        @routes = {}
        @nodes = {}
        # The nearest attached Level 2 system, as a Path: its distance and
        # the adjacencies toward it. Nil when none is reachable.
        @attached = nil
      end

      def run
        tent = {}
        # Step 0 a: "Add <SELF, 0, W> to PATHS".
        @paths[@self_id] = Path.new(0, [])
        add_prefixes(@self_id)
        # Step 0 b to g: TENT from the adjacencies Up, at the circuit's
        # metric.
        @adjacencies.each do |node, metric, adj|
          next if metric > @max_path_metric

          offer(tent, node.b, metric, [adj])
        end
        # Step 0 h and i: the systems a neighbouring pseudonode LSP lists,
        # which have no entry yet, through the DIS.
        @broadcast.each do |pseudonode, metric, dis|
          links(pseudonode.b)&.each_key do |n|
            offer(tent, n, metric, [dis]) unless tent.key?(n) || @paths.key?(n)
          end
        end
        # Step 2: the closest in TENT goes on PATHS, a pseudonode before a
        # non-pseudonode at one distance; then step 1 for it.
        until tent.empty?
          node, path = tent.min_by { |n, p| [p.distance, n.getbyte(-1).zero? ? 1 : 0, n] }
          tent.delete(node)
          @paths[node] = path
          extend_from(tent, node, path)
          add_prefixes(node)
          add_attached(node, path)
        end
        self
      end

      private

      # Step 1 for P, just placed on PATHS: each neighbour N its LSPs
      # report, at d(P) plus the link's metric, through P's adjacencies. Not
      # when P's LSP Number 0 has the LSP Database Overload bit set
      # (7.2.8.1), and not over a link N does not report back (7.2.8.2).
      def extend_from(tent, node, path)
        return if overloaded?(node)

        links(node)&.each do |n, metric|
          dist = path.distance + metric
          next if dist > @max_path_metric || @paths.key?(n)
          next unless links(n)&.key?(node)

          offer(tent, n, dist, path.adjacencies)
        end
      end

      # Steps 0 c to g and 1 d to e: a shorter path replaces, an equal one
      # adds its adjacencies, pruned to maximumPathSplits (7.2.7).
      def offer(tent, node, dist, adjacencies)
        held = tent[node]
        if held.nil? || dist < held.distance
          tent[node] = Path.new(dist, prune(adjacencies))
        elsif dist == held.distance
          held.adjacencies = prune(held.adjacencies | adjacencies)
        end
      end

      def prune(adjacencies)
        adjacencies.uniq.sort_by(&:rank).first(@max_path_splits)
      end

      # The prefixes P advertises, as leaves: the shortest to each wins, and
      # an equal one adds its adjacencies. A prefix this system advertises
      # stays local at an equal metric.
      def add_prefixes(node)
        path = @paths[node]
        prefixes(node)&.each do |prefix, metric|
          dist = path.distance + metric
          next if dist > @max_path_metric

          held = @routes[prefix]
          if held.nil? || dist < held.metric
            @routes[prefix] = Route.new(prefix, dist, prune(path.adjacencies))
          elsif dist == held.metric && !held.local?
            held.adjacencies = path.adjacencies.empty? ? [] : prune(held.adjacencies | path.adjacencies)
          end
        end
      end

      # Not asked of this system: its own links are its adjacencies (step
      # 0), so step 1 never runs for it.
      # A system placed on PATHS whose LSP Number 0 sets the default
      # metric's ATT bit joins R if it is as near as the nearest so far.
      # Systems go on PATHS in distance order, so the first one found is at
      # the least cost, and later ones join only at that cost.
      def add_attached(node, path)
        return unless node_info(node)&.fetch(:attached)

        if @attached.nil?
          @attached = Path.new(path.distance, prune(path.adjacencies))
        elsif path.distance == @attached.distance
          @attached.adjacencies = prune(@attached.adjacencies | path.adjacencies)
        end
      end

      def overloaded?(node)
        node_info(node)&.fetch(:overload)
      end

      def links(node)
        node_info(node)&.fetch(:links)
      end

      def prefixes(node)
        node_info(node)&.fetch(:prefixes)
      end

      def node_info(node)
        return @nodes[node] if @nodes.key?(node)

        lsps = node_lsps(node)
        @nodes[node] = lsps && { links: read_links(lsps), prefixes: read_prefixes(lsps),
                                 overload: lsps.first.overload?,
                                 attached: lsps.first.attached.include?(:default) }
      end

      # The LSPs of +node+, LSP Number 0 first, or nil. Clause 7.2.5: "If the
      # LSP with LSP Number zero and remaining lifetime > 0, is not present
      # for a particular system then the Decision Process shall not process
      # any LSPs with non-zero LSP Number which may be stored for that
      # system."
      def node_lsps(node)
        entries = @database.entries.select do |e|
          e.lsp && !e.purged? && e.lsp_id.byteslice(0, 7) == node
        end
        return nil unless entries.first&.lsp_id&.getbyte(-1)&.zero?

        entries.map(&:lsp)
      end

      def read_links(lsps)
        found = {}
        each_tlv(lsps) do |tlv|
          case tlv
          when Tlv::ExtendedIsReachability
            tlv.entries.each do |e|
              keep_lower(found, e.neighbor.b, e.metric) unless e.metric == MAX_LINK_METRIC
            end
          when Tlv::IsReachability
            tlv.entries.each { |e| keep_lower(found, e.neighbor.b, e.metrics.default) }
          end
        end
        found
      end

      # An entry that cannot be a prefix is skipped. RFC 5305 section 4: "If
      # a prefix is advertised with a metric larger then MAX_PATH_METRIC ...
      # this prefix MUST NOT be considered during the normal SPF
      # computation", which add_prefixes's limit on the path covers, since
      # the path to it is at least its metric.
      def read_prefixes(lsps)
        found = {}
        each_tlv(lsps) do |tlv|
          case tlv
          when Tlv::ExtendedIpReachability
            tlv.entries.each do |e|
              keep_lower(found, e.prefix, e.metric) if e.prefix
            end
          when Tlv::IpInternalReachability
            tlv.entries.each { |e| keep_lower(found, e.prefix, e.metrics.default) if e.prefix }
          end
        end
        found
      end

      def each_tlv(lsps, &block)
        lsps.each { |lsp| lsp.tlvs.each(&block) }
      end

      def keep_lower(hash, key, metric)
        hash[key] = metric if hash[key].nil? || metric < hash[key]
      end
    end
  end
end
