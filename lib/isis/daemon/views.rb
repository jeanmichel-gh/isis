# frozen_string_literal: true

require "time"

module ISIS
  class Daemon
    # What the API answers, read from a Router: plain Hashes of strings and
    # numbers, ready for JSON. Reading changes nothing.
    class Views
      def initialize(router)
        @router = router
      end

      def overview
        r = @router
        {
          system_id: r.system_id_s, hostname: r.config[:hostname], levels: r.levels,
          areas: r.config.fetch(:areas, ["49.0001"]), version: VERSION,
          interfaces: r.interfaces.size,
          adjacencies_up: adjacencies.count { _1[:state] == "up" },
          lsps: r.levels.to_h { |l| [l, r.databases[l].entries.count { !_1.placeholder? }] },
          routes: r.levels.to_h { |l| [l, r.decisions[l].routes.size] },
          spf_runs: r.levels.to_h { |l| [l, r.decisions[l].runs] },
          overload: r.originators.values.first&.overload || false
        }
      end

      def interfaces
        @router.interfaces.flat_map do |i|
          i.circuits.map do |level, c|
            row = { name: i.name, network: i.network, level: level, metric: c.metric }
            if i.broadcast?
              row.merge(priority: c.priority, lan_id: c.lan_id_s, dis: dis(c), state: c.up_neighbors.empty? ? "down" : "up")
            else
              row.merge(local_circuit_id: c.local_circuit_id, state: c.three_way_state.to_s)
            end
          end
        end
      end

      # One row per neighbour per level: on a point to point circuit the one
      # neighbour at each level it serves, on a LAN each neighbour of that
      # level's circuit.
      def adjacencies
        names = hostnames
        @router.interfaces.flat_map do |i|
          i.circuits.flat_map do |level, c|
            neighbors = i.broadcast? ? c.neighbors.values : [c.neighbor].compact
            neighbors.filter_map do |n|
              next if !i.broadcast? && n.state == :up && !Array(n.usage).include?(level)

              row = { interface: i.name, level: level, network: i.network, system_id: n.system_id_s,
                      hostname: names[n.system_id_s], state: n.state.to_s, snpa: n.snpa.to_s,
                      address: Array(n.ip_addresses).first, address6: Array(n.ipv6_addresses).first,
                      areas: Array(n.areas).map(&:to_s), holding_time: n.holding_time, hold: hold(n.expiry) }
              row[:priority] = n.priority if i.broadcast?
              row
            end
          end
        end
      end

      def database(level: nil)
        names = hostnames
        mine = @router.system_id_s
        @router.levels.select { level.nil? || _1 == Integer(level) }.flat_map do |l|
          @router.databases[l].entries.reject(&:placeholder?).map do |e|
            lsp = e.lsp
            id = e.lsp_id_s
            system = id[0, 14]
            { level: l, lsp_id: id, hostname: names[system], sequence: e.sequence,
              checksum: format("0x%04x", e.checksum), lifetime: e.remaining_lifetime,
              length: lsp.encode.bytesize, att: !lsp.attached.empty?, p: lsp.partition?, ol: lsp.overload?,
              purged: e.purged?, self: system == mine }
          end
        end
      end

      def routes(level: nil)
        @router.levels.select { level.nil? || _1 == Integer(level) }.flat_map do |l|
          @router.decisions[l].routes.values.map do |r|
            { level: l, prefix: r.prefix.to_s, metric: r.metric, external: r.external ? true : false,
              up_down: r.up_down ? true : false,
              next_hops: r.adjacencies.map { |a| { address: a.next_hop(r.family), interface: interface_of(a.circuit) } } }
          end
        end
      end

      # One level's database as a topology, for a reader such as a BGP-LS
      # Producer (docs/design/bgp-ls-export.md): one node per System ID and
      # pseudonode octet, its LSP fragments merged. Purged LSPs and
      # placeholders are left out, and so is a node without LSP Number 0,
      # as clause 7.2.5 has the Decision Process leave it out. +reachable+
      # is whether the last SPF run placed the node on PATHS, and +run+ is
      # that run's number. A level the router does not run has no nodes.
      def topology(level:)
        raise ArgumentError, "show.topology needs level" if level.nil?

        l = Integer(level)
        decision = @router.decisions[l] if @router.levels.include?(l)
        return { level: l, run: 0, nodes: [] } unless decision

        names = hostnames
        lsps = @router.databases[l].entries.reject { _1.placeholder? || _1.purged? }
                      .group_by { _1.lsp_id.b[0...-1] }
        nodes = lsps.filter_map do |node, entries|
          next unless entries.first.lsp_id.getbyte(-1).zero? # entries come in LSP ID order

          topology_node(node, entries.map(&:lsp), names, decision.paths.key?(node))
        end
        { level: l, run: decision.runs, nodes: nodes.sort_by { _1[:id] } }
      end

      # The last +count+ events, oldest first.
      def log(count = 100)
        @router.log.events.last(count).map { |e| Views.event(e) }
      end

      def self.event(e)
        { time: e.time.utc.iso8601(3), level: e.level.to_s, circuit: e.circuit, kind: e.kind.to_s,
          message: plain(e.message), data: plain(e.data) }
      end

      # Event data as JSON can carry it: strings as valid UTF-8, symbols and
      # anything else as text.
      def self.plain(value)
        case value
        when Hash then value.to_h { |k, v| [k.to_s, plain(v)] }
        when Array then value.map { plain(_1) }
        when String then value.dup.force_encoding("UTF-8").scrub
        when Numeric, true, false, nil then value
        else value.to_s
        end
      end

      # System ID to hostname, from TLV 137 in each non-pseudonode LSP
      # Number 0 (RFC 5301 section 4), kept through its purge until the
      # header goes, and this system's own.
      def hostnames
        names = {}
        @router.databases.each_value do |db|
          db.entries.each do |e|
            names[e.lsp_id_s[0, 14]] = e.hostname if e.hostname && e.lsp_id_s[15, 2] == "00"
          end
        end
        names[@router.system_id_s] = @router.config[:hostname] if @router.config[:hostname]
        names
      end

      private

      # One node of #topology from its LSPs, LSP Number 0 first.
      def topology_node(node, lsps, names, reachable)
        id = node_s(node)
        zero = lsps.first
        { id: id, hostname: names[id[0...-3]],
          areas: zero.tlvs.grep(Tlv::AreaAddresses).flat_map(&:areas).map(&:to_s),
          overload: zero.overload?, attached: !zero.attached.empty?, reachable: reachable,
          neighbors: topology_neighbors(lsps), prefixes: topology_prefixes(lsps),
          interface_addresses: topology_addresses(lsps, Tlv::IpInterfaceAddresses),
          ipv6_interface_addresses: topology_addresses(lsps, Tlv::Ipv6InterfaceAddresses) }
      end

      # TLV 132's addresses, or TLV 232's, from every LSP of the node, LSP
      # Number 0 first, each once. RFC 1195 section 5.2: TLV 132 "may occur
      # multiple times in an LSP, and may occur in an LSP with any LSP
      # number". RFC 5308 section 3 maps TLV 232 directly onto it.
      def topology_addresses(lsps, klass)
        lsps.flat_map { _1.tlvs.to_a.grep(klass) }.flat_map(&:addresses).map(&:to_s).uniq
      end

      # TLV 22's entries, or TLV 2's when no LSP of the node has TLV 22.
      def topology_neighbors(lsps)
        tlvs = lsps.flat_map { _1.tlvs.to_a }
        wide = tlvs.grep(Tlv::ExtendedIsReachability)
        if wide.empty?
          tlvs.grep(Tlv::IsReachability).flat_map(&:entries).map do |e|
            { id: e.neighbor_s, metric: e.metrics.default, style: "narrow" }
          end
        else
          wide.flat_map(&:entries).map { |e| { id: e.neighbor_s, metric: e.metric, style: "wide" } }
        end
      end

      # TLV 135's entries, or TLV 128's and 130's when no LSP of the node
      # has TLV 135; TLV 130's class is a subclass of 128's. An entry that
      # is no prefix, a mask that is not contiguous, is left out, as SPF
      # leaves it out.
      def topology_prefixes(lsps)
        tlvs = lsps.flat_map { _1.tlvs.to_a }
        wide = tlvs.grep(Tlv::ExtendedIpReachability)
        if wide.empty?
          tlvs.grep(Tlv::IpInternalReachability).flat_map(&:entries).filter_map do |e|
            next unless e.prefix

            { prefix: e.prefix, metric: e.metrics.default, up_down: e.up_down?, style: "narrow" }
          end
        else
          wide.flat_map(&:entries).filter_map do |e|
            next unless e.prefix

            { prefix: e.prefix, metric: e.metric, up_down: e.up_down ? true : false, style: "wide" }
          end
        end
      end

      # A node ID, the System ID and the pseudonode octet, as TLV 22 prints
      # a neighbour: "0000.0001.0101.00".
      def node_s(octets)
        hex = octets.unpack1("H*")
        (hex[0...-2].scan(/.{1,4}/) + [hex[-2, 2]]).join(".")
      end

      def dis(circuit)
        d = circuit.dis
        d == :self ? "self" : d&.system_id_s
      end

      def hold(timer)
        timer && [timer.due - @router.clock.now, 0].max.round(1)
      end

      # A circuit's name is the interface's, with -l1 or -l2 on a LAN at
      # both levels.
      def interface_of(name)
        @router.interfaces.find { |i| i.circuits.values.any? { _1.name == name } }&.name || name
      end
    end
  end
end
