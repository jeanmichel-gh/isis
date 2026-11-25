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
          overload: r.originators.values.first&.overload || false,
          lsp_generation: lsp_generation(r.originators.values.first)
        }
      end

      # How a change to this system's own LSP is timed: fixed, RFC 1142's
      # hold, or the backoff (docs/design/lsp-generation.md).
      def lsp_generation(originator)
        t = originator&.generation_timer
        t.respond_to?(:to_h) ? t.to_h : nil
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
              bfd = c.bfd_view(n)
              row[:bfd] = bfd if bfd
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
          labels = @router.decisions[l].labels
          backups = @router.decisions[l].backups
          names = backups ? hostnames : {}
          @router.decisions[l].routes.values.map do |r|
            row = { level: l, prefix: r.prefix.to_s, metric: r.metric, external: r.external ? true : false,
                    up_down: r.up_down ? true : false,
                    next_hops: r.adjacencies.map do |a|
                      hop = { address: a.next_hop(r.family), interface: interface_of(a.circuit) }
                      label = labels&.out_label(r.prefix, a)
                      label ? hop.merge(label: label) : hop
                    end }
            row[:sid] = r.sid.index if r.sid&.index
            backup = backups&.routes&.[](r.prefix)
            row.merge!(backup_fields(backup, r.family, names)) if backup
            row
          end
        end
      end

      # The label table each level's last SPF run gave (Spf::Labels), one
      # row per in-label: its kind, what it is for, what is done with it,
      # and each next hop with the label it leaves with, 3 being implicit
      # null, a pop; and the algorithm it is for, 0 or a flex-algo's.
      # Empty without segment routing.
      def labels(level: nil)
        names = hostnames
        @router.levels.select { level.nil? || _1 == Integer(level) }.flat_map do |l|
          table = @router.decisions[l].labels or next []
          entries = table.entries.values + @router.decisions[l].flex_labels.values.flat_map { _1.entries.values }
          entries.sort_by(&:label).map do |e|
            fec = e.kind == :adj_sid ? names.fetch(SystemId.from_bytes(e.fec).to_s, SystemId.from_bytes(e.fec).to_s) : e.fec
            row = { level: l, label: e.label, kind: e.kind.to_s, fec: fec, op: e.op.to_s,
                    next_hops: e.hops.map do |a, out|
                      { address: a.next_hop(e.kind == :adj_sid || !e.fec.include?(":") ? :ipv4 : :ipv6),
                        interface: interface_of(a.circuit), label: out }
                    end,
                    algorithm: e.algorithm || 0 }
            next row unless row[:algorithm].zero?

            backup = @router.decisions[l].backups&.label(e.label)
            row.merge!(backup_fields(backup, e.fec.include?(":") ? :ipv6 : :ipv4, names)) if backup
            row
          end
        end
      end

      # TI-LFA (docs/ti-lfa.md): per level, each protected interface with
      # its neighbor and what it protects, and how long the last
      # computation took. { enabled: false } when no interface has ti_lfa.
      def ti_lfa
        names = @router.ti_lfa_interfaces
        return { enabled: false } if names.empty?

        hosts = hostnames
        { enabled: true, interfaces: names,
          levels: @router.levels.to_h do |l|
            b = @router.decisions[l].backups
            [l, { trees: b&.trees || 0, milliseconds: ((b&.seconds || 0) * 1000).round(1),
                  protecting: (b&.summaries || []).map do |s|
                    id = SystemId.from_bytes(s.neighbor).to_s
                    { interface: interface_of(s.interface), neighbor: hosts.fetch(id, id), mode: s.mode.to_s,
                      protected: s.protected, ecmp: s.ecmp, fallback: s.fallback,
                      unprotected: s.unprotected.transform_keys(&:to_s) }
                  end }]
          end }
      end

      # Flex-algo (docs/design/flex-algo.md, "API and CLI"): the configured
      # algorithms, then per level each one's winning FAD and its origin,
      # whether isis4r can run it, whether this system takes part and why
      # not, and every FAD offered, the winner first; the routes of each
      # algorithm it takes part in, for its label table; and the findings
      # on the FADs read. { enabled: false } without flex_algo.
      def flex_algo
        return { enabled: false } if @router.flex_config.empty?

        names = hostnames
        { enabled: true, configured: @router.flex_config.entries.map(&:to_hash),
          levels: @router.flex_algos.to_h do |l, f|
            h = f.to_hash.except(:level)
            routes = @router.decisions[l]&.flex_routes || {}
            h[:algorithms] = h[:algorithms].map do |a|
              a = a.merge(candidates: a[:candidates].map { |c| c.merge(hostname: names[c[:origin]]).compact })
              a = a.merge(winner: a[:winner].merge(hostname: names[a[:winner][:origin]]).compact) if a[:winner]
              a.merge(routes: (routes[a[:algorithm]] || {}).values.sort_by(&:prefix).map { flex_route(_1) })
            end
            [l, h]
          end }
      end

      # One route of a flex-algo: its prefix, metric and next hops.
      def flex_route(route)
        { prefix: route.prefix, metric: route.metric,
          next_hops: route.adjacencies.map do |a|
            { address: a.next_hop(route.family), interface: interface_of(a.circuit) }
          end }
      end

      # This system's segment routing and what it learned: its blocks and
      # Adj-SIDs, then per level each reachable system's SRGB and
      # algorithms, the problems the last run met, its findings by name
      # (Validation) and the receive policy. { enabled: false } without it.
      def segment_routing
        sr = @router.segment_routing or return { enabled: false }
        names = hostnames
        span = ->(first, size) { "#{first}-#{first + size - 1}" }
        { enabled: true, router_id: sr.router_id.to_s, srgb: sr.srgb.map { |f, s| span.(f, s) },
          srlb: span.(*sr.srlb),
          adj_sids: sr.adj_labels.map do |(circuit, neighbor, family), label|
            id = SystemId.from_bytes(neighbor).to_s
            { interface: interface_of(circuit), neighbor: names.fetch(id, id), family: family.to_s, label: label }
          end,
          levels: @router.levels.to_h do |l|
            table = @router.decisions[l].labels
            own = sr.srgb.map { |f, s| [f, f + s - 1] }
            nodes = (table&.nodes || {}).map do |node, n|
              id = SystemId.from_bytes(node.byteslice(0, 6)).to_s
              row = { system_id: id, hostname: names[id], srgb: n.srgb&.map { |a, b| "#{a}-#{b}" },
                      algorithms: n.algorithms }
              row[:router_id] = n.router_id if n.router_id
              row[:srlb] = n.srlb.map { |a, b| "#{a}-#{b}" } if n.srlb
              # The Node-SID, and the label this system takes it in.
              row.merge!(sid: n.sid, prefix: n.prefix, label: Spf::Labels.label_at(own, n.sid)) if n.sid
              row
            end
            [l, { nodes: nodes, problems: table&.problems || [], findings: (table&.findings || []).map(&:to_hash),
                  receive_policy: (table&.policy || sr.receive_policy).to_s }]
          end }
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
      # Each link gains its attributes for flex-algo, and the node the
      # findings on them, when it has any (Spf::LinkAttributes).
      def topology_node(node, lsps, names, reachable)
        id = node_s(node)
        zero = lsps.first
        attributes = Spf::LinkAttributes.new(lsps, policy: receive_policy, subject: id)
        h = { id: id, hostname: names[id[0...-3]],
              areas: zero.tlvs.grep(Tlv::AreaAddresses).flat_map(&:areas).map(&:to_s),
              overload: zero.overload?, attached: !zero.attached.empty?, reachable: reachable,
              neighbors: topology_neighbors(lsps, attributes), prefixes: topology_prefixes(lsps),
              interface_addresses: topology_addresses(lsps, Tlv::IpInterfaceAddresses),
              ipv6_interface_addresses: topology_addresses(lsps, Tlv::Ipv6InterfaceAddresses) }
        h[:link_findings] = attributes.findings.map(&:to_hash) unless attributes.findings.empty?
        sr = topology_sr(lsps)
        sr ? h.merge(sr: sr) : h
      end

      # What a finding on received data does: segment routing's
      # receive_policy, rfc without it.
      def receive_policy
        @router.segment_routing&.receive_policy || :rfc
      end

      # The node's SR, from the sub-TLVs of its Router Capability TLV 242
      # (RFC 8667 section 3): SR-Capabilities (2) as the SRGB with its
      # flags, SR Local Block (22) and SR-Algorithm (19). Each from the
      # first fragment that carries it, LSP Number 0 first. nil when the
      # node advertises none, so a topology without SR reads as before.
      # routescope docs/design/bgp-ls-sr.md: what a BGP-LS Producer puts in
      # RFC 9085's TLVs 1034, 1036 and 1035.
      def topology_sr(lsps)
        subs = lsps.flat_map { _1.tlvs.to_a.grep(Tlv::RouterCapability) }.flat_map { _1.subtlvs.to_a }
        cap = subs.grep(SubTlv::SrCapabilities).first
        srlb = subs.grep(SubTlv::SrLocalBlock).first
        algo = subs.grep(SubTlv::SrAlgorithm).first
        return nil unless cap || srlb || algo

        h = {}
        h[:srgb] = blocks(cap) if cap
        h[:flags] = Array(cap.to_hash[:flags]) if cap
        h[:srlb] = blocks(srlb) if srlb
        h[:algorithms] = algo.algorithms.to_a if algo
        h
      end

      # A label block's ranges as [{ start:, size: }], in the order sent.
      def blocks(subtlv)
        subtlv.ranges.map { |lo, hi| { start: lo, size: hi - lo + 1 } }
      end

      # TLV 132's addresses, or TLV 232's, from every LSP of the node, LSP
      # Number 0 first, each once. RFC 1195 section 5.2: TLV 132 "may occur
      # multiple times in an LSP, and may occur in an LSP with any LSP
      # number". RFC 5308 section 3 maps TLV 232 directly onto it.
      def topology_addresses(lsps, klass)
        lsps.flat_map { _1.tlvs.to_a.grep(klass) }.flat_map(&:addresses).map(&:to_s).uniq
      end

      # TLV 22's entries, or TLV 2's when no LSP of the node has TLV 22.
      def topology_neighbors(lsps, attributes)
        tlvs = lsps.flat_map { _1.tlvs.to_a }
        wide = tlvs.grep(Tlv::ExtendedIsReachability)
        if wide.empty?
          tlvs.grep(Tlv::IsReachability).flat_map(&:entries).map do |e|
            { id: e.neighbor_s, metric: e.metrics.default, style: "narrow" }
          end
        else
          wide.flat_map(&:entries).map { |e| wide_neighbor(e).merge(attributes.for(e)&.to_hash || {}) }
        end
      end

      # A TLV 22 entry, with the first of its sub-TLVs 6 and 8 when it has
      # them (RFC 5305 sections 3.2 and 3.3). Its link attributes for
      # flex-algo are merged in by the caller: affinity (groups), te_metric,
      # delay ({ min:, max:, average: } in µs, those given), srlg, and
      # asla_legacy when the L flag sent them in the legacy sub-TLVs.
      def wide_neighbor(entry)
        h = { id: entry.neighbor_s, metric: entry.metric, style: "wide" }
        { interface_address: SubTlv::Ipv4InterfaceAddress,
          neighbor_address: SubTlv::Ipv4NeighborAddress }.each do |key, klass|
          address = entry.subtlvs.grep(klass).filter_map(&:address).first
          h[key] = address.to_s if address
        end
        # Adj-SID (31) and LAN-Adj-SID (32), RFC 8667 sections 2.2.1 and
        # 2.2.2, each as its sub-TLV gives it; only when the entry has one.
        lan = Array(entry.subtlvs).grep(SubTlv::LanAdjSid)
        adj = Array(entry.subtlvs).grep(SubTlv::AdjSid) - lan
        h[:adj_sids] = adj.map(&:to_hash) unless adj.empty?
        h[:lan_adj_sids] = lan.map(&:to_hash) unless lan.empty?
        h
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

            h = { prefix: e.prefix, metric: e.metric, up_down: e.up_down ? true : false, style: "wide" }
            # Prefix-SID (3), RFC 8667 section 2.1: the first, when it has one.
            sid = Array(e.subtlvs).grep(SubTlv::PrefixSid).first
            sid ? h.merge(prefix_sid: sid.to_hash) : h
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
      # A route's or label's backup as fields: backup, its next hop and
      # labels, the repair's path from this system to the destination, P
      # and Q, each by hostname (a pseudonode as its DIS's, with its octet);
      # or unprotected and why. +names+ is #hostnames, read once.
      def backup_fields(backup, family, names = hostnames)
        case backup
        when Spf::Backups::Backup
          a = backup.adjacency
          rep = backup.repair
          name = ->(node) { node_name(node, names) }
          b = { address: a.next_hop(family), interface: interface_of(a.circuit), labels: backup.labels,
                case: rep.case.to_s, protects: backup.protects.to_s,
                path: rep.path.map(&name), p: name.(rep.p), q: name.(rep.q) }
          { backup: backup.fallback ? b.merge(fallback: true) : b }
        when Spf::Backups::Ecmp then { backup: { ecmp: true } }
        else { unprotected: backup.reason.to_s }
        end
      end

      def node_name(node, names)
        id = SystemId.from_bytes(node.byteslice(0, 6)).to_s
        base = names.fetch(id, id)
        node.getbyte(-1).zero? ? base : format("%<base>s.%<octet>02x", base: base, octet: node.getbyte(-1))
      end

      def interface_of(name)
        @router.interfaces.find { |i| i.circuits.values.any? { _1.name == name } }&.name || name
      end
    end
  end
end
