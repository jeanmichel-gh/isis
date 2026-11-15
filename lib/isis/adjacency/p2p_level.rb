# frozen_string_literal: true

module ISIS
  class P2pCircuit
    # One level of a point to point circuit: its database, its originator,
    # its key, and the update process for that level (RFC 1142 clause
    # 7.3.15 for a non-broadcast circuit). A circuit at both levels has two,
    # sharing the one adjacency, since a point to point hello serves both
    # levels at once (clause 9.7).
    #
    # This is what the database and the originator see as "the circuit": it
    # answers is_neighbor and flood for its level, so a Level 1 originator
    # and a Level 2 one each hear only about their own level.
    #
    # Each step is a method a test can replace on one object, as on the
    # circuit: receive_lsp, receive_snp, send_psnp, send_csnp and
    # send_srm_lsps.
    class Level
      include UpdateProcess

      attr_reader :circuit, :level, :database, :originator
      attr_accessor :area_key, :decision

      def initialize(circuit:, level:, database:, originator: nil, area_key: nil, partial_snp_interval:,
                     lsp_transmission_interval:)
        @circuit = circuit
        @level = level
        @name = circuit.name
        @system_id = circuit.system_id
        @log = circuit.log
        @scheduler = circuit.scheduler
        @database = database
        @originator = originator
        @area_key = area_key
        @partial_snp_interval = partial_snp_interval
        @lsp_transmission_interval = lsp_transmission_interval
        @psnp_timer = @srm_timer = nil
        @database.attach(self)
        @originator&.attach(self)
      end

      # The adjacency is Up and serves this level.
      def up?
        @circuit.up?(@level)
      end

      def broadcast?
        false
      end

      def generators
        [@originator].compact + @database.generators
      end

      def transmit(pdu)
        @circuit.transmit(pdu)
      end

      # What this level puts in its system's IS reachability: the
      # neighbour's System ID with "an appended zero octet (indicating
      # non-pseudonode)" and the circuit's metric, from an adjacency Up at
      # this level (RFC 1142 7.3.7, 7.3.9). Nil without.
      #
      # The third element is the link's IPv4 addresses for TLV 22's sub-TLVs:
      # this end's first TLV 132 address, for sub-TLV 6, and the
      # neighbour's, from its hellos, for sub-TLV 8. RFC 5305 sections 3.2
      # and 3.3 make both optional without traffic engineering ("MAY add or
      # omit"); isis4r sends them so a reader of the LSP can tell the link's
      # two ends apart, as BGP-LS link descriptors need.
      def is_neighbor
        return unless up?

        addresses = { interface: @circuit.ip_addresses.first, neighbor: @circuit.neighbor.ip_addresses&.first }
        [(@circuit.neighbor.system_id + "\x00".b).b, @circuit.metric, addresses.compact]
      end

      # The first hop for the Decision Process: the neighbour, at the
      # circuit's metric, with the adjacency Up at this level. The circuit ID
      # 7.2.7 ranks by is the ptPtCircuitID, the Local Circuit ID.
      def spf_adjacencies
        return [] unless up?

        n = @circuit.neighbor
        adj = Spf::Adjacency.new(circuit: @name, neighbor: n.system_id.b, circuit_id: @circuit.local_circuit_id,
                                 address: n.ip_addresses&.first, address6: n.ipv6_addresses&.first)
        [[(n.system_id + "\x00".b).b, @circuit.metric, adj]]
      end

      # A point to point circuit has no pseudonode.
      def spf_broadcast
        nil
      end

      # The originator generated +entry+: set SRM for it here, with the
      # adjacency up at this level (RFC 1142 7.3.5, 7.3.6).
      def flood(entry)
        set_srm(entry) if up?
      end

      # The adjacency came to serve this level. Clause 7.3.15.3 b: CSNPs
      # "are only transmitted on point to point circuits at
      # initialisation", and the PSNP timer starts.
      def adjacency_up(neighbor)
        @originator&.changed("adjacency with #{neighbor} on #{@name} up at Level #{@level} (RFC 1142 7.3.6)")
        @decision&.changed("adjacency with #{neighbor} on #{@name} up")
        send_csnp
        start_psnp_timer unless @psnp_timer
      end

      # The neighbour's hellos gave it other interface addresses, which are
      # the next hops' addresses, and the one in sub-TLV 8 of its TLV 22
      # entry.
      def addresses_changed(neighbor)
        @originator&.changed("addresses of #{neighbor} on #{@name} changed (RFC 1142 7.3.6)")
        @decision&.changed("addresses of #{neighbor} on #{@name} changed")
      end

      # The adjacency stopped serving this level, so nothing is owed on it.
      def adjacency_down
        @originator&.changed("adjacency on #{@name} down at Level #{@level} (RFC 1142 7.3.6)")
        @decision&.changed("adjacency on #{@name} down")
        stop
      end

      def stop
        @psnp_timer&.cancel
        @psnp_timer = nil
        clear_update_state
      end

      private

      # The PSNP timer, clause 7.3.15.4 b: every partialSNPInterval. The
      # jitter clause 10.1 asks for is not applied yet.
      def start_psnp_timer
        @psnp_timer = @scheduler.after(@partial_snp_interval) do
          send_psnp
          start_psnp_timer
        end
      end
    end
  end
end
