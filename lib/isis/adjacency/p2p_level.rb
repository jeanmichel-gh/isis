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
      attr_accessor :area_key

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
        [@originator].compact
      end

      def transmit(pdu)
        @circuit.transmit(pdu)
      end

      # What this level puts in its system's IS reachability: the
      # neighbour's System ID with "an appended zero octet (indicating
      # non-pseudonode)" and the circuit's metric, from an adjacency Up at
      # this level (RFC 1142 7.3.7, 7.3.9). Nil without.
      def is_neighbor
        [(@circuit.neighbor.system_id + "\x00".b).b, @circuit.metric] if up?
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
        send_csnp
        start_psnp_timer unless @psnp_timer
      end

      # The adjacency stopped serving this level, so nothing is owed on it.
      def adjacency_down
        @originator&.changed("adjacency on #{@name} down at Level #{@level} (RFC 1142 7.3.6)")
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
