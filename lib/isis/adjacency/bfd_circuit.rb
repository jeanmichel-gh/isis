# frozen_string_literal: true

module ISIS
  class Bfd
    # What a circuit does with BFD, shared by P2pCircuit and LanCircuit.
    # RFC 6213, read 2026-11-21, and RFC 5882 as routescope
    # docs/design/bfd-clients.md quotes it.
    #
    # TLV 148 (section 3): sent in every IIH on a circuit with BFD, with an
    # MTID/NLPID pair per protocol the circuit runs, MTID 0 since isis4r
    # runs no other topology; never on a circuit without. "BFD is supported
    # by the local system" only while bfdd4r answers, so with it away the
    # TLV is not sent (RFC 5882 4.1). +bfd_tlv+, true or false, overrides
    # that whatever bfdd4r does, for a test that wants a system that says
    # one thing and does another.
    #
    # The variables of section 3.1, per neighbour, over the pairs this
    # circuit runs:
    #
    # * ISIS_TOPO_NLPID_BFD_REQUIRED: the pair is in our TLV 148 and the
    #   neighbour's;
    # * ISIS_BFD_REQUIRED: per MTID the OR of those, then the AND over MTIDs
    #   (#bfd_required?);
    # * ISIS_NEIGHBOR_USEABLE: per pair the session Up, or true when the
    #   pair is not required; per MTID the AND, then the OR (#bfd_usable?).
    #
    # Section 3.2, while ISIS_BFD_REQUIRED: Init to Up waits for usable;
    # an IIH on a point to point circuit says Down in TLV 240 while not
    # usable; one on a LAN leaves the neighbour's MAC out of TLV 6. Section
    # 4: an Up adjacency that is required and not usable does not refresh
    # its hold time, so it is neither dropped at once nor kept forever.
    #
    # Two readings, where the sections pull apart:
    #
    # * The Down in TLV 240 and the MAC left out of TLV 6 apply while the
    #   adjacency is not Up (#bfd_hidden?). Applied to an Up one, they take
    #   it down at the peer at once, by RFC 5303 3.2's table (Up, received
    #   Down: Initialize) or RFC 1142 8.4.1.5, which is what section 4's
    #   hold time is there to avoid. An Up adjacency still goes Down for BFD
    #   on a failure, below.
    # * A session in AdminDown counts as usable. RFC 5882 4.1: "If either
    #   end is AdminDown, the adjacency MUST be allowed". Section 4's own
    #   case for it, holding the hold time, then does not arise.
    #
    # A neighbour that sends no TLV 148 is not required, and its adjacency
    # is not blocked (RFC 5882 4.1). It may still run BFD: FRR 10.5.1's
    # isisd has no TLV 148 and asks for a session once the adjacency is Up
    # (measured 2026-11-21: no TLV 148 code in its binary; FRR 10.2.1's
    # and 10.7.1's hellos carry none in routescope/labs/isis4r-bfd). So on a circuit
    # with BFD and with bfdd4r answering, an Up adjacency has a session too,
    # for each protocol both run, and RFC 5882 10.1.2 applies: "IS-IS ...
    # simulates an adjacency failure".
    #
    # Either way an adjacency goes Down for BFD only on a failure, an Up
    # session gone Down; never on AdminDown, local or remote (RFC 5882
    # 4.2), which BFD::Client tells as :admin_down.
    module Circuit
      NLPID_IPV4 = ISIS::NLPID_IPV4
      NLPID_IPV6 = ISIS::NLPID_IPV6
      NLPIDS = { ipv4: NLPID_IPV4, ipv6: NLPID_IPV6 }.freeze
      MTID = 0
      # The session states a pair is usable in: Up, and AdminDown (RFC 5882
      # 4.1).
      USABLE = %i[up admin_down].freeze

      # The BFD mechanism, nil without BFD on this circuit.
      attr_reader :bfd

      # true or false overrides what TLV 148 says; nil follows bfdd4r.
      attr_accessor :bfd_tlv

      # Whether BFD is configured on this circuit.
      def bfd? = !@bfd.nil?

      # The MTID/NLPID pairs this circuit runs.
      def bfd_local_pairs
        @protocols.filter_map { |p| NLPIDS[p] }.map { |n| [MTID, n] }
      end

      # The pairs this circuit's IIHs carry in TLV 148 now.
      def bfd_pairs_sent
        return [] if @bfd_tlv == false
        return bfd_local_pairs if @bfd_tlv == true

        bfd? && @bfd.running? ? bfd_local_pairs : []
      end

      # ISIS_BFD_REQUIRED for +n+.
      def bfd_required?(n)
        required = bfd_required_pairs(n)
        return false if required.empty?

        bfd_local_pairs.group_by(&:first).all? { |_, pairs| pairs.any? { |p| required.include?(p) } }
      end

      # ISIS_NEIGHBOR_USEABLE for +n+.
      def bfd_usable?(n)
        required = bfd_required_pairs(n)
        bfd_local_pairs.group_by(&:first).any? do |_, pairs|
          pairs.all? { |p| !required.include?(p) || bfd_session_up?(n, p) }
        end
      end

      # Required and not usable: what holds an adjacency from Up and stops
      # its hold time being refreshed.
      def bfd_blocked?(n) = bfd_required?(n) && !bfd_usable?(n)

      # Blocked and not Up: what the hellos hide.
      def bfd_hidden?(n) = n.state != :up && bfd_blocked?(n)

      # What the adjacencies view says: nil with no session for +n+, else
      # "up" with every session Up, "waiting" until one has been, "down"
      # after.
      def bfd_view(n)
        sessions = Array(n.bfd_sessions)
        return nil if sessions.empty?
        return "up" if sessions.all? { |(peer, _)| bfd_state(peer) == :up }

        n.bfd_seen_up ? "down" : "waiting"
      end

      # A session of this circuit changed (Bfd#poll).
      def bfd_changed(event)
        bfd_neighbors.each do |n|
          next unless Array(n.bfd_sessions).any? { |(peer, _)| peer == event.peer }

          if event.failure? && n.state == :up
            # RFC 5882 10.1.2, and for a required neighbour RFC 6213 3.2:
            # "When the IS-IS adjacency is "UP" and "ISIS_NEIGHBOR_USEABLE"
            # becomes "FALSE", the IS-IS adjacency MUST transition to "DOWN"."
            bfd_drop(n, "BFD session to #{event.peer} went Down#{" (#{event.diag})" if event.diag}")
            next
          end
          n.bfd_seen_up = true if event.up?
          bfd_usable_changed(n)
        end
      end

      # bfdd4r came or went: TLV 148 changes, and with it what is required.
      def bfd_running_changed
        bfd_neighbors.each { |n| bfd_sync(n) }
        bfd_hello_changed
        bfd_neighbors.each { |n| bfd_usable_changed(n) }
      end

      private

      def setup_bfd(bfd, interface, tlv)
        @bfd = bfd
        @bfd_interface = interface || @name
        @bfd_tlv = tlv
        @bfd&.attach(self)
      end

      def bfd_tlvs
        pairs = bfd_pairs_sent
        pairs.empty? ? [] : [Tlv::BfdEnabled.new(pairs)]
      end

      # The pairs a hello's TLV 148s carry, nil with none.
      def bfd_pairs_of(hello)
        tlvs = hello.tlvs.select { |t| t.is_a?(Tlv::BfdEnabled) }
        tlvs.empty? ? nil : tlvs.flat_map(&:pairs).uniq
      end

      def bfd_required_pairs(n)
        theirs = n.bfd_pairs or return []
        bfd_pairs_sent & theirs
      end

      # The session for +pair+ with +n+: [peer, local], nil when either end
      # has no address of that protocol on the link.
      def bfd_session(n, pair)
        peer, local =
          case pair.last
          when NLPID_IPV4 then [Array(n.ip_addresses).first, Array(@ip_addresses).first]
          when NLPID_IPV6 then [Array(n.ipv6_addresses).first, Array(@ipv6_addresses).first]
          end
        peer && local ? [peer.to_s, local.to_s] : nil
      end

      def bfd_session_up?(n, pair)
        s = bfd_session(n, pair)
        s && Array(n.bfd_sessions).include?(s) && USABLE.include?(bfd_state(s.first))
      end

      def bfd_state(peer) = @bfd&.state(interface: @bfd_interface, peer: peer)

      # The sessions +n+ needs: the required pairs' when it is required,
      # else, with bfdd4r answering and the adjacency Up, one per protocol
      # both run (RFC 5882).
      def bfd_wanted(n)
        return [] unless bfd?

        pairs =
          if bfd_required?(n) then bfd_required_pairs(n)
          elsif n.state == :up && @bfd.running? then bfd_local_pairs
          else []
          end
        pairs.filter_map { |p| bfd_session(n, p) }.uniq
      end

      # Ask for what +n+ needs and let go of the rest.
      def bfd_sync(n)
        return unless bfd?

        wanted = bfd_wanted(n)
        had = Array(n.bfd_sessions)
        (had - wanted).each { |(peer, _)| @bfd.drop(self, interface: @bfd_interface, peer: peer) }
        (wanted - had).each { |(peer, local)| @bfd.want(self, interface: @bfd_interface, peer: peer, local: local) }
        n.bfd_seen_up = false if wanted.empty?
        n.bfd_sessions = wanted
      end

      # +n+ is going: let go of its sessions.
      def bfd_release(n)
        return unless bfd?

        Array(n.bfd_sessions).each { |(peer, _)| @bfd.drop(self, interface: @bfd_interface, peer: peer) }
        n.bfd_sessions = []
      end

      # Whether a received hello may refresh +n+'s hold time: not while it
      # is Up, required and not usable (RFC 6213 4: "not update the
      # adjacency hold time when receiving such an IIH from a neighbor with
      # whom we have an "UP" adjacency until "ISIS_NEIGHBOR_USEABLE"
      # becomes "TRUE"").
      def bfd_holds_time?(n)
        return true unless n.state == :up && bfd_blocked?(n)

        @log.debug("hold time of #{n.system_id_s} not refreshed: BFD required and not usable (RFC 6213 4)",
                   circuit: @name)
        false
      end
    end
  end
end
