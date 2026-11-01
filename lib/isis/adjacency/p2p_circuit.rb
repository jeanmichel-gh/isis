# frozen_string_literal: true

module ISIS
  # A point to point circuit: one link, at most one neighbour, the RFC 5303
  # three-way handshake on top of RFC 1142 clause 8.2. Level 1 only, which
  # is phase 1's scope.
  #
  # Everything that varies is injected: the transport moves frames, the
  # scheduler runs the hello and holding timers on its clock, and the log
  # takes every line, event and PDU. Nothing here reads the system clock.
  #
  # Each step is a method a test can replace on one object: build_hello
  # makes the hello, transmit sends a PDU, receive_hello decides what a
  # received hello changes, and receive_lsp and receive_snp what a received
  # LSP or sequence numbers PDU does to the database and its flags. The
  # defaults follow the clauses quoted beside them, and every refusal is
  # logged with its reason.
  #
  # The update process here is RFC 1142 clause 7.3.15 for one non-broadcast
  # circuit: the SRM and SSN flags on the database's entries, a PSNP every
  # partialSNPInterval carrying the entries with SSN set, a CSNP when the
  # adjacency comes up, and the LSPs with SRM set sent every
  # minimumLSPTransmissionInterval until the neighbour acknowledges them.
  # With an Originator, the circuit's adjacency goes into this system's
  # LSP, an Up or Down asks it for a new one (clause 7.3.6), and a received
  # copy of it is handled by clause 7.3.15.1 d. Not here yet: purges
  # (clause 7.3.16.4), so LSP confusion (7.3.16.2) and a stale LSP of this
  # system's (7.3.15.1 c) are refused.
  #
  # Authentication, RFC 5304 HMAC-MD5: hello_key for the hellos, the link
  # level password, and area_key for Level 1 LSPs and SNPs. With a key,
  # what this circuit sends carries TLV 10 first, and what it receives is
  # refused unless its digest checks out under that key. Without one,
  # nothing is added and nothing is checked.
  class P2pCircuit
    # AllISs. RFC 5309 section 4.1 recommends it for point to point hellos
    # on a LAN; second hand, from FRR's isis_pfpacket.c, which cites that
    # section. RFC 5309 itself is not read here.
    ALL_ISS = "09:00:2b:00:00:05"

    Neighbor = Struct.new(:system_id, :snpa, :state, :extended_circuit_id, :holding_time, :areas, :expiry) do
      def system_id_s
        system_id.unpack1("H*").scan(/.{1,4}/).join(".")
      end
    end

    # RFC 1142 clause 7.3.21 and annex defaults: "partialSNPInterval-Default
    # INTEGER ::= 2" and "minimumLSPTransmissionInterval-Default INTEGER ::=
    # 5", in seconds.
    PARTIAL_SNP_INTERVAL = 2
    MINIMUM_LSP_TRANSMISSION_INTERVAL = 5

    attr_reader :name, :system_id, :neighbor, :log, :scheduler, :transport, :database, :originator
    attr_accessor :areas, :hello_interval, :hello_multiplier, :metric, :hello_key, :area_key

    def initialize(transport:, scheduler:, log:, name:, system_id:, snpa:, areas: ["49.0001"],
                   extended_circuit_id: 1, local_circuit_id: 1, hello_interval: 3, hello_multiplier: 10,
                   ip_addresses: [], protocols: [:ipv4], database: nil, originator: nil, metric: 10,
                   hello_key: nil, area_key: nil,
                   partial_snp_interval: PARTIAL_SNP_INTERVAL,
                   lsp_transmission_interval: MINIMUM_LSP_TRANSMISSION_INTERVAL)
      @transport = transport
      @scheduler = scheduler
      @log = log
      @name = name
      @system_id = Pdu.dotted_octets(system_id)
      @snpa = snpa.is_a?(Datalink::MAC) ? snpa : Datalink::MAC.new(snpa)
      @areas = areas
      @extended_circuit_id = extended_circuit_id
      @local_circuit_id = local_circuit_id
      @hello_interval = hello_interval
      @hello_multiplier = hello_multiplier
      @ip_addresses = ip_addresses
      @protocols = protocols
      @neighbor = nil
      @hello_timer = nil
      @database = database || Database.new(level: 1, clock: scheduler.clock)
      @partial_snp_interval = partial_snp_interval
      @lsp_transmission_interval = lsp_transmission_interval
      @psnp_timer = nil
      @srm_timer = nil
      @metric = metric
      @hello_key = hello_key
      @area_key = area_key
      @originator = originator
      @originator&.attach(self)
    end

    # Send a hello now and every hello_interval after.
    def start
      send_hello
      @hello_timer = @scheduler.after(@hello_interval) { start }
      self
    end

    def stop
      @hello_timer&.cancel
      @hello_timer = nil
      [@psnp_timer, @srm_timer].each { |t| t&.cancel }
      @psnp_timer = @srm_timer = nil
      self
    end

    # This system's three-way state for the circuit: :down with no
    # neighbour. RFC 5303 section 3.2 reports Down when there is none.
    def three_way_state
      @neighbor ? @neighbor.state : :down
    end

    def up?
      three_way_state == :up
    end

    # What this circuit puts in its system's TLV 22: the neighbour's System
    # ID with "an appended zero octet (indicating non-pseudonode)" and the
    # circuit's metric, from an adjacency Up (RFC 1142 7.3.7). Nil without.
    def is_neighbor
      [(@neighbor.system_id + "\x00".b).b, @metric] if up?
    end

    # The originator generated +entry+: set SRM for it here, on a circuit
    # with an adjacency up (RFC 1142 7.3.5, 7.3.6).
    def flood(entry)
      set_srm(entry) if up?
    end

    # The hello this circuit sends now. RFC 1142 clause 8.2.3 and RFC 5303
    # section 3.2: the Extended Local Circuit ID always, the neighbour's
    # System ID and Extended Local Circuit ID once they are known.
    def build_hello
      tlvs = [Tlv::AreaAddresses.new(@areas), Tlv::ProtocolsSupported.new(@protocols)]
      tlvs << Tlv::IpInterfaceAddresses.new(@ip_addresses) unless @ip_addresses.empty?
      three_way = { extended_circuit_id: @extended_circuit_id }
      if @neighbor
        three_way[:neighbor_system_id] = Octets.new(@neighbor.system_id)
        three_way[:neighbor_extended_circuit_id] = @neighbor.extended_circuit_id
      end
      tlvs << Tlv::ThreeWayAdjacency.new(three_way_state, **three_way.compact)
      hello = Pdu::P2pHello.new(circuit_type: :l1, source_id: Octets.new(@system_id), holding_time: holding_time,
                                local_circuit_id: @local_circuit_id, tlvs: keyed(tlvs, @hello_key))
      hello.key = @hello_key
      hello
    end

    def send_hello
      transmit(build_hello)
    end

    # Hand one PDU to the transport, framed for AllISs.
    def transmit(pdu, dst: ALL_ISS)
      payload = Link.llc.wrap(pdu.encode)
      @transport.send(Datalink::Frame.ieee_802_3(dst: Datalink::MAC.new(dst), src: @snpa, payload: payload))
      @log.trace(:sent, @name, pdu, dst)
      pdu
    end

    # Read every frame the transport has and process it.
    def poll(timeout: nil)
      count = 0
      while (frame = @transport.receive(timeout: timeout))
        count += 1
        receive_frame(frame)
      end
      count
    end

    def receive_frame(frame)
      sdu = frame.sdu
      return @log.debug("not IS-IS LLC, ignored", circuit: @name) unless Link.isis_llc?(sdu)

      _llc, octets = Datalink::LLC.parse(sdu)
      pdu = Pdu.factory(Octets.new(octets))
      @log.trace(:received, @name, pdu, frame.src.to_s)
      case pdu
      when Pdu::P2pHello then receive_hello(pdu, frame.src)
      when Pdu::Lsp, Pdu::Csnp, Pdu::Psnp then receive_update(pdu)
      else @log.debug("#{pdu_name(pdu)} ignored on a point to point circuit", circuit: @name)
      end
    end

    # What a received LSP does, RFC 1142 clause 7.3.15.1. Returns what
    # happened, or the reason it was refused, as a Symbol.
    def receive_lsp(lsp)
      id = lsp.lsp_id_s
      # Clause 7.3.15.1 a 2: an ID Length that is not ours.
      if lsp.lsp_id.bytesize != @system_id.bytesize + 2
        return refuse_pdu(:id_length, "LSP #{id}: ID Length #{lsp.lsp_id.bytesize - 2} octets, ours is " \
                                      "#{@system_id.bytesize} (RFC 1142 7.3.15.1 a 2)")
      end
      # Clause 7.3.14 e asks for a corrupted LSP to be treated as expired,
      # which is a purge, and purging is not here yet.
      unless lsp.checksum_ok?
        return refuse_pdu(:checksum, "LSP #{id}: checksum #{format('0x%04x', lsp.checksum)} is wrong; " \
                                     "RFC 1142 7.3.14 e treats it as expired, and purging is not implemented")
      end
      # Clause 7.3.15.1 a 3, and RFC 5304 section 2.
      if (why = authentication_refusal(lsp, @area_key, "RFC 1142 7.3.15.1 a 3"))
        return refuse_pdu(:authentication, "LSP #{id}: #{why}")
      end
      # Clause 7.3.15.1 b sends a zero Remaining Lifetime to 7.3.16.4.
      return refuse_pdu(:purge, "LSP #{id}: a purge (lifetime 0); RFC 1142 7.3.16.4 is not implemented") if lsp.lifetime.zero?
      # Clause 7.3.15.1 c and d: an LSP with this system's ID.
      return receive_own_lsp(lsp) if lsp.lsp_id.byteslice(0, @system_id.bytesize) == @system_id

      entry = @database.entry(lsp.lsp_id)
      result = entry.placeholder? ? :new : Database.compare(entry, sequence: lsp.sequence, lifetime: lsp.lifetime,
                                                                   checksum: lsp.checksum)
      case result
      when :new, :newer
        held = entry.sequence
        entry.store(lsp)
        # Clause 7.3.15.1 e 1: store, clear SRM for C, and on a
        # non-broadcast circuit set SSN for C. There are no other circuits.
        entry.srm.delete(@name)
        set_ssn(entry)
        @log.info("LSP #{id} sequence #{seq(lsp.sequence)} stored: " \
                  "#{result == :new ? 'not held before' : "newer than #{seq(held)}"} (RFC 1142 7.3.15.1 e 1)",
                  circuit: @name, kind: :database, lsp_id: id, sequence: lsp.sequence, result: result)
      when :equal
        # Clause 7.3.15.1 e 2: clear SRM, set SSN.
        entry.srm.delete(@name)
        set_ssn(entry)
        @log.debug("LSP #{id} sequence #{seq(lsp.sequence)} equals the held one, acknowledged", circuit: @name)
      when :older
        # Clause 7.3.15.1 e 3: set SRM, clear SSN, so ours goes back.
        entry.ssn.delete(@name)
        set_srm(entry)
        @log.info("LSP #{id} sequence #{seq(lsp.sequence)} is older than the held #{seq(entry.sequence)}, " \
                  "sending ours (RFC 1142 7.3.15.1 e 3)", circuit: @name, kind: :database, lsp_id: id, result: result)
      when :confused
        return refuse_pdu(:confused, "LSP #{id}: same sequence #{seq(lsp.sequence)}, different checksum; " \
                                     "RFC 1142 7.3.16.2 treats it as expired, and purging is not implemented")
      end
      result
    end

    # What a received CSNP or PSNP does, RFC 1142 clause 7.3.15.2.
    def receive_snp(snp)
      if snp.source_id.bytesize != @system_id.bytesize + 1
        return refuse_pdu(:id_length, "#{pdu_name(snp)}: ID Length #{snp.source_id.bytesize - 1} octets, ours is " \
                                      "#{@system_id.bytesize} (RFC 1142 7.3.15.2 a 2)")
      end
      # Clause 7.3.15.2 a 3, and RFC 5304 section 2.
      if (why = authentication_refusal(snp, @area_key, "RFC 1142 7.3.15.2 a 3"))
        return refuse_pdu(:authentication, "#{pdu_name(snp)}: #{why}")
      end

      mentioned = Set.new
      snp_entries(snp).each do |reported|
        mentioned << reported.lsp_id
        snp_entry(reported)
      end
      # Clause 7.3.15.2 c: a CSNP sets SRM for what this system holds in its
      # range and the neighbour did not mention.
      if snp.is_a?(Pdu::Csnp)
        @database.range(snp.start_lsp_id, snp.end_lsp_id).each do |entry|
          next if mentioned.include?(entry.lsp_id) || entry.sequence.zero? || entry.remaining_lifetime.zero?

          set_srm(entry)
          @log.debug("#{entry.lsp_id_s} not in the neighbour's CSNP, sending it (RFC 1142 7.3.15.2 c)", circuit: @name)
        end
      end
      :processed
    end

    # Send a PSNP with every entry whose SSN is set for this circuit, and
    # clear them. RFC 1142 clause 7.3.15.4: "If there were no ... Link State
    # PDUs with SSNflag set, do not transmit". Returns the PSNP, or nil.
    def send_psnp
      entries = @database.entries.select { |e| e.ssn.include?(@name) }
      return nil if entries.empty?

      psnp = Pdu::Psnp.new(level: 1, source_id: snp_source_id,
                           tlvs: keyed(lsp_entry_tlvs(entries.map(&:snp_entry)), @area_key))
      psnp.key = @area_key
      entries.each { |e| e.ssn.delete(@name) }
      @log.debug("PSNP with #{entries.size} entries: #{entries.map(&:lsp_id_s).join(', ')}", circuit: @name)
      transmit(psnp)
    end

    # The CSNP clause 7.3.15.3 b sends on a point to point circuit "at
    # initialisation": every LSP held, over the whole range. One PDU; more
    # LSPs than fit in one is not handled yet.
    def send_csnp
      entries = @database.entries.reject { |e| e.sequence.zero? }.map(&:snp_entry)
      csnp = Pdu::Csnp.new(level: 1, source_id: snp_source_id, tlvs: keyed(lsp_entry_tlvs(entries), @area_key))
      csnp.key = @area_key
      @log.debug("CSNP with #{entries.size} entries", circuit: @name)
      transmit(csnp)
    end

    # Send every LSP whose SRM is set for this circuit. On a non-broadcast
    # circuit SRM stays set until an LSP or SNP clears it (clause 7.3.15),
    # so this runs again every minimumLSPTransmissionInterval while any is
    # set. Before sending, the Remaining Lifetime is what is left, less one
    # (clause 7.3.16.3: "decrement the Remaining Lifetime in the PDU being
    # transmitted by at least 1").
    def send_srm_lsps
      @srm_timer = nil
      entries = @database.entries.select { |e| e.srm.include?(@name) && !e.placeholder? }
      entries.each do |entry|
        lsp = Pdu::Lsp.new(entry.lsp)
        lsp.lifetime = [entry.remaining_lifetime - 1, 0].max
        transmit(lsp)
      end
      schedule_srm(@lsp_transmission_interval) unless entries.empty?
      entries.size
    end

    # What a received hello changes. Returns the action taken, or the
    # reason it was refused, as a Symbol.
    def receive_hello(hello, snpa)
      if hello.source_id == @system_id
        @log.debug("own hello, ignored", circuit: @name)
        return :own
      end
      # RFC 1142 clause 8.2.4.1 b: an ID Length that is not ours.
      return refuse(:id_length, "ID Length #{hello.source_id.bytesize} octets, ours is #{@system_id.bytesize}") if hello.source_id.bytesize != @system_id.bytesize
      # Clause 9.7: circuit type 0 "the entire PDU shall be ignored".
      return refuse(:circuit_type, "circuit type 0 is reserved (RFC 1142 9.7)") if hello.circuit_type == 0
      # Clause 8.2.4.1 c, and RFC 5304 section 2.
      if (why = authentication_refusal(hello, @hello_key, "RFC 1142 8.2.4.1 c"))
        return refuse(:authentication, why)
      end

      three_way = hello.tlvs.find { |t| t.is_a?(Tlv::ThreeWayAdjacency) }
      reason = three_way && three_way_refusal(three_way)
      return refuse(*reason) if reason

      # A Level 1 circuit and a neighbour that is Level 2 only: no
      # adjacency. ISO's state table for this is not in the supplied text;
      # this follows FRR's process_p2p_hello.
      return drop_neighbor(:level, "neighbor is Level 2 only, this circuit is Level 1") if hello.circuit_type == :l2

      their_areas = hello.tlvs.select { |t| t.is_a?(Tlv::AreaAddresses) }.flat_map { |t| t.areas.map(&:to_s) }
      # RFC 1142 clause 8.2.4.2 b: a Level 1 system with no area in common
      # deletes the adjacency.
      return drop_neighbor(:area, "no area in common: theirs #{their_areas.join(', ')}, ours #{@areas.join(', ')}") if (their_areas & normalized_areas).empty?

      if @neighbor && @neighbor.system_id != hello.source_id
        drop_neighbor(:replaced, "hello from #{hello.source_id_s}, a different neighbor")
      end
      # RFC 5303 section 3.2 a: a new adjacency starts in three-way Down.
      @neighbor ||= Neighbor.new(hello.source_id, snpa, :down)

      # RFC 5303 section 3.2: with no TLV 240 the link is taken to work in
      # both directions, which is the ISO procedure's Up.
      action = three_way ? Adjacency::ThreeWay.action(@neighbor.state, three_way.state) : :up
      @log.debug("three-way #{@neighbor.state}, received #{three_way ? three_way.state : 'no TLV 240'}: #{action}",
                 circuit: @name)
      apply(action, hello, three_way, snpa)
      action
    end

    private

    # +tlvs+ with an HMAC-MD5 Authentication TLV in front when there is a
    # key. First is where FRR 8.4.4 puts it; RFC 5304 does not say.
    def keyed(tlvs, key)
      key ? [Tlv::Authentication.new(:hmac_md5)] + tlvs : tlvs
    end

    # Why a received PDU fails authentication under +key+, or nil. With no
    # key there is nothing to check. With one, clause +clause+: a PDU with
    # no Authentication Information "shall be discarded" (i), and one of a
    # type this system does not implement is "outside the scope" of the
    # clause (ii), so isis4r, configured for HMAC-MD5, refuses it too. RFC
    # 5304 section 2: a receiver "MUST discard the PDU if the
    # Authentication Value is incorrect".
    def authentication_refusal(pdu, key, clause)
      return nil if key.nil?

      unless pdu.tlvs.any? { |t| t.is_a?(Tlv::Authentication) }
        return "no Authentication Information, and a key is configured (#{clause} i)"
      end
      return "authentication is not HMAC-MD5, and isis4r is configured for it (#{clause} ii)" unless pdu.hmac_md5?
      return "the HMAC-MD5 digest is wrong for the configured key (RFC 5304 section 2)" unless pdu.authentic?(key)

      nil
    end

    def holding_time
      [@hello_interval * @hello_multiplier, 0xffff].min
    end

    def normalized_areas
      @areas.map { |a| AreaAddress.new(a).to_s }
    end

    # RFC 5303 section 3.2: an invalid state, or neighbour fields that do
    # not name this system and circuit, discard the PDU.
    def three_way_refusal(three_way)
      unless Adjacency::ThreeWay::TABLE.key?(three_way.state)
        return [:three_way_state, "three-way state #{three_way.state} is not 0, 1 or 2 (RFC 5303 3.2)"]
      end
      if three_way.neighbor_system_id && three_way.neighbor_system_id != @system_id
        return [:three_way_neighbor, "TLV 240 names neighbor #{three_way.to_hash[:neighbor_system_id]}, not us (RFC 5303 3.2)"]
      end
      if three_way.neighbor_extended_circuit_id && three_way.neighbor_extended_circuit_id != @extended_circuit_id
        return [:three_way_circuit,
                "TLV 240 names circuit #{three_way.neighbor_extended_circuit_id}, ours is #{@extended_circuit_id} (RFC 5303 3.2)"]
      end
      nil
    end

    def apply(action, hello, three_way, snpa)
      if action == :down
        drop_neighbor(:restarted, "neighbor reports three-way Up while ours is Down: neighbor restarted (RFC 5303 3.2)")
        return
      end

      before = @neighbor.state
      @neighbor.state = Adjacency::ThreeWay.after(action, before)
      # RFC 1142 clause 8.2.4.2 e: on Up or Accept, take the holding time
      # and areas from the PDU.
      @neighbor.snpa = snpa
      @neighbor.holding_time = hello.holding_time
      @neighbor.areas = hello.tlvs.select { |t| t.is_a?(Tlv::AreaAddresses) }.flat_map { |t| t.areas.map(&:to_s) }
      @neighbor.extended_circuit_id = three_way&.extended_circuit_id
      restart_holding_timer
      return if before == @neighbor.state

      @log.info("adjacency with #{@neighbor.system_id_s} #{before} -> #{@neighbor.state}",
                circuit: @name, kind: :adjacency, neighbor: @neighbor.system_id_s, from: before, to: @neighbor.state)
      adjacency_up if @neighbor.state == :up
    end

    # Clause 7.3.15.3 b: CSNPs "are only transmitted on point to point
    # circuits at initialisation", and the PSNP timer starts.
    def adjacency_up
      @originator&.changed("adjacency with #{@neighbor.system_id_s} on #{@name} up (RFC 1142 7.3.6)")
      send_csnp
      start_psnp_timer unless @psnp_timer
    end

    # The neighbour is gone, so nothing is owed to it on this circuit.
    def adjacency_down
      @originator&.changed("adjacency on #{@name} down (RFC 1142 7.3.6)")
      [@psnp_timer, @srm_timer].each { |t| t&.cancel }
      @psnp_timer = @srm_timer = nil
      @database.entries.each do |e|
        e.srm.delete(@name)
        e.ssn.delete(@name)
      end
    end

    # Clause 7.3.15.1 c: an LSP with this system's ID that it does not
    # generate is purged network wide, which is not here yet. Clause d: one
    # it does generate is compared with the held copy. Equal is acknowledged
    # and older sends ours back, as for any LSP (7.3.15.1 e 2 and e 3).
    # Newer, or the same sequence with another checksum, is the
    # originator's: it generates past the received sequence (7.3.16.1,
    # 7.3.16.2).
    def receive_own_lsp(lsp)
      id = lsp.lsp_id_s
      unless @originator&.generates?(lsp.lsp_id)
        return refuse_pdu(:own, "LSP #{id} carries this system's ID and is not one it generates; " \
                                "RFC 1142 7.3.15.1 c purges it, and purging is not implemented")
      end

      entry = @database.entry(lsp.lsp_id)
      result = Database.compare(entry, sequence: lsp.sequence, lifetime: lsp.lifetime, checksum: lsp.checksum)
      case result
      when :equal
        entry.srm.delete(@name)
        set_ssn(entry)
        @log.debug("own LSP #{id} sequence #{seq(lsp.sequence)} equals ours, acknowledged", circuit: @name)
      when :older
        entry.ssn.delete(@name)
        set_srm(entry)
        @log.debug("own LSP #{id} sequence #{seq(lsp.sequence)} is older than ours, sending ours", circuit: @name)
      else
        @log.info("own LSP #{id} received with sequence #{seq(lsp.sequence)}, ours is #{seq(entry.sequence)}: " \
                  "#{result}", circuit: @name, kind: :database, lsp_id: id, result: result)
        @originator.receive_own(result, lsp)
      end
      result
    end

    def receive_update(pdu)
      unless pdu.level == 1
        return @log.debug("Level #{pdu.level.inspect} #{pdu_name(pdu)} ignored on a Level 1 circuit", circuit: @name)
      end
      return @log.debug("#{pdu_name(pdu)} ignored: no adjacency up", circuit: @name) unless up?

      pdu.is_a?(Pdu::Lsp) ? receive_lsp(pdu) : receive_snp(pdu)
    end

    def snp_entries(snp)
      snp.tlvs.select { |t| t.is_a?(Tlv::LspEntries) }.flat_map(&:entries)
    end

    # One reported entry against the database, RFC 1142 clause 7.3.15.2 b.
    def snp_entry(reported)
      held = @database[reported.lsp_id]
      if held.nil?
        # b 4: nothing held, and the report is all non-zero: make a
        # sequence 0 entry and ask for it.
        return if [reported.lifetime, reported.checksum, reported.sequence].any?(&:zero?)

        entry = @database.entry(reported.lsp_id)
        set_ssn(entry)
        @log.debug("#{entry.lsp_id_s} reported and not held, requesting it (RFC 1142 7.3.15.2 b 4)", circuit: @name)
        return
      end

      case Database.compare(held, sequence: reported.sequence, lifetime: reported.lifetime, checksum: reported.checksum)
      when :equal
        # b 1: the neighbour has it, so it is acknowledged.
        held.srm.delete(@name)
      when :older
        # b 2: the neighbour's is older, so send ours.
        held.ssn.delete(@name)
        set_srm(held)
      when :newer
        # b 3: the neighbour's is newer, so ask for it.
        set_ssn(held)
        held.srm.delete(@name)
        @log.debug("#{held.lsp_id_s} reported newer (#{seq(reported.sequence)} against #{seq(held.sequence)}), " \
                   "requesting it (RFC 1142 7.3.15.2 b 3)", circuit: @name)
      when :confused
        @log.info("#{held.lsp_id_s} reported with sequence #{seq(reported.sequence)} and a different checksum; " \
                  "RFC 1142 7.3.16.2 is not implemented", circuit: @name, kind: :refused, reason: :confused)
      end
    end

    def set_ssn(entry)
      entry.ssn << @name
    end

    # RFC 1142 clause 7.3.15: "SRMflag shall never be set for an LSP with
    # sequence number zero".
    def set_srm(entry)
      return if entry.sequence.zero?

      entry.srm << @name
      schedule_srm(0)
    end

    def schedule_srm(delay)
      @srm_timer ||= @scheduler.after(delay) { send_srm_lsps }
    end

    # TLV 9s holding +entries+, as many to a TLV as fit in 255 octets.
    def lsp_entry_tlvs(entries)
      return [] if entries.empty?

      per_tlv = 255 / (@system_id.bytesize + 10)
      entries.each_slice(per_tlv).map { |slice| Tlv::LspEntries.new(slice) }
    end

    # The PSNP timer, clause 7.3.15.4: every partialSNPInterval. The jitter
    # clause 10.1 asks for is not applied yet.
    def start_psnp_timer
      @psnp_timer = @scheduler.after(@partial_snp_interval) do
        send_psnp
        start_psnp_timer
      end
    end

    # This system's ID with a zero circuit octet, as the Source ID of an SNP
    # is written: "the system ID of Intermediate System (with zero Circuit
    # ID)", RFC 1142 clause 9.10.
    def snp_source_id
      "#{@system_id.unpack1('H*').scan(/.{1,4}/).join('.')}.00"
    end

    def seq(n)
      format("0x%08x", n)
    end

    def pdu_name(pdu)
      pdu.class.name.split("::").last
    end

    def refuse_pdu(reason, why)
      @log.info("refused: #{why}", circuit: @name, kind: :refused, reason: reason)
      reason
    end

    # RFC 1142 clause 8.2.5: a neighbour not heard from within its holding
    # time is purged.
    def restart_holding_timer
      @neighbor.expiry&.cancel
      seconds = @neighbor.holding_time
      @neighbor.expiry = @scheduler.after(seconds) do
        drop_neighbor(:expired, "holding time of #{seconds} s expired without a hello (RFC 1142 8.2.5)")
      end
    end

    def drop_neighbor(reason, why)
      if @neighbor
        @neighbor.expiry&.cancel
        @log.info("adjacency with #{@neighbor.system_id_s} #{@neighbor.state} -> down: #{why}",
                  circuit: @name, kind: :adjacency, neighbor: @neighbor.system_id_s, from: @neighbor.state,
                  to: :down, reason: reason)
        @neighbor = nil
        adjacency_down
      else
        @log.info("hello refused: #{why}", circuit: @name, kind: :refused, reason: reason)
      end
      reason
    end

    def refuse(reason, why)
      @log.info("hello refused: #{why}", circuit: @name, kind: :refused, reason: reason)
      reason
    end
  end
end
