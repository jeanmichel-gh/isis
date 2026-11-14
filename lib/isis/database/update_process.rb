# frozen_string_literal: true

module ISIS
  # The update process for one circuit, RFC 1142 clause 7.3.15: what a
  # received LSP or sequence numbers PDU does to the database and to this
  # circuit's SRM and SSN flags, and the PSNPs, CSNPs and LSPs those flags
  # send. P2pCircuit and LanCircuit both include it. Where the clauses say
  # "if C is a non-broadcast circuit", the answer is broadcast?.
  #
  # What the two circuits differ in, all from clause 7.3.15:
  #
  #   received LSP, newer or equal   SSN set only on a non-broadcast circuit
  #                                  (7.3.15.1 e 1 iv, e 2 ii)
  #   SNP reports an equal LSP       SRM cleared only on a non-broadcast
  #                                  circuit (7.3.15.2 b 1)
  #   SNP reports a newer LSP        SRM cleared only on a non-broadcast
  #                                  circuit (7.3.15.2 b 3)
  #   SRM                            on a broadcast circuit cleared as soon as
  #                                  the LSP is sent, otherwise kept until an
  #                                  LSP or SNP clears it (7.3.15)
  #
  # The circuit provides: @name, @system_id, @database, @log, @scheduler,
  # @area_key, @lsp_transmission_interval, broadcast?, level, transmit,
  # and generators, the originators whose LSPs this system generates.
  module UpdateProcess
    # What a received LSP does, RFC 1142 clause 7.3.15.1. Returns what
    # happened, or the reason it was refused, as a Symbol.
    def receive_lsp(lsp)
      id = lsp.lsp_id_s
      # Clause 7.3.15.1 a 2: an ID Length that is not ours.
      if lsp.lsp_id.bytesize != @system_id.bytesize + 2
        return refuse_pdu(:id_length, "LSP #{id}: ID Length #{lsp.lsp_id.bytesize - 2} octets, ours is " \
                                      "#{@system_id.bytesize} (RFC 1142 7.3.15.1 a 2)")
      end
      # Clause 7.3.15.1 a 3, and RFC 5304 section 2.
      if (why = authentication_refusal(lsp, @area_key, "RFC 1142 7.3.15.1 a 3"))
        return refuse_pdu(:authentication, "LSP #{id}: #{why}")
      end
      # Clause 7.3.15.1 b sends a zero Remaining Lifetime to 7.3.16.4. Its
      # checksum is not checked: "A check of the checksum of a zero
      # Remaining Lifetime LSP succeeds even though the data portion is not
      # present" (7.3.16.4).
      return receive_purge(lsp) if lsp.lifetime.zero?

      # Clause 7.3.14 e asks for a corrupted LSP to be treated as expired
      # and purged. isis4r drops it and starts no purge.
      unless lsp.checksum_ok?
        return refuse_pdu(:checksum, "LSP #{id}: checksum #{format('0x%04x', lsp.checksum)} is wrong; " \
                                     "dropped, and not purged as RFC 1142 7.3.14 e asks")
      end
      # Clause 7.3.15.1 c and d: an LSP with this system's ID, or one a
      # generator here generates, such as a simulated system's.
      return receive_own_lsp(lsp) if own_id?(lsp.lsp_id) || generator_of(lsp.lsp_id)

      entry = @database.entry(lsp.lsp_id)
      result = entry.placeholder? ? :new : Database.compare(entry, sequence: lsp.sequence, lifetime: lsp.lifetime,
                                                                   checksum: lsp.checksum)
      case result
      when :new, :newer
        held = entry.sequence
        before = entry.placeholder? || entry.purged? ? nil : entry.lsp
        entry.store(lsp)
        # A refresh is marked, so a viewer can leave it out.
        refresh = before && !lsp.lifetime.zero? && Database.same_content?(before, lsp) ? { refresh: true } : {}
        # Clause 7.3.15.1 e 1: store, set SRM on the other circuits and
        # clear their SSN, clear SRM for C, and on a non-broadcast circuit
        # set SSN for C.
        stored_from_c(entry)
        @log.info("LSP #{id} sequence #{seq(lsp.sequence)} stored: " \
                  "#{result == :new ? 'not held before' : "newer than #{seq(held)}"} (RFC 1142 7.3.15.1 e 1)",
                  circuit: @name, kind: :database, lsp_id: id, sequence: lsp.sequence, result: result, **refresh)
      when :equal
        # Clause 7.3.15.1 e 2: clear SRM, and on a non-broadcast circuit
        # set SSN.
        entry.srm.delete(@name)
        set_ssn(entry) unless broadcast?
        @log.debug("LSP #{id} sequence #{seq(lsp.sequence)} equals the held one#{broadcast? ? '' : ', acknowledged'}",
                   circuit: @name)
      when :older
        # Clause 7.3.15.1 e 3: set SRM, clear SSN, so ours goes back.
        entry.ssn.delete(@name)
        set_srm(entry)
        @log.info("LSP #{id} sequence #{seq(lsp.sequence)} is older than the held #{seq(entry.sequence)}, " \
                  "sending ours (RFC 1142 7.3.15.1 e 3)", circuit: @name, kind: :database, lsp_id: id, result: result)
      when :confused
        # Clause 7.3.16.2: "treat the LSP as if its Remaining Lifetime had
        # expired. It shall store one of the copies of the LSP, with zero
        # written as the Remaining Lifetime, and flood the LSP." The held
        # copy is the one kept.
        @database.purge(entry, "same sequence #{seq(lsp.sequence)} as the held copy, another checksum " \
                               "(RFC 1142 7.3.16.2)", retain: Database::MAX_AGE)
      end
      result
    end

    # A received LSP with zero Remaining Lifetime, a purge: RFC 1142 clause
    # 7.3.16.4. Returns what was done as a Symbol.
    def receive_purge(lsp)
      id = lsp.lsp_id_s
      # RFC 5304 section 2: "ISes MUST NOT accept purges that contain TLVs
      # other than the authentication TLV."
      if @area_key && lsp.tlvs.any? { |t| !t.is_a?(Tlv::Authentication) }
        return refuse_pdu(:purge_tlvs, "LSP #{id}: a purge carrying TLVs other than TLV 10 (RFC 5304 section 2)")
      end

      held = @database[lsp.lsp_id]
      generator = generator_of(lsp.lsp_id)
      # c: this system's own LSP, unexpired: not overwritten, generated
      # again past the purge's sequence.
      if generator && held && !held.placeholder? && !held.remaining_lifetime.zero?
        @log.info("own LSP #{id} purged by a neighbour at sequence #{seq(lsp.sequence)}, ours is " \
                  "#{seq(held.sequence)}: generating it again (RFC 1142 7.3.16.4 c)",
                  circuit: @name, kind: :database, lsp_id: id, result: :purged_own)
        generator.receive_own(:newer, lsp)
        return :regenerated
      end
      # a: nothing held, so acknowledge and keep nothing.
      if held.nil? || held.placeholder?
        @database.delete(lsp.lsp_id) if held
        acknowledge_unheld(lsp)
        @log.debug("purge of #{id}, not held: acknowledged, not kept (RFC 1142 7.3.16.4 a)", circuit: @name)
        return :not_held
      end

      result = Database.compare(held, sequence: lsp.sequence, lifetime: 0, checksum: lsp.checksum)
      case result
      when :newer
        # b 1: store it, and the flags as 7.3.15.1 e 1 sets them. Its
        # header goes after ZeroAgeLifetime.
        held.store(lsp)
        stored_from_c(held)
        @log.info("LSP #{id} sequence #{seq(lsp.sequence)} purged by a neighbour (RFC 1142 7.3.16.4 b 1)",
                  circuit: @name, kind: :database, lsp_id: id, sequence: lsp.sequence, result: :purged)
      when :equal
        # b 2: clear SRM, and on a non-broadcast circuit set SSN.
        held.srm.delete(@name)
        set_ssn(held) unless broadcast?
        @log.debug("purge of #{id} sequence #{seq(lsp.sequence)} equals the held one", circuit: @name)
      when :older
        # b 3: set SRM and clear SSN, so ours goes back.
        held.ssn.delete(@name)
        set_srm(held)
        @log.debug("purge of #{id} sequence #{seq(lsp.sequence)} is older than the held #{seq(held.sequence)}",
                   circuit: @name)
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

    # Send a PSNP with the entries whose SSN is set for this circuit, as
    # many as fit, and clear SSN for those. RFC 1142 clause 7.3.15.4: "as
    # many ... with SSNflag set as will fit in the PDU", and "to avoid the
    # possibility of starvation, the scan ... shall commence with the next
    # LSP which was not included in the previous scan". "If there were no
    # ... Link State PDUs with SSNflag set, do not transmit". Returns the
    # PSNP, or nil.
    def send_psnp
      flagged = @database.entries.select { |e| e.ssn.include?(@name) }.sort_by(&:lsp_id)
      return nil if flagged.empty?

      after = flagged.index { |e| e.lsp_id > @psnp_scanned_to } if @psnp_scanned_to
      flagged = flagged.rotate(after || 0)
      build = ->(slice) { snp(Pdu::Psnp, slice.map(&:snp_entry)) }
      entries = flagged.first(fitting(flagged.size) { |n| build.(flagged.first(n)) })
      psnp = build.(entries)
      entries.each { |e| e.ssn.delete(@name) }
      @psnp_scanned_to = entries.last.lsp_id
      @log.debug("PSNP with #{entries.size} entries: #{entries.map(&:lsp_id_s).join(', ')}", circuit: @name)
      transmit(psnp)
      psnp
    end

    # A complete set of CSNPs: every LSP held, over the whole range. On a
    # point to point circuit clause 7.3.15.3 b sends it "at
    # initialisation", and on a broadcast one the DIS sends "a complete
    # set" every completeSNPInterval (7.3.15.3 a).
    #
    # More entries than fit in one PDU of originatingLxLSPBufferSize octets
    # go in "a series of individual CSNPs, each referring to a subset of
    # the complete range". The ranges "shall be contiguous ... and shall
    # cover the entire range of possible LSPIDs" (section 9.10): the first
    # starts at all zeros, each next one right after the last LSP of the
    # one before, and the last ends at all ones. On a broadcast circuit
    # they go "separated by an interval of at least
    # minimumBroadcastLSPTransmissionInterval" (7.3.15.3 a). Returns them.
    def send_csnp
      entries = @database.entries.reject { |e| e.sequence.zero? }.sort_by(&:lsp_id).map(&:snp_entry)
      csnps = csnp_set(entries)
      @log.debug("CSNP set of #{csnps.size} with #{entries.size} entries", circuit: @name)
      csnps.each_with_index do |csnp, i|
        if i.zero? || !broadcast?
          transmit(csnp)
        else
          # Only while still DIS: it may have lost the election meanwhile.
          @scheduler.after(i * @lsp_transmission_interval) { transmit(csnp) if dis? }
        end
      end
      csnps
    end

    # Send the LSPs whose SRM is set for this circuit. Before sending, the
    # Remaining Lifetime is what is left, less one (clause 7.3.16.3:
    # "decrement the Remaining Lifetime in the PDU being transmitted by at
    # least 1").
    #
    # On a non-broadcast circuit every one goes, and SRM stays set until an
    # LSP or SNP clears it, so this runs again every
    # minimumLSPTransmissionInterval while any is set (clauses 7.3.15 and
    # 7.3.15.5). On a broadcast circuit one goes, and its SRM is cleared,
    # every minimumBroadcastLSPTransmissionInterval (clause 7.3.15.6). The
    # clause picks that one "at random"; this takes the lowest LSP ID, so a
    # run is reproducible without an injected source of randomness.
    def send_srm_lsps
      @srm_timer = nil
      entries = @database.entries.select { |e| e.srm.include?(@name) && !e.placeholder? }
      if broadcast?
        entries = entries.first(1)
        entries.each { |e| e.srm.delete(@name) }
      end
      entries.each { |entry| transmit(outgoing(entry)) }
      more = broadcast? ? @database.entries.any? { |e| e.srm.include?(@name) } : !entries.empty?
      schedule_srm(@lsp_transmission_interval) if more
      entries.size
    end

    private

    def keyed(tlvs, key)
      Receive::Authentication.keyed(tlvs, key)
    end

    # The copy of +entry+'s LSP that goes out now, its lifetime counted
    # down. A purge this system started holds the header alone, and with an
    # area key it goes out with TLV 10 (RFC 5304 section 2: purges "MUST
    # remove the body of the LSP and add the authentication TLV").
    def outgoing(entry)
      if entry.purged? && @area_key && entry.lsp.tlvs.size.zero?
        lsp = Pdu::Lsp.new(level: entry.lsp.level, lsp_id: Octets.new(entry.lsp_id), lifetime: 0,
                           sequence: entry.sequence, tlvs: keyed([], @area_key))
        lsp.flags = entry.lsp.flags
        lsp.key = @area_key
        return lsp
      end

      lsp = Pdu::Lsp.new(entry.lsp)
      lsp.lifetime = [entry.remaining_lifetime - 1, 0].max
      lsp
    end

    # Clause 7.3.16.4 a 1: a purge of an LSP not held is acknowledged on
    # C. On a non-broadcast circuit that is a PSNP; on a broadcast circuit
    # the DIS's CSNPs acknowledge, and nothing is sent.
    def acknowledge_unheld(lsp)
      return if broadcast?

      reported = Tlv::LspEntries::Entry.new(0, lsp.lsp_id, lsp.sequence, lsp.checksum)
      psnp = Pdu::Psnp.new(level: level, source_id: snp_source_id, tlvs: keyed(lsp_entry_tlvs([reported]), @area_key))
      psnp.key = @area_key
      transmit(psnp)
    end

    def authentication_refusal(pdu, key, clause)
      Receive::Authentication.refusal(pdu, key, clause)
    end

    # Clause 7.3.15.1 c: an LSP with this system's ID that it does not
    # generate is purged network wide. Clause d: one
    # it does generate is compared with the held copy. Equal is acknowledged
    # and older sends ours back, as for any LSP (7.3.15.1 e 2 and e 3).
    # Newer, or the same sequence with another checksum, is the
    # originator's: it generates past the received sequence (7.3.16.1,
    # 7.3.16.2).
    def receive_own_lsp(lsp)
      id = lsp.lsp_id_s
      generator = generator_of(lsp.lsp_id)
      unless generator
        # Clause 7.3.15.1 c: one this system does not generate, from a
        # previous incarnation or a pseudonode it no longer runs, is purged
        # network wide, the received sequence kept so the purge is newer.
        entry = @database.entry(lsp.lsp_id)
        entry.store(lsp) if entry.placeholder? || lsp.sequence > entry.sequence
        @database.purge(entry, "carries this system's ID and is not one it generates (RFC 1142 7.3.15.1 c)",
                        retain: Database::MAX_AGE)
        return :purged
      end

      entry = @database.entry(lsp.lsp_id)
      result = Database.compare(entry, sequence: lsp.sequence, lifetime: lsp.lifetime, checksum: lsp.checksum)
      case result
      when :equal
        entry.srm.delete(@name)
        set_ssn(entry) unless broadcast?
        @log.debug("own LSP #{id} sequence #{seq(lsp.sequence)} equals ours", circuit: @name)
      when :older
        entry.ssn.delete(@name)
        set_srm(entry)
        @log.debug("own LSP #{id} sequence #{seq(lsp.sequence)} is older than ours, sending ours", circuit: @name)
      else
        @log.info("own LSP #{id} received with sequence #{seq(lsp.sequence)}, ours is #{seq(entry.sequence)}: " \
                  "#{result}", circuit: @name, kind: :database, lsp_id: id, result: result)
        generator.receive_own(result, lsp)
      end
      result
    end

    def own_id?(lsp_id)
      lsp_id.byteslice(0, @system_id.bytesize) == @system_id
    end

    # The generator here of +lsp_id+, nil when none generates it.
    def generator_of(lsp_id)
      generators.find { |g| g.generates?(lsp_id) }
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
        # b 1: on a non-broadcast circuit the neighbour has it, so it is
        # acknowledged.
        held.srm.delete(@name) unless broadcast?
      when :older
        # b 2: the neighbour's is older, so send ours.
        held.ssn.delete(@name)
        set_srm(held)
      when :newer
        # b 3: the neighbour's is newer, so ask for it.
        set_ssn(held)
        held.srm.delete(@name) unless broadcast?
        @log.debug("#{held.lsp_id_s} reported newer (#{seq(reported.sequence)} against #{seq(held.sequence)}), " \
                   "requesting it (RFC 1142 7.3.15.2 b 3)", circuit: @name)
      when :confused
        # Clause 7.3.16.2 compares "the checksum on a received LSP", so a
        # report in an SNP starts no purge; the LSP itself would.
        @log.info("#{held.lsp_id_s} reported with sequence #{seq(reported.sequence)} and a different checksum; " \
                  "no purge for a report (RFC 1142 7.3.16.2 is about a received LSP)",
                  circuit: @name, kind: :refused, reason: :confused)
      end
    end

    def set_ssn(entry)
      entry.ssn << @name
    end

    # The flags after storing a newer LSP or purge received on this
    # circuit, C: RFC 1142 7.3.15.1 e 1 ii to v, and 7.3.16.4 b 1 ii to v,
    # in the same words. "Set SRMflag for that LSP for all circuits other
    # than C", "Clear SRMflag for C", "If C is a non-broadcast circuit, set
    # SSNflag for that LSP for C", "Clear SSNflag for that LSP for the
    # circuits other than C".
    #
    # The other circuits are the database's, each asked to flood the
    # entry: a circuit sets SRM only while it has an adjacency up, as for
    # this system's own LSPs and for a purge (7.3.16.4 a). One that comes
    # up later is brought level by the CSNP sent on its adjacency coming
    # up.
    def stored_from_c(entry)
      entry.ssn.clear
      @database.circuits.each { |c| c.flood(entry) unless c.equal?(self) }
      entry.srm.delete(@name)
      set_ssn(entry) unless broadcast?
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

    # Nothing is owed on this circuit any more: no LSPs to send, no flags.
    def clear_update_state
      @srm_timer&.cancel
      @srm_timer = nil
      @database.entries.each do |e|
        e.srm.delete(@name)
        e.ssn.delete(@name)
      end
    end

    # The CSNPs of a complete set for +entries+, sorted by LSP ID.
    def csnp_set(entries)
      width = @system_id.bytesize + 2
      bottom = "\x00".b * width
      top = "\xff".b * width
      return [snp(Pdu::Csnp, [], bottom, top)] if entries.empty?

      set = []
      start = bottom
      until entries.empty?
        n = fitting(entries.size) { |k| snp(Pdu::Csnp, entries.first(k), start, top) }
        slice = entries.shift(n)
        last = entries.empty? ? top : slice.last.lsp_id
        set << snp(Pdu::Csnp, slice, start, last)
        start = lsp_id_after(last) unless entries.empty?
      end
      set
    end

    # A PSNP, or a CSNP over +start+ to +last+, holding +entries+, keyed.
    def snp(klass, entries, start = nil, last = nil)
      range = klass == Pdu::Csnp ? { start_lsp_id: Pdu.lsp_id_s(start), end_lsp_id: Pdu.lsp_id_s(last) } : {}
      pdu = klass.new(level: level, source_id: snp_source_id, tlvs: keyed(lsp_entry_tlvs(entries), @area_key), **range)
      pdu.key = @area_key
      pdu
    end

    # The most of +available+ entries whose PDU, as the block builds it,
    # fits in originatingLxLSPBufferSize octets (clauses 7.3.15.3 and
    # 7.3.15.4). At least one, so a set always moves on.
    def fitting(available)
      fits = ->(n) { yield(n).encode.bytesize <= snp_buffer_size }
      return available if fits.(available)

      low = 1
      high = available
      while high - low > 1
        mid = (low + high) / 2
        fits.(mid) ? low = mid : high = mid
      end
      low
    end

    # originatingL1LSPBufferSize or originatingL2LSPBufferSize: the
    # originators' buffer size, which is the same at a level.
    def snp_buffer_size
      generators.map { |g| g.respond_to?(:buffer_size) ? g.buffer_size : nil }.compact.min || Originator::LSP_BUFFER_SIZE
    end

    # The LSP ID one above +octets+, where the next CSNP's range starts.
    def lsp_id_after(octets)
      [format("%0#{octets.bytesize * 2}x", octets.unpack1("H*").to_i(16) + 1)].pack("H*")
    end

    # TLV 9s holding +entries+, as many to a TLV as fit in 255 octets.
    def lsp_entry_tlvs(entries)
      return [] if entries.empty?

      per_tlv = 255 / (@system_id.bytesize + 10)
      entries.each_slice(per_tlv).map { |slice| Tlv::LspEntries.new(slice) }
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
  end
end
