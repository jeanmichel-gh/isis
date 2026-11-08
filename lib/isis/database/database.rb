# frozen_string_literal: true

require "set"

module ISIS
  # One level's link state database: the LSPs this system holds, and for
  # each the per circuit SRM and SSN flags of RFC 1142 clause 7.3.15.
  #
  # The Remaining Lifetime of a stored LSP counts down on the injected
  # clock. RFC 1142 clause 7.3.16.3: "When a system holds the information
  # for some time before successfully transmitting it to a neighbour, that
  # system shall decrement the Remaining Lifetime field according to the
  # holding time." So an entry keeps the lifetime it arrived with and when
  # it arrived, and answers the remaining lifetime from the clock.
  #
  # This system's own LSP is stored here by the Originator, like any other.
  #
  # With a scheduler, an LSP expires when its Remaining Lifetime reaches
  # zero, and a purged LSP's header is removed when it has been held long
  # enough. RFC 1142 clause 7.3.16.4. Without one, nothing ages away on its
  # own, which suits a test that only wants a store.
  #
  # A purge keeps the header alone, with lifetime 0, the same sequence,
  # and a checksum computed again over the header. Measured on FRR 8.4.4:
  # its purge is exactly that, and isis4r builds the same octets
  # (test/fixtures/frr-8.4.4-l1-lsp-purge.hex). An authenticated purge
  # also carries TLV 10 (RFC 5304 section 2); the circuit adds it as it
  # sends, since the key is the circuit's.
  class Database
    # RFC 1142 clause 7.3.21: "MaxAge is an architectural constant equal to
    # 20 minutes."
    MAX_AGE = 1200
    # Clause 7.3.21: "ZeroAgeLifetime is an architectural constant with a
    # value of 1 minute."
    ZERO_AGE_LIFETIME = 60

    # One stored LSP, or, with sequence 0 and no LSP, the placeholder
    # clause 7.3.15.2 b 4 asks for when an SNP reports an LSP this system
    # does not have: "create an entry with sequence number 0".
    class Entry
      attr_reader :lsp_id, :lsp, :sequence, :checksum, :srm, :ssn, :hostname
      attr_accessor :timer

      def initialize(lsp_id, clock, database = nil)
        @lsp_id = lsp_id
        @clock = clock
        @database = database
        @timer = nil
        @sequence = 0
        @checksum = 0
        @lifetime = 0
        @stored_at = clock.now
        @lsp = nil
        @hostname = nil
        @srm = Set.new
        @ssn = Set.new
      end

      # +retain+, for a purge, is how long its header is kept.
      def store(lsp, retain: nil)
        @lsp = lsp
        @hostname = name_in(lsp) unless lsp.lifetime.zero?
        @sequence = lsp.sequence
        @checksum = lsp.checksum
        @lifetime = lsp.lifetime
        @stored_at = @clock.now
        @database&.stored(self, retain)
        self
      end

      # A purge, or an LSP that expired: lifetime 0 (clause 7.3.16.4).
      def purged?
        !placeholder? && @lifetime.zero?
      end

      def placeholder?
        @lsp.nil?
      end

      # Seconds left, counted down from what the LSP arrived with.
      def remaining_lifetime
        [@lifetime - (@clock.now - @stored_at).floor, 0].max
      end

      def lsp_id_s
        Pdu.lsp_id_s(@lsp_id)
      end

      # The values an SNP reports for this LSP: clause 9.10's entry fields.
      def snp_entry
        Tlv::LspEntries::Entry.new(remaining_lifetime, @lsp_id, @sequence, @checksum)
      end

      private

      # The name in TLV 137, from a non-pseudonode LSP (RFC 5301 section 3:
      # in a pseudonode LSP it "SHOULD NOT be interpreted as the DNS
      # hostname of the router"). A purge carries no TLVs, so +store+ keeps
      # the name the LSP had until the header goes. RFC 5301 section 4 says
      # only that a receiver may "install the symbolic name and system ID
      # in its hostname mapping table"; how long it stays is our choice,
      # and it is what FRR 8.4.4 shows, a purge listed by name.
      def name_in(lsp)
        return nil unless @lsp_id.getbyte(@lsp_id.bytesize - 2).zero?

        tlv = lsp.tlvs.to_a.grep(Tlv::DynamicHostname).first
        tlv&.name&.dup&.force_encoding("UTF-8")
      end
    end

    attr_reader :level, :clock, :scheduler, :circuits

    def initialize(level:, clock:, scheduler: nil, log: nil)
      @level = level
      @clock = clock
      @scheduler = scheduler
      @log = log
      @entries = {}
      @circuits = []
      @listeners = []
      @generators = []
    end

    # Originators of LSPs in this database other than a circuit's own: a
    # simulator's simulated systems. Each answers generates?(lsp_id) and
    # receive_own(result, lsp), and the update process treats the LSPs it
    # generates as this system's own (RFC 1142 7.3.15.1 c and d, 7.3.16.1,
    # 7.3.16.4 c).
    attr_reader :generators

    def add_generator(generator)
      @generators << generator unless @generators.include?(generator)
      self
    end

    # A circuit that floods from this database. It answers flood(entry),
    # which sets SRM on it when it has an adjacency up. Clause 7.3.16.4 a
    # sets SRM "for that LSP" on all circuits when it expires.
    def attach(circuit)
      @circuits << circuit unless @circuits.include?(circuit)
      self
    end

    # Something told of every LSP stored here, purges included: it answers
    # stored(entry). The Level 2 originator of a system at both levels
    # listens to the Level 1 database for its area addresses (7.2.11).
    def listen(listener)
      @listeners << listener unless @listeners.include?(listener)
      self
    end

    def [](lsp_id)
      @entries[lsp_id.b]
    end

    # The entry for +lsp_id+, made if there is none.
    def entry(lsp_id)
      @entries[lsp_id.b] ||= Entry.new(lsp_id.b, @clock, self)
    end

    # Drop the entry for +lsp_id+, and its timer.
    def delete(lsp_id)
      entry = @entries.delete(lsp_id.b)
      entry&.timer&.cancel
      entry
    end

    # Purge +entry+ now, clause 7.3.16.4: keep the header alone with lifetime
    # 0 and set SRM on every circuit. +retain+ is how long the header stays:
    # ZeroAgeLifetime for an LSP that expired, and MaxAge for a purge this
    # system starts of an LSP whose lifetime had not run out ("When a purge
    # of an LSP with non-zero Remaining Lifetime is initiated, the header
    # shall be retained for MaxAge"). Returns the entry.
    def purge(entry, reason, retain: ZERO_AGE_LIFETIME)
      header = Pdu::Lsp.new(level: @level, lsp_id: Octets.new(entry.lsp_id), lifetime: 0, sequence: entry.sequence,
                            tlvs: [])
      header.flags = entry.lsp.flags if entry.lsp
      entry.store(header, retain: retain)
      @log&.info("LSP #{entry.lsp_id_s} sequence #{format('0x%08x', entry.sequence)} purged: #{reason}",
                 kind: :purge, lsp_id: entry.lsp_id_s, sequence: entry.sequence)
      @circuits.each { |c| c.flood(entry) }
      entry
    end

    # Called by an entry as it stores an LSP: tell the listeners, and set
    # the timer for what comes next. An LSP with lifetime left expires when it runs out (7.3.16.3).
    # A purge's header goes after ZeroAgeLifetime, or the retention purge
    # asked for (7.3.16.4 c).
    def stored(entry, retain = nil)
      @listeners.each { |l| l.stored(entry) }
      return unless @scheduler

      entry.timer&.cancel
      entry.timer =
        if entry.purged?
          @scheduler.after(retain || ZERO_AGE_LIFETIME) { remove(entry) }
        else
          @scheduler.after(entry.remaining_lifetime) do
            purge(entry, "Remaining Lifetime reached zero (RFC 1142 7.3.16.4)")
          end
        end
    end

    # Every entry in ascending LSP ID order, the order clause 9.10 asks of
    # the entries in a CSNP.
    def entries
      @entries.keys.sort.map { |k| @entries[k] }
    end

    def size
      @entries.size
    end

    # Entries whose LSP ID falls in the range of a CSNP, inclusive.
    def range(start_lsp_id, end_lsp_id)
      entries.select { |e| e.lsp_id >= start_lsp_id && e.lsp_id <= end_lsp_id }
    end

    # How a reported LSP compares with what is held, from the receiver's
    # side: :newer, :equal or :older than the database's, or :confused.
    #
    # RFC 1142 clause 7.3.16.3: with a non-zero Remaining Lifetime and the
    # same sequence number as a held LSP of zero lifetime, "the LSP in the
    # database shall be considered most recent. Otherwise, the PDU with the
    # larger sequence number shall be considered the most recent." Clause
    # 7.3.15.1 e 2 defines equal: "same Sequence Number, Remaining Lifetimes
    # both zero or both non-zero, same checksums". The same sequence with a
    # zero lifetime arriving against a held non-zero one is a purge, which
    # clause 7.3.16.4 makes newer.
    #
    # Two purges of one sequence are equal whatever their checksums, since
    # equal is "Remaining Lifetimes both zero" (7.3.16.4 b 2). The same
    # sequence and non-zero lifetimes with different checksums is clause
    # 7.3.16.2's LSP confusion, reported as :confused for the update
    # process to purge.
    def self.compare(held, sequence:, lifetime:, checksum:)
      return :newer if sequence > held.sequence
      return :older if sequence < held.sequence

      held_zero = held.remaining_lifetime.zero?
      return :newer if lifetime.zero? && !held_zero
      return :older if !lifetime.zero? && held_zero
      return :equal if held_zero || checksum == held.checksum

      :confused
    end

    # The same TLVs and flags: what a regeneration would change. A new
    # sequence with the same content is a refresh (RFC 1142 7.3.5).
    def self.same_content?(held, fresh)
      held.flags == fresh.flags && held.tlvs.to_shex == fresh.tlvs.to_shex
    end

    private

    def remove(entry)
      return unless @entries[entry.lsp_id].equal?(entry)

      @log&.debug("LSP #{entry.lsp_id_s} header removed, its purge held long enough (RFC 1142 7.3.16.4 c)")
      delete(entry.lsp_id)
    end
  end
end
