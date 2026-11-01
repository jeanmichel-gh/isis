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
  # Not here yet: LSP expiry and purging (clause 7.3.16.4).
  class Database
    # RFC 1142 clause 7.3.21: "MaxAge is an architectural constant equal to
    # 20 minutes."
    MAX_AGE = 1200

    # One stored LSP, or, with sequence 0 and no LSP, the placeholder
    # clause 7.3.15.2 b 4 asks for when an SNP reports an LSP this system
    # does not have: "create an entry with sequence number 0".
    class Entry
      attr_reader :lsp_id, :lsp, :sequence, :checksum, :srm, :ssn

      def initialize(lsp_id, clock)
        @lsp_id = lsp_id
        @clock = clock
        @sequence = 0
        @checksum = 0
        @lifetime = 0
        @stored_at = clock.now
        @lsp = nil
        @srm = Set.new
        @ssn = Set.new
      end

      def store(lsp)
        @lsp = lsp
        @sequence = lsp.sequence
        @checksum = lsp.checksum
        @lifetime = lsp.lifetime
        @stored_at = @clock.now
        self
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
    end

    attr_reader :level, :clock

    def initialize(level:, clock:)
      @level = level
      @clock = clock
      @entries = {}
    end

    def [](lsp_id)
      @entries[lsp_id.b]
    end

    # The entry for +lsp_id+, made if there is none.
    def entry(lsp_id)
      @entries[lsp_id.b] ||= Entry.new(lsp_id.b, @clock)
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
    # The same sequence and lifetimes with different checksums is clause
    # 7.3.16.2's LSP confusion, which asks for the LSP to be treated as
    # expired. That needs purging, which is not here yet, so it is reported
    # as :confused and not folded into one of the other three.
    def self.compare(held, sequence:, lifetime:, checksum:)
      return :newer if sequence > held.sequence
      return :older if sequence < held.sequence

      held_zero = held.remaining_lifetime.zero?
      return :newer if lifetime.zero? && !held_zero
      return :older if !lifetime.zero? && held_zero
      return :equal if checksum == held.checksum

      :confused
    end
  end
end
