# frozen_string_literal: true

module ISIS
  class Pdu
    # The Link State PDU, one layout for both levels. The level lives in the
    # PDU type, 18 for Level 1 (RFC 1142 clause 9.8) and 20 for Level 2
    # (clause 9.9).
    #
    # Fixed header after the common header, clause 9.8, agreeing with FRR
    # (isisd/isis_pdu.h, ISIS_LSP_HDR_LEN 19):
    #
    #   PDU Length          2 octets, "Entire Length of this PDU"
    #   Remaining Lifetime  2 octets, "Number of seconds before LSP
    #                       considered expired"
    #   LSP ID              ID Length + 2 octets: Source ID, Pseudonode ID,
    #                       LSP Number
    #   Sequence Number     4 octets
    #   Checksum            2 octets, "of contents of LSP from Source ID to
    #                       end"
    #   P/ATT/LSPDBOL/IS Type  1 octet, see FLAGS
    #
    # Three computed fields, each replayed when parsed and recomputed once
    # the octets it describes move: the Length Indicator and the PDU
    # Length, as in every layout, and the Checksum. The Checksum has its own
    # retained input, the checksum span with the Checksum zeroed, because it
    # covers different octets. RFC 1142 clause 7.3.11: "computed over all
    # fields in the LSP which appear after the Remaining Lifetime field".
    # So an edit to the common header or the Remaining Lifetime leaves it
    # alone, and an edit inside the LSP ID or any TLV does not. CLAUDE.md,
    # "One retained input per calculation".
    #
    # Remaining Lifetime is aged in transit, so it is outside the checksum
    # and also outside what decides whether the lengths are replayed:
    # aging a capture keeps whatever lengths it arrived with.
    class Lsp < Layout
      LEVEL_TYPES = { 1 => 18, 2 => 20 }.freeze

      # The flags octet, RFC 1142 clause 9.8, with bit 1 the least
      # significant (clause 9.1): "P - Bit 8"; "ATT - Bits 7-4", with "Bit 4
      # - the Default Metric", "Bit 5 - the Delay Metric", "Bit 6 - the
      # Expense Metric", "Bit 7 - the Error Metric"; "LSPDBOL Bit 3"; "IS
      # Type Bits 1 and 2". The four ATT bits are four fields, one per
      # metric, not one "attached bit".
      PARTITION = 0x80
      ATTACHED = { error: 0x40, expense: 0x20, delay: 0x10, default: 0x08 }.freeze
      OVERLOAD = 0x04
      IS_TYPE = 0x03

      attr_accessor :lifetime, :sequence, :flags
      attr_reader :lsp_id

      class << self
        def fixed_length(id_width)
          2 + 2 + id_width + 2 + 4 + 2 + 1
        end

        def declared_pdu_length(octets)
          octets.byteslice(COMMON_HEADER, 2).unpack1("n")
        end

        # Where the checksum span starts in the PDU: the LSP ID, right after
        # the PDU Length and the Remaining Lifetime.
        def span_start
          COMMON_HEADER + 4
        end

        # Where the Checksum sits inside the span: after the LSP ID and the
        # Sequence Number.
        def checksum_offset(id_width)
          id_width + 2 + 4
        end
      end

      def level
        LEVEL_TYPES.key(type)
      end

      def lsp_id=(value)
        @lsp_id = value.is_a?(Octets) ? value.b : Pdu.dotted_octets(value.to_s.tr("-", "."))
      end

      # The LSP ID as routers print it, "1921.6800.1001.00-00": the System
      # ID in groups of four hex digits, the pseudonode octet after a dot
      # and the LSP Number after a hyphen. A convention with no clause
      # behind it. new accepts it back.
      def lsp_id_s
        hex = @lsp_id.unpack1("H*")
        system = hex[0...-4].scan(/.{1,4}/)
        "#{(system + [hex[-4, 2]]).join('.')}-#{hex[-2, 2]}"
      end

      def partition?
        @flags & PARTITION != 0
      end

      # The metrics the ATT bits say this system is attached by, in the
      # clause's order from bit 7 down.
      def attached
        ATTACHED.select { |_, mask| @flags & mask != 0 }.keys
      end

      def overload?
        @flags & OVERLOAD != 0
      end

      # 1 for a Level 1 system and 3 for Level 2; 0 and 2 are "Unused
      # value", and are carried like any other.
      def is_type
        @flags & IS_TYPE
      end

      # The checksum this LSP encodes with: the one it arrived with if
      # nothing it covers has moved, else the one computed now.
      def checksum
        encode.byteslice(checksum_at, 2).unpack1("n")
      end

      # True when the LSP was parsed and encode will replay the checksum it
      # arrived with, because nothing in the checksum span has changed.
      def checksum_preserved?
        return false if @declared_checksum.nil?

        checksum_input(super_encode) == @retained_checksum_input
      end

      # True when the checksum this LSP encodes with checks out: both
      # running sums over the span are zero. A receiver's test, and the one
      # that lets a test show a capture's wrong checksum is replayed wrong.
      def checksum_ok?
        ISIS.fletcher_ok?(encode.byteslice(self.class.span_start..))
      end

      def encode
        octets = super_encode
        value = checksum_preserved? ? @declared_checksum : compute_checksum(octets)
        octets[checksum_at, 2] = value
        octets
      end

      def recompute!
        @declared_checksum = nil
        @retained_checksum_input = nil
        super
      end

      def to_hash
        h = @header.to_hash.merge(lsp_id: lsp_id_s, lifetime: @lifetime, sequence: @sequence, is_type: is_type)
        h[:partition] = true if partition?
        h[:attached] = attached unless attached.empty?
        h[:overload] = true if overload?
        h[:tlvs] = @tlvs.to_hash[:tlvs]
        h[:tail] = @tlvs.tail.unpack1("H*") unless @tlvs.tail.empty?
        h
      end

      def to_s
        flags = [("P" if partition?), ("ATT #{attached.join(',')}" unless attached.empty?), ("OL" if overload?)].compact
        "L#{level || '?'} LSP #{lsp_id_s}, sequence #{format('0x%08x', @sequence)}, lifetime #{@lifetime}, " \
          "checksum #{format('0x%04x', checksum)}, IS type #{is_type}#{flags.empty? ? '' : ", #{flags.join(' ')}"}, " \
          "#{@tlvs.size} TLVs"
      end

      private

      # The layout's encode: lengths computed or replayed, and the Checksum
      # field as it stands in the fixed header, zero until encode fills it.
      def super_encode
        Layout.instance_method(:encode).bind_call(self)
      end

      def checksum_at
        self.class.span_start + self.class.checksum_offset(@header.id_width)
      end

      # The checksum span with the Checksum zeroed: what the checksum is a
      # function of, and what decides whether a parsed one still holds.
      def checksum_input(octets)
        span = octets.byteslice(self.class.span_start..).b
        offset = self.class.checksum_offset(@header.id_width)
        span[offset, 2] = "\x00\x00".b if span.bytesize >= offset + 2
        span
      end

      def compute_checksum(octets)
        ISIS.fletcher(checksum_input(octets), self.class.checksum_offset(@header.id_width))
      end

      # The lengths are replayed until something other than the Remaining
      # Lifetime and the Checksum moves. Both are zeroed here, so aging an
      # LSP or recomputing its checksum does not count as an edit.
      def normalized
        out = super
        out[COMMON_HEADER + 2, 2] = "\x00\x00".b
        out[checksum_at, 2] = "\x00\x00".b
        out
      end

      def encode_fixed(pdu_length)
        [pdu_length, @lifetime].pack("nn") + @lsp_id + [@sequence].pack("N") + "\x00\x00".b + [@flags].pack("C")
      end

      def parse(octets)
        extent = [self.class.declared_pdu_length(octets), octets.bytesize].min
        raw = octets.byteslice(0, extent).b
        super
        @retained_checksum_input = checksum_input(raw)
        @declared_checksum = raw.byteslice(checksum_at, 2)
      end

      def parse_fixed(fixed)
        width = fixed.bytesize - 13
        _pdu_length, @lifetime = fixed.unpack("nn")
        @lsp_id = fixed.byteslice(4, width + 2).b
        @sequence = fixed.byteslice(6 + width, 4).unpack1("N")
        @flags = fixed.getbyte(12 + width)
      end

      # Lsp.new(level: 1, lsp_id: "1921.6800.1001.00-00", lifetime: 1200,
      #         sequence: 7, tlvs: [...])
      #
      # Flags default to an ordinary system of that level: IS type 1 for
      # Level 1 and 3 for Level 2, no ATT, no overload, no partition
      # repair. The LSP ID's width, less its two trailing octets, sets the
      # ID Length.
      def from_fields(level:, lsp_id:, lifetime:, sequence:, tlvs: [], partition: false, attached: [],
                      overload: false, is_type: nil, max_area_addresses: 0)
        type = LEVEL_TYPES.fetch(level) { raise ArgumentError, "LSP level is 1 or 2, not #{level.inspect}" }
        self.lsp_id = lsp_id
        width = @lsp_id.bytesize - 2
        raise ArgumentError, "an LSP ID needs a pseudonode and an LSP Number octet" if width.negative?

        @lifetime = field(lifetime, 0xffff, "remaining lifetime")
        @sequence = field(sequence, 0xffff_ffff, "sequence number")
        @flags = flags_octet(partition, attached, overload, is_type || (level == 1 ? 1 : 3))
        @header = Header.new(type: type, id_length: Pdu.id_length_for(width), max_area_addresses: max_area_addresses)
        @tlvs = tlvs.is_a?(Tlv::List) ? tlvs : Tlv::List.new(tlvs)
        recompute!
      end

      def from_hash(hash)
        from_fields(level: hash.fetch(:type) == :l2_lsp ? 2 : 1, lsp_id: hash.fetch(:lsp_id),
                    lifetime: hash.fetch(:lifetime), sequence: hash.fetch(:sequence),
                    partition: hash.fetch(:partition, false), attached: hash.fetch(:attached, []),
                    overload: hash.fetch(:overload, false), is_type: hash.fetch(:is_type),
                    tlvs: Tlv::List.new({ tlvs: hash.fetch(:tlvs, []), tail: hash.fetch(:tail, "") }),
                    max_area_addresses: hash.fetch(:max_area_addresses, 0))
        @header.apply_unusual(hash)
      end

      def flags_octet(partition, attached, overload, is_type)
        octet = field(is_type, IS_TYPE, "IS type")
        octet |= PARTITION if partition
        octet |= OVERLOAD if overload
        Array(attached).each do |metric|
          octet |= ATTACHED.fetch(metric) { raise ArgumentError, "no ATT metric #{metric.inspect}" }
        end
        octet
      end

      def field(value, max, name)
        n = Integer(value)
        raise ArgumentError, "#{name} #{n} does not fit (0 to #{max})" unless (0..max).cover?(n)

        n
      end
    end

    register(18, Lsp)
    register(20, Lsp)
  end
end
