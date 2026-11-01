# frozen_string_literal: true

module ISIS
  class Pdu
    # The Partial Sequence Numbers PDU, one layout for both levels. The
    # level lives in the PDU type, 26 for Level 1 and 27 for Level 2.
    #
    # Fixed header after the common header, RFC 1142 clause 9.12 (and 9.13
    # for Level 2), agreeing with FRR (isisd/isis_pdu.h, ISIS_PSNP_HDRLEN 9):
    #
    #   PDU Length  2 octets, the length of the whole PDU
    #   Source ID   ID Length + 1 octets: "the system ID of Intermediate
    #               system (with zero Circuit ID)"
    #
    # Its LSP Entries are TLV 9, Tlv::LspEntries.
    class Psnp < Layout
      LEVEL_TYPES = { 1 => 26, 2 => 27 }.freeze

      attr_accessor :source_id

      def self.fixed_length(id_width)
        2 + id_width + 1
      end

      def self.declared_pdu_length(octets)
        octets.byteslice(COMMON_HEADER, 2).unpack1("n")
      end

      def level
        LEVEL_TYPES.key(type)
      end

      # The Source ID as dotted hex: the System ID in groups of four digits,
      # then the circuit octet, "1921.6800.1001.00". The form is a
      # convention copied from router output, with no clause behind it.
      def source_id_s
        hex = @source_id.unpack1("H*")
        (hex[0...-2].scan(/.{1,4}/) + [hex[-2..]]).compact.join(".")
      end

      def to_hash
        h = @header.to_hash.merge(source_id: source_id_s)
        h[:tlvs] = @tlvs.to_hash[:tlvs]
        h[:tail] = @tlvs.tail.unpack1("H*") unless @tlvs.tail.empty?
        h
      end

      def to_s
        "L#{level || '?'} PSNP from #{source_id_s}, #{@tlvs.size} TLVs"
      end

      private

      def encode_fixed(pdu_length)
        [pdu_length].pack("n") + @source_id
      end

      def parse_fixed(fixed)
        @source_id = fixed.byteslice(2..).b
      end

      # Psnp.new(level: 1, source_id: "1921.6800.1001.00", tlvs: [...])
      #
      # The Source ID's width sets the ID Length octet: six octets of
      # System ID writes 0, the default.
      def from_fields(level:, source_id:, tlvs: [], max_area_addresses: 0)
        type = LEVEL_TYPES.fetch(level) { raise ArgumentError, "PSNP level is 1 or 2, not #{level.inspect}" }
        @source_id = Pdu.dotted_octets(source_id)
        width = @source_id.bytesize - 1
        raise ArgumentError, "a Source ID needs a circuit octet" if width.negative?

        @header = Header.new(type: type, id_length: Pdu.id_length_for(width), max_area_addresses: max_area_addresses)
        @tlvs = tlvs.is_a?(Tlv::List) ? tlvs : Tlv::List.new(tlvs)
        recompute!
      end

      def from_hash(hash)
        from_fields(level: hash.fetch(:type) == :l2_psnp ? 2 : 1, source_id: hash.fetch(:source_id),
                    tlvs: Tlv::List.new({ tlvs: hash.fetch(:tlvs, []), tail: hash.fetch(:tail, "") }),
                    max_area_addresses: hash.fetch(:max_area_addresses, 0))
        @header.apply_unusual(hash)
      end
    end

    register(26, Psnp)
    register(27, Psnp)
  end
end
