# frozen_string_literal: true

module ISIS
  class Pdu
    # The Complete Sequence Numbers PDU, one layout for both levels. The
    # level lives in the PDU type, 24 for Level 1 (RFC 1142 clause 9.10)
    # and 25 for Level 2 (clause 9.11).
    #
    # Fixed header after the common header, clause 9.10, agreeing with FRR
    # (isisd/isis_pdu.h, ISIS_CSNP_HDRLEN 25):
    #
    #   PDU Length     2 octets, "Entire Length of this PDU"
    #   Source ID      ID Length + 1 octets: "the system ID of Intermediate
    #                  System (with zero Circuit ID) generating this
    #                  Sequence Numbers PDU"
    #   Start LSP ID   ID Length + 2 octets, "the system ID of first LSP in
    #                  the range covered by this" CSNP
    #   End LSP ID     ID Length + 2 octets, the last
    #
    # Its LSP Entries are TLV 9, Tlv::LspEntries.
    class Csnp < Layout
      LEVEL_TYPES = { 1 => 24, 2 => 25 }.freeze

      attr_reader :source_id, :start_lsp_id, :end_lsp_id

      def self.fixed_length(id_width)
        2 + (id_width + 1) + (id_width + 2) * 2
      end

      def self.declared_pdu_length(octets)
        octets.byteslice(COMMON_HEADER, 2).unpack1("n")
      end

      def level
        LEVEL_TYPES.key(type)
      end

      def source_id=(value)
        @source_id = value.is_a?(Octets) ? value.b : Pdu.dotted_octets(value)
      end

      def start_lsp_id=(value)
        @start_lsp_id = value.is_a?(Octets) ? value.b : Pdu.lsp_id_octets(value)
      end

      def end_lsp_id=(value)
        @end_lsp_id = value.is_a?(Octets) ? value.b : Pdu.lsp_id_octets(value)
      end

      # The Source ID as dotted hex, the System ID in groups of four then
      # the circuit octet, "1921.6800.1001.00". A convention copied from
      # router output.
      def source_id_s
        hex = @source_id.unpack1("H*")
        (hex[0...-2].scan(/.{1,4}/) + [hex[-2..]]).compact.join(".")
      end

      def start_lsp_id_s
        Pdu.lsp_id_s(@start_lsp_id)
      end

      def end_lsp_id_s
        Pdu.lsp_id_s(@end_lsp_id)
      end

      # Every LSP entry the CSNP describes, from all its TLV 9s, since the
      # option "may appear multiple times".
      def entries
        @tlvs.select { |t| t.is_a?(Tlv::LspEntries) }.flat_map(&:entries)
      end

      def to_hash
        h = @header.to_hash.merge(source_id: source_id_s, start_lsp_id: start_lsp_id_s, end_lsp_id: end_lsp_id_s)
        h[:tlvs] = @tlvs.to_hash[:tlvs]
        h[:tail] = @tlvs.tail.unpack1("H*") unless @tlvs.tail.empty?
        h
      end

      def to_s
        "L#{level || '?'} CSNP from #{source_id_s}, #{start_lsp_id_s} to #{end_lsp_id_s}, " \
          "#{entries.size} entries"
      end

      private

      def encode_fixed(pdu_length)
        [pdu_length].pack("n") + @source_id + @start_lsp_id + @end_lsp_id
      end

      def parse_fixed(fixed)
        width = (fixed.bytesize - 7) / 3
        @source_id = fixed.byteslice(2, width + 1).b
        @start_lsp_id = fixed.byteslice(3 + width, width + 2).b
        @end_lsp_id = fixed.byteslice(5 + 2 * width, width + 2).b
      end

      # Csnp.new(level: 1, source_id: "1921.6800.1001.00",
      #          start_lsp_id: "0000.0000.0000.00-00",
      #          end_lsp_id: "ffff.ffff.ffff.ff-ff", tlvs: [...])
      #
      # The whole range is the default. The Source ID's width less its
      # circuit octet sets the ID Length, and the two LSP IDs must be one
      # octet longer, since a PDU has one ID Length.
      def from_fields(level:, source_id:, start_lsp_id: nil, end_lsp_id: nil, tlvs: [], max_area_addresses: 0)
        type = LEVEL_TYPES.fetch(level) { raise ArgumentError, "CSNP level is 1 or 2, not #{level.inspect}" }
        self.source_id = source_id
        width = @source_id.bytesize - 1
        raise ArgumentError, "a Source ID needs a circuit octet" if width.negative?

        @start_lsp_id = start_lsp_id ? Pdu.lsp_id_octets(start_lsp_id) : ("\x00".b * (width + 2))
        @end_lsp_id = end_lsp_id ? Pdu.lsp_id_octets(end_lsp_id) : ("\xff".b * (width + 2))
        [@start_lsp_id, @end_lsp_id].each do |id|
          next if id.bytesize == width + 2

          raise ArgumentError, "an LSP ID here is #{width + 2} octets, the Source ID's System ID plus two, " \
                               "not #{id.bytesize}"
        end
        @header = Header.new(type: type, id_length: Pdu.id_length_for(width), max_area_addresses: max_area_addresses)
        @tlvs = tlvs.is_a?(Tlv::List) ? tlvs : Tlv::List.new(tlvs)
        recompute!
      end

      def from_hash(hash)
        from_fields(level: hash.fetch(:type) == :l2_csnp ? 2 : 1, source_id: hash.fetch(:source_id),
                    start_lsp_id: hash.fetch(:start_lsp_id), end_lsp_id: hash.fetch(:end_lsp_id),
                    tlvs: Tlv::List.new({ tlvs: hash.fetch(:tlvs, []), tail: hash.fetch(:tail, "") }),
                    max_area_addresses: hash.fetch(:max_area_addresses, 0))
        @header.apply_unusual(hash)
      end
    end

    register(24, Csnp)
    register(25, Csnp)
  end
end
