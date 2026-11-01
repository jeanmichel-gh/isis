# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 9, LSP Entries, carried in CSNPs and PSNPs. RFC 1142 clause 9.10:
    # "CODE - 9", "LENGTH - total length of the value field", and a value
    # that is "a list of LSP entries", each of
    #
    #   Remaining Lifetime   2 octets, "Remaining Lifetime of LSP"
    #   LSP ID               ID Length + 2 octets
    #   LSP Sequence Number  4 octets
    #   Checksum             2 octets, "Checksum reported in LSP"
    #
    # The LSP ID is ID Length wide plus two, and nothing in the TLV says so,
    # so the width is a parse-time input. Clause 9.10 also has the entries
    # "sorted into ascending LSPID order"; that is validation's business,
    # so they are kept in the order they came.
    #
    # The checksum here is a field the sender reports, not one this TLV
    # computes, so it is carried and hashed like any other.
    #
    # Octets that do not make a whole entry are kept as a tail.
    class LspEntries < Tlv
      TYPE = 9
      PARSE_INPUTS = [:id_width].freeze

      # One entry. lsp_id is octets; lsp_id_s prints it as routers do.
      Entry = Struct.new(:lifetime, :lsp_id, :sequence, :checksum) do
        def lsp_id_s
          Pdu.lsp_id_s(lsp_id)
        end

        def encode
          [lifetime].pack("n") + lsp_id + [sequence, checksum].pack("Nn")
        end

        def to_hash
          { lifetime: lifetime, lsp_id: lsp_id_s, sequence: sequence, checksum: checksum }
        end

        def to_s
          format("%s seq 0x%08x lifetime %d checksum 0x%04x", lsp_id_s, sequence, lifetime, checksum)
        end
      end

      attr_accessor :entries, :tail

      # A list of entry hashes. A hash only when something arrived unusual.
      def to_hash
        list = @entries.map(&:to_hash)
        return list if @tail.empty? && !unusual_type

        h = { entries: list }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        note = @tail.empty? ? "" : ", tail of #{@tail.bytesize} octets"
        "LSP Entries #{@entries.join('; ')}#{note}"
      end

      private

      def encode_value
        out = ISIS.buffer
        @entries.each { |e| out << e.encode }
        out << @tail
      end

      def parse(octets, id_width: DEFAULT_ID_WIDTH)
        @id_width = id_width
        value = read_frame(octets)
        size = 2 + id_width + 2 + 4 + 2
        whole = value.bytesize - (value.bytesize % size)
        @entries = (0...whole).step(size).map do |i|
          e = value.byteslice(i, size)
          Entry.new(e.unpack1("n"), e.byteslice(2, id_width + 2).b, *e.byteslice(4 + id_width, 6).unpack("Nn"))
        end
        @tail = value.byteslice(whole..).b
      end

      def parse_inputs
        { id_width: @id_width || DEFAULT_ID_WIDTH }
      end

      # LspEntries.new({ lifetime: 1184, lsp_id: "0000.0000.0002.00-00",
      #                  sequence: 2, checksum: 0x6c27 }, ...), or one array
      # of them. An Entry is taken as it is.
      def from_fields(*entries)
        entries = entries.first if entries.size == 1 && entries.first.is_a?(Array)
        @entries = entries.map { |e| entry(e) }
        @tail = "".b
        @id_width = @entries.empty? ? DEFAULT_ID_WIDTH : @entries.first.lsp_id.bytesize - 2
      end

      # A hash with :entries is the unusual form. A single entry hash is
      # field values, since Node hands any Hash to from_hash.
      def from_hash(hash)
        return from_fields(hash) unless hash.key?(:entries)

        from_fields(hash.fetch(:entries))
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end

      def entry(e)
        return e if e.is_a?(Entry)

        Entry.new(field(e.fetch(:lifetime), 0xffff, "remaining lifetime"), Pdu.lsp_id_octets(e.fetch(:lsp_id)),
                  field(e.fetch(:sequence), 0xffff_ffff, "sequence number"),
                  field(e.fetch(:checksum), 0xffff, "checksum"))
      end

      def field(value, max, name)
        n = Integer(value)
        raise ArgumentError, "#{name} #{n} does not fit (0 to #{max})" unless (0..max).cover?(n)

        n
      end
    end

    register(LspEntries::TYPE, :lsp_entries, LspEntries)
  end
end
