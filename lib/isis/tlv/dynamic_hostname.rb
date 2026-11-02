# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 137, Dynamic Hostname. RFC 5301 section 3: "The Dynamic hostname
    # TLV is defined here as TLV type 137", its value "a string of 1 to 255
    # bytes", "encoded in 7-bit ASCII". It may sit in any LSP Number of a
    # non-pseudonode LSP, and "If this TLV is present in a pseudonode LSP,
    # then it SHOULD NOT be interpreted as the DNS hostname of the router."
    #
    # The name is kept as the octets it is, so a name that is empty or not
    # ASCII builds and replays: that is validation's business, not this
    # class's.
    class DynamicHostname < Tlv
      TYPE = 137

      # The name, as binary octets.
      attr_reader :name

      def name=(name)
        @name = name.to_s.b
      end

      # The name, or { hostname:, type: } under an unusual type.
      def to_hash
        unusual_type ? { hostname: @name, type: unusual_type } : @name
      end

      def to_s
        "Hostname #{@name.dump[1..-2]}"
      end

      private

      def encode_value
        @name
      end

      def parse(octets)
        @name = read_frame(octets).b
      end

      # DynamicHostname.new("r1").
      def from_fields(name)
        self.name = name
      end

      def from_hash(hash)
        from_fields(hash.fetch(:hostname))
        @type = hash[:type]
      end
    end

    register(DynamicHostname::TYPE, :dynamic_hostname, DynamicHostname)
  end
end
