# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 8, Padding. RFC 1142 clause 9.5: "CODE 8", "LENGTH total length
    # of the value field (may be zero)", "VALUE LENGTH octets of arbitrary
    # value". Hellos carry it to pad the PDU up to a size, which is the
    # hello builder's business; this class is only the TLV.
    #
    # Built from a length, the value is zeros. Parsed, the value is kept as
    # it arrived, since arbitrary means anything.
    class Padding < Tlv
      TYPE = 8

      attr_accessor :pad

      # {length: n} when the value is all zeros, {value: hex} otherwise.
      def to_hash
        h = @pad.count("\x00") == @pad.bytesize ? { length: @pad.bytesize } : { value: @pad.unpack1("H*") }
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        "Padding, #{@pad.bytesize} octets"
      end

      private

      def encode_value
        @pad
      end

      def parse(octets)
        @pad = read_frame(octets)
      end

      # Padding.new(10) for ten zero octets, or Padding.new(value: octets).
      def from_fields(length = 0, value: nil)
        @pad = value ? value.b : ("\x00" * Integer(length)).b
      end

      def from_hash(hash)
        if hash.key?(:value)
          from_fields(value: [hash[:value]].pack("H*"))
        else
          from_fields(hash.fetch(:length, 0))
        end
        @type = hash[:type]
      end
    end

    register(Padding::TYPE, :padding, Padding)
  end
end
