# frozen_string_literal: true

module ISIS
  class Pdu
    # The Reserved/Circuit Type octet, the same field in all three hellos.
    # RFC 1142 clauses 9.5, 9.6 and 9.7: "Most significant 6 bits reserved
    # (Transmitted as zero, ignored on receipt)", and bits 1 and 2: 0 a
    # "reserved value (if specified the entire PDU shall be ignored)", 1
    # Level 1 only, 2 Level 2 only, 3 both.
    #
    # Ignoring a PDU is the receive policy's call, so 0 is carried like any
    # other value, and reserved bits that arrived set are kept and echoed.
    # This is a field the hellos share, not a base class: the LAN and point
    # to point hellos are different layouts. CLAUDE.md, "Nine PDU types,
    # five layouts".
    #
    # The including class keeps the octet in @circuit_octet.
    module CircuitType
      MASK = 0x03
      RESERVED_MASK = 0xfc
      TYPES = { 1 => :l1, 2 => :l2, 3 => :l1l2 }.freeze
      NUMBERS = TYPES.invert.freeze

      # :l1, :l2 or :l1l2, or the number when it is 0.
      def circuit_type
        n = @circuit_octet & MASK
        TYPES.fetch(n, n)
      end

      def circuit_type=(value)
        @circuit_octet = (@circuit_octet & RESERVED_MASK) | circuit_type_number(value)
      end

      # The six reserved bits of the Circuit Type octet, as they arrived.
      def circuit_reserved_bits
        @circuit_octet & RESERVED_MASK
      end

      private

      def circuit_type_number(value)
        n = value.is_a?(Symbol) ? NUMBERS.fetch(value) { raise ArgumentError, "no circuit type #{value.inspect}" } : Integer(value)
        raise ArgumentError, "circuit type #{n} does not fit in two bits" unless (0..3).cover?(n)

        n
      end

      # The reserved bits a hash carried, put back after the fields.
      def apply_circuit_bits(hash)
        @circuit_octet |= hash.fetch(:circuit_bits, 0) & RESERVED_MASK
      end

      def field(value, max, name)
        n = Integer(value)
        raise ArgumentError, "#{name} #{n} does not fit (0 to #{max})" unless (0..max).cover?(n)

        n
      end
    end
  end
end
