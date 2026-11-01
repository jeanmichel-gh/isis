# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 129, Protocols Supported. RFC 1195 section 5.3.1: "CODE - 129",
    # "LENGTH - total length of the value field (one octet per protocol",
    # and a value of "one octet NLPID (as assigned by ISO/TR 9577)" per
    # protocol.
    #
    # RFC 1195 does not give the numbers. The names below are second hand:
    # 0xcc for IPv4 and 0x81 for CLNP are the ISO/TR 9577 values as
    # Wireshark and FRR use them, and 0x8e for IPv6 is RFC 5308's, not read
    # here. A number with no name is kept as a number.
    class ProtocolsSupported < Tlv
      TYPE = 129
      NAMES = { 0xcc => :ipv4, 0x8e => :ipv6, 0x81 => :clnp }.freeze
      NUMBERS = NAMES.invert.freeze

      # NLPID numbers, in the order they arrived.
      attr_accessor :nlpids

      # [:ipv4, :ipv6], with a bare number for an NLPID that has no name.
      def to_hash
        list = @nlpids.map { |n| NAMES.fetch(n, n) }
        unusual_type ? { protocols: list, type: unusual_type } : list
      end

      def to_s
        "Protocols Supported #{to_hash_list.join(', ')}"
      end

      private

      def to_hash_list
        @nlpids.map { |n| NAMES.fetch(n) { format("0x%02x", n) } }
      end

      def encode_value
        @nlpids.pack("C*").b
      end

      def parse(octets)
        @nlpids = read_frame(octets).bytes
      end

      # ProtocolsSupported.new(:ipv4, :ipv6), or numbers, or one array.
      def from_fields(*protocols)
        protocols = protocols.first if protocols.size == 1 && protocols.first.is_a?(Array)
        @nlpids = protocols.map { |p| nlpid(p) }
      end

      def from_hash(hash)
        from_fields(hash.fetch(:protocols))
        @type = hash[:type]
      end

      def nlpid(protocol)
        n = protocol.is_a?(Symbol) ? NUMBERS.fetch(protocol) { raise ArgumentError, "no NLPID named #{protocol.inspect}" } : Integer(protocol)
        raise ArgumentError, "NLPID #{n} does not fit in one octet" unless (0..255).cover?(n)

        n
      end
    end

    register(ProtocolsSupported::TYPE, :protocols_supported, ProtocolsSupported)
  end
end
