# frozen_string_literal: true

module ISIS
  class Pdu
    # The Point-to-Point IS to IS Hello, PDU type 17, RFC 1142 clause 9.7.
    # One PDU type for both levels: the Circuit Type field is the only level
    # information it carries, and it can say "both", which a level argument
    # could not. So this class takes a circuit type and no level.
    #
    # Fixed header after the common header, in the order of the clause's
    # field descriptions, which FRR (isisd/isis_pdu.h, struct
    # isis_p2p_hello_hdr, ISIS_P2PHELLO_HDRLEN 12) and Wireshark
    # (packet-isis-hello.c) both follow:
    #
    #   Reserved/Circuit Type  1 octet: "Most significant 6 bits reserved",
    #                          bits 1 and 2 the circuit type
    #   Source ID              ID Length octets, "the system ID of
    #                          transmitting Intermediate system"
    #   Holding Time           2 octets
    #   PDU Length             2 octets, "Entire length of this PDU"
    #   Local Circuit ID       1 octet
    #
    # The Circuit Type octet is the field all three hellos share, in
    # Pdu::CircuitType.
    #
    # This is not a LAN hello with parts removed, and shares no base with
    # one. CLAUDE.md, "Nine PDU types, five layouts".
    class P2pHello < Layout
      include CircuitType

      TYPE = 17

      attr_accessor :holding_time, :local_circuit_id
      attr_reader :source_id

      class << self
        def fixed_length(id_width)
          1 + id_width + 2 + 2 + 1
        end

        # The PDU Length sits after the Circuit Type, the Source ID and the
        # Holding Time, so where it is depends on the ID Length.
        def declared_pdu_length(octets)
          at = COMMON_HEADER + 1 + Pdu.id_width(octets.getbyte(3) || 0) + 2
          octets.byteslice(at, 2).unpack1("n")
        end
      end

      def source_id=(value)
        @source_id = value.is_a?(Octets) ? value.b : Pdu.dotted_octets(value)
      end

      # The Source ID in groups of four hex digits, "1921.6800.1001". A
      # convention copied from router output, with no clause behind it.
      def source_id_s
        @source_id.unpack1("H*").scan(/.{1,4}/).join(".")
      end

      def to_hash
        h = @header.to_hash.merge(circuit_type: circuit_type, source_id: source_id_s,
                                  holding_time: @holding_time, local_circuit_id: @local_circuit_id)
        h[:circuit_bits] = circuit_reserved_bits unless circuit_reserved_bits.zero?
        h[:tlvs] = @tlvs.to_hash[:tlvs]
        h[:tail] = @tlvs.tail.unpack1("H*") unless @tlvs.tail.empty?
        h
      end

      def to_s
        "P2P hello #{circuit_type} from #{source_id_s}, holding #{@holding_time}, " \
          "circuit #{@local_circuit_id}, #{@tlvs.size} TLVs"
      end

      private

      def encode_fixed(pdu_length)
        [@circuit_octet].pack("C") + @source_id + [@holding_time, pdu_length, @local_circuit_id].pack("nnC")
      end

      def parse_fixed(fixed)
        width = fixed.bytesize - 6
        @circuit_octet = fixed.getbyte(0)
        @source_id = fixed.byteslice(1, width).b
        @holding_time, _pdu_length, @local_circuit_id = fixed.byteslice(1 + width, 5).unpack("nnC")
      end

      # P2pHello.new(circuit_type: :l1l2, source_id: "1921.6800.1001",
      #              holding_time: 30, local_circuit_id: 1, tlvs: [...])
      #
      # The Source ID's width sets the ID Length octet: six octets writes 0,
      # the default.
      def from_fields(circuit_type:, source_id:, holding_time:, local_circuit_id:, tlvs: [],
                      max_area_addresses: 0)
        @circuit_octet = circuit_type_number(circuit_type)
        self.source_id = source_id
        @holding_time = field(holding_time, 0xffff, "holding time")
        @local_circuit_id = field(local_circuit_id, 0xff, "local circuit ID")
        @header = Header.new(type: TYPE, id_length: Pdu.id_length_for(@source_id.bytesize),
                             max_area_addresses: max_area_addresses)
        @tlvs = tlvs.is_a?(Tlv::List) ? tlvs : Tlv::List.new(tlvs)
        recompute!
      end

      def from_hash(hash)
        from_fields(circuit_type: hash.fetch(:circuit_type), source_id: hash.fetch(:source_id),
                    holding_time: hash.fetch(:holding_time), local_circuit_id: hash.fetch(:local_circuit_id),
                    tlvs: Tlv::List.new({ tlvs: hash.fetch(:tlvs, []), tail: hash.fetch(:tail, "") }),
                    max_area_addresses: hash.fetch(:max_area_addresses, 0))
        apply_circuit_bits(hash)
        @header.apply_unusual(hash)
      end
    end

    register(P2pHello::TYPE, P2pHello)
  end
end
