# frozen_string_literal: true

module ISIS
  class Pdu
    # The LAN IS to IS Hello, one layout for both levels. The level lives
    # in the PDU type, 15 for Level 1 (RFC 1142 clause 9.5) and 16 for
    # Level 2 (clause 9.6). The Circuit Type field is a second, different
    # fact: which levels the sender runs on this circuit. So this class
    # takes both a level and a circuit type. CLAUDE.md, "The level is not
    # one parameter".
    #
    # Fixed header after the common header, in the order of the clause's
    # field descriptions, which FRR (isisd/isis_pdu.h, struct
    # isis_lan_hello_hdr, ISIS_LANHELLO_HDRLEN 19) and Wireshark
    # (packet-isis-hello.c) both follow:
    #
    #   Reserved/Circuit Type  1 octet, Pdu::CircuitType
    #   Source ID              ID Length octets, "the system ID of
    #                          transmitting Intermediate system"
    #   Holding Time           2 octets
    #   PDU Length             2 octets, "Entire length of this PDU"
    #   Reserved/Priority      1 octet: "Bit 8 reserved (Transmitted as
    #                          zero, ignored on receipt). Bits 1 through 7
    #                          priority for being LAN Level 1 Designated
    #                          Intermediate System"
    #   LAN ID                 ID Length + 1 octets: "the system ID ... of
    #                          the LAN Level 1 Designated Intermediate
    #                          System, plus a low order octet assigned by"
    #                          it
    #
    # Clause 9.5 also notes "In a LAN Level 1 IIH PDU the Circuit Type shall
    # be either 1 or 3". That is validation's business, so any value is
    # built and kept.
    class LanHello < Layout
      include CircuitType

      LEVEL_TYPES = { 1 => 15, 2 => 16 }.freeze
      PRIORITY_MASK = 0x7f
      PRIORITY_RESERVED_MASK = 0x80

      attr_accessor :holding_time
      attr_reader :source_id, :lan_id

      class << self
        def fixed_length(id_width)
          1 + id_width + 2 + 2 + 1 + id_width + 1
        end

        # The PDU Length sits after the Circuit Type, the Source ID and the
        # Holding Time, so where it is depends on the ID Length.
        def declared_pdu_length(octets)
          at = COMMON_HEADER + 1 + Pdu.id_width(octets.getbyte(3) || 0) + 2
          octets.byteslice(at, 2).unpack1("n")
        end
      end

      def level
        LEVEL_TYPES.key(type)
      end

      def priority
        @priority_octet & PRIORITY_MASK
      end

      def priority=(value)
        @priority_octet = (@priority_octet & PRIORITY_RESERVED_MASK) | field(value, PRIORITY_MASK, "priority")
      end

      # Bit 8 of the Priority octet, as it arrived.
      def priority_reserved_bit
        @priority_octet & PRIORITY_RESERVED_MASK
      end

      def source_id=(value)
        @source_id = value.is_a?(Octets) ? value.b : Pdu.dotted_octets(value)
      end

      def lan_id=(value)
        @lan_id = value.is_a?(Octets) ? value.b : Pdu.dotted_octets(value)
      end

      # The Source ID in groups of four hex digits, "1921.6800.1001". A
      # convention copied from router output, with no clause behind it.
      def source_id_s
        @source_id.unpack1("H*").scan(/.{1,4}/).join(".")
      end

      # The LAN ID as the System ID in groups of four, then the low order
      # octet, "1921.6800.1001.01". The same convention.
      def lan_id_s
        hex = @lan_id.unpack1("H*")
        (hex[0...-2].scan(/.{1,4}/) + [hex[-2..]]).compact.join(".")
      end

      # The IS Neighbours the hello lists, from every TLV 6 it carries,
      # since the option "can occur multiple times".
      def neighbors
        @tlvs.select { |t| t.is_a?(Tlv::IsNeighbors) }.flat_map(&:neighbors)
      end

      def to_hash
        h = @header.to_hash.merge(circuit_type: circuit_type, source_id: source_id_s,
                                  holding_time: @holding_time, priority: priority, lan_id: lan_id_s)
        h[:circuit_bits] = circuit_reserved_bits unless circuit_reserved_bits.zero?
        h[:priority_bit] = priority_reserved_bit unless priority_reserved_bit.zero?
        h[:tlvs] = @tlvs.to_hash[:tlvs]
        h[:tail] = @tlvs.tail.unpack1("H*") unless @tlvs.tail.empty?
        h
      end

      def to_s
        "L#{level || '?'} LAN hello #{circuit_type} from #{source_id_s}, holding #{@holding_time}, " \
          "priority #{priority}, LAN ID #{lan_id_s}, #{@tlvs.size} TLVs"
      end

      private

      def encode_fixed(pdu_length)
        [@circuit_octet].pack("C") + @source_id + [@holding_time, pdu_length, @priority_octet].pack("nnC") + @lan_id
      end

      def parse_fixed(fixed)
        width = (fixed.bytesize - 7) / 2
        @circuit_octet = fixed.getbyte(0)
        @source_id = fixed.byteslice(1, width).b
        @holding_time, _pdu_length, @priority_octet = fixed.byteslice(1 + width, 5).unpack("nnC")
        @lan_id = fixed.byteslice(6 + width, width + 1).b
      end

      # LanHello.new(level: 1, circuit_type: :l1, source_id: "1921.6800.1001",
      #              holding_time: 30, priority: 64,
      #              lan_id: "1921.6800.1001.01", tlvs: [...])
      #
      # The Source ID's width sets the ID Length octet, and the LAN ID must
      # be one octet longer, since a PDU has one ID Length.
      def from_fields(level:, circuit_type:, source_id:, holding_time:, priority:, lan_id:, tlvs: [],
                      max_area_addresses: 0)
        type = LEVEL_TYPES.fetch(level) { raise ArgumentError, "LAN hello level is 1 or 2, not #{level.inspect}" }
        @circuit_octet = circuit_type_number(circuit_type)
        self.source_id = source_id
        self.lan_id = lan_id
        unless @lan_id.bytesize == @source_id.bytesize + 1
          raise ArgumentError, "a LAN ID is the System ID width plus one octet: #{@lan_id.bytesize} " \
                               "octets against a #{@source_id.bytesize} octet Source ID"
        end

        @holding_time = field(holding_time, 0xffff, "holding time")
        @priority_octet = field(priority, PRIORITY_MASK, "priority")
        @header = Header.new(type: type, id_length: Pdu.id_length_for(@source_id.bytesize),
                             max_area_addresses: max_area_addresses)
        @tlvs = tlvs.is_a?(Tlv::List) ? tlvs : Tlv::List.new(tlvs)
        recompute!
      end

      def from_hash(hash)
        from_fields(level: hash.fetch(:type) == :l2_lan_hello ? 2 : 1, circuit_type: hash.fetch(:circuit_type),
                    source_id: hash.fetch(:source_id), holding_time: hash.fetch(:holding_time),
                    priority: hash.fetch(:priority), lan_id: hash.fetch(:lan_id),
                    tlvs: Tlv::List.new({ tlvs: hash.fetch(:tlvs, []), tail: hash.fetch(:tail, "") }),
                    max_area_addresses: hash.fetch(:max_area_addresses, 0))
        apply_circuit_bits(hash)
        @priority_octet |= hash.fetch(:priority_bit, 0) & PRIORITY_RESERVED_MASK
        @header.apply_unusual(hash)
      end
    end

    register(15, LanHello)
    register(16, LanHello)
  end
end
