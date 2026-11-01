# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 240, Point-to-Point Three-Way Adjacency. RFC 5303 section 3.1:
    # "Type - 0xF0 (decimal 240)", "Length - total length of the value
    # field (1 to 17 octets)", and four fields in order:
    #
    #   Adjacency Three-Way State           1 octet: 0 Up, 1 Initializing,
    #                                       2 Down
    #   Extended Local Circuit ID           4 octets
    #   Neighbor System ID                  ID Length octets
    #   Neighbor Extended Local Circuit ID  4 octets
    #
    # Only the state is mandatory; section 3.2 has the neighbour fields sent
    # once the neighbour is known. So the fields are read in order and each
    # is present only if the octets for it arrived. The Neighbor System ID
    # is as wide as the PDU's ID Length says, which is why this class takes
    # id_width at parse time: the TLV's own length cannot settle it, since
    # 11 octets could be a six octet ID alone or a two octet ID with the
    # circuit ID after it.
    #
    # A state outside 0 to 2 is kept as its number. RFC 5303 section 3.2
    # discards such a PDU, which is the receive policy's decision, not the
    # codec's. Octets after the last whole field are kept as a tail.
    class ThreeWayAdjacency < Tlv
      TYPE = 240
      PARSE_INPUTS = [:id_width].freeze
      STATES = { 0 => :up, 1 => :initializing, 2 => :down }.freeze
      NUMBERS = STATES.invert.freeze

      attr_accessor :extended_circuit_id, :neighbor_extended_circuit_id, :tail
      attr_reader :state_number, :neighbor_system_id

      # :up, :initializing or :down, or the number when it is none of them.
      def state
        STATES.fetch(@state_number, @state_number)
      end

      def state=(value)
        @state_number = state_number_for(value)
      end

      # The Neighbor System ID as octets, or nil when it was not sent.
      # Accepts dotted hex, "1921.6800.1001", or octets.
      def neighbor_system_id=(value)
        @neighbor_system_id = value.nil? ? nil : system_id_octets(value)
      end

      def to_hash
        h = { state: state }
        h[:extended_circuit_id] = @extended_circuit_id if @extended_circuit_id
        h[:neighbor_system_id] = dotted(@neighbor_system_id) if @neighbor_system_id
        h[:neighbor_extended_circuit_id] = @neighbor_extended_circuit_id if @neighbor_extended_circuit_id
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        parts = ["Three-Way Adjacency #{state}"]
        parts << "circuit #{@extended_circuit_id}" if @extended_circuit_id
        parts << "neighbor #{dotted(@neighbor_system_id)}" if @neighbor_system_id
        parts << "neighbor circuit #{@neighbor_extended_circuit_id}" if @neighbor_extended_circuit_id
        parts << "tail of #{@tail.bytesize} octets" unless @tail.empty?
        parts.join(", ")
      end

      private

      def encode_value
        out = ISIS.buffer
        out << [@state_number].pack("C") unless @state_number.nil?
        out << [@extended_circuit_id].pack("N") if @extended_circuit_id
        out << @neighbor_system_id if @neighbor_system_id
        out << [@neighbor_extended_circuit_id].pack("N") if @neighbor_extended_circuit_id
        out << @tail
      end

      def parse(octets, id_width: DEFAULT_ID_WIDTH)
        value = read_frame(octets)
        @id_width = id_width
        @state_number = @extended_circuit_id = @neighbor_system_id = @neighbor_extended_circuit_id = nil
        i = 0
        if value.bytesize >= 1
          @state_number = value.getbyte(0)
          i = 1
        end
        if value.bytesize >= i + 4
          @extended_circuit_id = value.byteslice(i, 4).unpack1("N")
          i += 4
        end
        if value.bytesize > i && value.bytesize >= i + id_width
          @neighbor_system_id = value.byteslice(i, id_width).b
          i += id_width
        end
        if @neighbor_system_id && value.bytesize >= i + 4
          @neighbor_extended_circuit_id = value.byteslice(i, 4).unpack1("N")
          i += 4
        end
        @tail = value.byteslice(i..).b
      end

      # A copy reads its own encoding back with the width it was read with,
      # or the width of the Neighbor System ID it was built with.
      def parse_inputs
        { id_width: @id_width || @neighbor_system_id&.bytesize || DEFAULT_ID_WIDTH }
      end

      # ThreeWayAdjacency.new(:down, extended_circuit_id: 1), and with
      # neighbor_system_id: and neighbor_extended_circuit_id: once known.
      def from_fields(state = :down, extended_circuit_id: nil, neighbor_system_id: nil,
                      neighbor_extended_circuit_id: nil)
        @state_number = state_number_for(state)
        @extended_circuit_id = circuit_id(extended_circuit_id)
        self.neighbor_system_id = neighbor_system_id
        @neighbor_extended_circuit_id = circuit_id(neighbor_extended_circuit_id)
        @tail = "".b
      end

      def from_hash(hash)
        from_fields(hash.fetch(:state),
                    extended_circuit_id: hash[:extended_circuit_id],
                    neighbor_system_id: hash[:neighbor_system_id],
                    neighbor_extended_circuit_id: hash[:neighbor_extended_circuit_id])
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end

      def state_number_for(value)
        n = value.is_a?(Symbol) ? NUMBERS.fetch(value) { raise ArgumentError, "no three-way state #{value.inspect}" } : Integer(value)
        raise ArgumentError, "three-way state #{n} does not fit in one octet" unless (0..255).cover?(n)

        n
      end

      def circuit_id(value)
        return nil if value.nil?

        n = Integer(value)
        raise ArgumentError, "extended circuit ID #{n} does not fit in four octets" unless (0..0xffff_ffff).cover?(n)

        n
      end

      def system_id_octets(value)
        return value.b if value.is_a?(Octets)

        hex = value.to_s.delete(".")
        raise ArgumentError, "not dotted hex: #{value.inspect}" unless hex.match?(/\A(\h\h)+\z/)

        [hex].pack("H*").b
      end

      # Groups of four hex digits, "1921.6800.1001": the form routers print
      # a System ID in. A convention, with no clause behind it.
      def dotted(octets)
        octets.unpack1("H*").scan(/.{1,4}/).join(".")
      end
    end

    register(ThreeWayAdjacency::TYPE, :three_way_adjacency, ThreeWayAdjacency)
  end
end
