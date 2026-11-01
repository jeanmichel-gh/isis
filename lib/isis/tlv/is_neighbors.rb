# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 6, IS Neighbours, carried in LAN hellos. RFC 1142 clause 9.5:
    # "CODE - 6", "LENGTH - total length of the value field", each value
    # entry a "LAN Address - 6 octet MAC Address of Intermediate System
    # neighbour". The set is the systems "from which Level 1 IIH PDUs have
    # been heard", and the option "can occur multiple times".
    #
    # The entries are MAC addresses of the link, not System IDs, so ID
    # Length does not touch them and this class takes no id_width. TLV 2,
    # with a nearly identical name, is the one whose entries are System ID
    # based.
    #
    # Octets that do not make a whole address are kept as a tail.
    class IsNeighbors < Tlv
      TYPE = 6
      LAN_ADDRESS = 6

      attr_accessor :neighbors, :tail

      # A list: ["00:00:00:00:00:02"]. A hash only when something arrived
      # unusual.
      def to_hash
        list = @neighbors.map(&:to_s)
        return list if @tail.empty? && !unusual_type

        h = { neighbors: list }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        note = @tail.empty? ? "" : ", tail of #{@tail.bytesize} octets"
        "IS Neighbors #{@neighbors.join(', ')}#{note}"
      end

      private

      def encode_value
        out = ISIS.buffer
        @neighbors.each { |m| out << m.encode }
        out << @tail
      end

      def parse(octets)
        value = read_frame(octets)
        whole = value.bytesize - (value.bytesize % LAN_ADDRESS)
        @neighbors = (0...whole).step(LAN_ADDRESS).map do |i|
          Datalink::MAC.from_bytes(value.byteslice(i, LAN_ADDRESS))
        end
        @tail = value.byteslice(whole..).b
      end

      # IsNeighbors.new("00:00:00:00:00:02", "00:00:00:00:00:03"), or one
      # array. A Datalink::MAC is taken as it is.
      def from_fields(*neighbors)
        neighbors = neighbors.first if neighbors.size == 1 && neighbors.first.is_a?(Array)
        @neighbors = neighbors.map { |n| Datalink::MAC.new(n) }
        @tail = "".b
      end

      def from_hash(hash)
        from_fields(hash.fetch(:neighbors))
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end
    end

    register(IsNeighbors::TYPE, :is_neighbors, IsNeighbors)
  end
end
