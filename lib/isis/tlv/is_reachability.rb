# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 2, IS Reachability, the Intermediate System Neighbours option of
    # an LSP. RFC 1142 clause 9.8: "CODE - 2", "LENGTH - 1 plus a multiple
    # of 11" for six octet IDs, and a value of
    #
    #   Virtual Flag      1 octet: "If equal to 1, this indicates the link
    #                     is really a Level 2 path to repair an area
    #                     partition"
    #   then per neighbour:
    #   Default Metric    1 octet  \
    #   Delay Metric      1 octet   | NarrowMetrics, I/E in all four
    #   Expense Metric    1 octet   |
    #   Error Metric      1 octet  /
    #   Neighbour ID      ID Length + 1 octets: "the first ID Length octets
    #                     are the neighbour's system ID, and the last octet
    #                     is 0", or a pseudonode ID
    #
    # The figure in the supplied text was flattened by extraction, so the
    # order of the fields is from the clause's descriptions and agrees with
    # FRR 8.4's pack_item_oldstyle_reach: the four metrics, then the ID.
    #
    # The Neighbour ID is ID Length wide plus one, so the width is a
    # parse-time input. FRR reads it as seven octets whatever the header
    # says; this class follows the clause.
    #
    # The Virtual Flag is kept as the octet that arrived, whatever its
    # value. A value with no octets at all has no flag, and replays as
    # none. Octets that do not make a whole entry are kept as a tail.
    class IsReachability < Tlv
      TYPE = 2
      PARSE_INPUTS = [:id_width].freeze
      # Clause 9.8: the I/E bit is in each of the four metric octets.
      IE_OCTETS = [0, 1, 2, 3].freeze

      # One neighbour: the four metric octets and the neighbour ID octets.
      class Entry
        attr_accessor :metrics, :neighbor

        def initialize(metrics:, neighbor:)
          @metrics = metrics
          @neighbor = neighbor.b
        end

        # "0000.0000.0001.00": the System ID in groups of four hex digits
        # and the pseudonode octet after a dot. A convention, as for TLV 22.
        def neighbor_s
          hex = @neighbor.unpack1("H*")
          (hex[0...-2].scan(/.{1,4}/) + [hex[-2, 2]]).join(".")
        end

        def encode
          @metrics.octets + @neighbor
        end

        def to_hash
          h = { neighbor: neighbor_s }.merge(@metrics.fields)
          h[:metric_octets] = @metrics.octets.unpack1("H*") unless @metrics.canonical?(IE_OCTETS)
          h
        end

        def to_s
          "#{neighbor_s} #{@metrics}"
        end
      end

      attr_accessor :entries, :virtual_flag, :tail

      # A list of entry hashes, or a hash when the flag is not zero, is
      # missing, or a tail arrived.
      def to_hash
        list = @entries.map(&:to_hash)
        return list if @virtual_flag == 0 && @tail.empty? && !unusual_type

        h = { entries: list, virtual_flag: @virtual_flag }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        flag = @virtual_flag.nil? ? ", no virtual flag" : (@virtual_flag.zero? ? "" : ", virtual flag #{@virtual_flag}")
        note = @tail.empty? ? "" : ", tail of #{@tail.bytesize} octets"
        "IS Reachability #{@entries.join('; ')}#{flag}#{note}"
      end

      private

      def encode_value
        out = ISIS.buffer
        out << [@virtual_flag].pack("C") unless @virtual_flag.nil?
        @entries.each { |e| out << e.encode }
        out << @tail
      end

      def parse(octets, id_width: DEFAULT_ID_WIDTH)
        @id_width = id_width
        value = read_frame(octets)
        @virtual_flag = value.getbyte(0)
        size = 4 + id_width + 1
        @entries = []
        i = 1
        while value.bytesize >= i + size
          @entries << Entry.new(metrics: NarrowMetrics.new(value.byteslice(i, 4)),
                                neighbor: value.byteslice(i + 4, id_width + 1))
          i += size
        end
        @tail = (value.byteslice([i, value.bytesize].min..) || "").b
      end

      def parse_inputs
        { id_width: @id_width || DEFAULT_ID_WIDTH }
      end

      # IsReachability.new({ neighbor: "0000.0000.0002.00", metric: 10 }, ...),
      # or one array of them. A Level 1 system's flag is 0.
      def from_fields(*entries)
        entries = entries.first if entries.size == 1 && entries.first.is_a?(Array)
        @entries = entries.map { |e| entry(e) }
        @virtual_flag = 0
        @tail = "".b
        @id_width = @entries.empty? ? DEFAULT_ID_WIDTH : @entries.first.neighbor.bytesize - 1
      end

      def from_hash(hash)
        return from_fields(hash) unless hash.key?(:entries)

        from_fields(hash.fetch(:entries))
        @virtual_flag = hash.fetch(:virtual_flag, 0)
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end

      def entry(e)
        return e if e.is_a?(Entry)

        metrics =
          if e.key?(:metric_octets)
            NarrowMetrics.new([e.fetch(:metric_octets)].pack("H*"))
          else
            NarrowMetrics.build(**e.slice(:metric, :delay, :expense, :error, :external), ie_octets: IE_OCTETS)
          end
        neighbor = Pdu.dotted_octets(e.fetch(:neighbor))
        raise ArgumentError, "a neighbour ID needs a pseudonode octet: #{e[:neighbor].inspect}" if neighbor.bytesize < 2

        Entry.new(metrics: metrics, neighbor: neighbor)
      end
    end

    register(IsReachability::TYPE, :is_reachability, IsReachability)
  end
end
