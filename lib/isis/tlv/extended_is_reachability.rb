# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 22, Extended IS Reachability. RFC 5305 section 3. Each entry is
    #
    #   Neighbor ID       "7 octets of system ID and pseudonode number"
    #   Metric            "3 octets of default metric"
    #   Sub-TLV length    "1 octet of length of sub-TLVs", always written,
    #                     zero when there are none, so a bare entry is 11
    #                     octets
    #   Sub-TLVs          "0-244 octets of sub-TLVs"
    #
    # The neighbor ID is seven octets in the RFC's own words, not ID Length
    # plus one, so this class does not take id_width.
    #
    # Unlike TLV 135, the sub-TLV length is written whatever the list holds.
    # CLAUDE.md, "Sub-TLV framing belongs to the parent TLV".
    #
    # Octets that do not make a whole entry, a sub-TLV length that runs past
    # the value included, are kept as a tail.
    class ExtendedIsReachability < Tlv
      TYPE = 22
      NEIGHBOR = 7
      # Section 3: a link "advertised with the maximum link metric (2^24 -
      # 1)" "MUST NOT be considered during the normal SPF computation".
      MAX_LINK_METRIC = 0xff_ffff

      # One neighbour. neighbor is the seven octets on the wire; subtlvs is
      # a SubTlv::List, empty when the length octet is zero.
      class Entry
        attr_accessor :neighbor, :metric, :subtlvs

        def initialize(neighbor:, metric:, subtlvs: nil)
          @neighbor = neighbor.b
          @metric = metric
          @subtlvs = subtlvs || SubTlv::List.new(TYPE)
        end

        # The neighbour as routers print it, "0000.0000.0001.00": the System
        # ID in groups of four hex digits and the pseudonode octet after a
        # dot. A convention, like the LSP ID's, and Entry.neighbor_octets
        # reads it back.
        def neighbor_s
          hex = @neighbor.unpack1("H*")
          (hex[0...-2].scan(/.{1,4}/) + [hex[-2, 2]]).join(".")
        end

        def encode
          body = @subtlvs.encode
          out = ISIS.buffer
          out << @neighbor << [@metric].pack("N").byteslice(1, 3) << [body.bytesize].pack("C") << body
        end

        def to_hash
          h = { neighbor: neighbor_s, metric: @metric }
          sub = @subtlvs.to_hash
          h[:subtlvs] = sub[:tlvs] unless sub[:tlvs].empty?
          h[:subtlv_tail] = sub[:tail] if sub[:tail]
          h
        end

        def to_s
          [neighbor_s, "metric #{@metric}", ("#{@subtlvs.size} sub-TLVs" unless @subtlvs.size.zero?)].compact.join(" ")
        end

        def self.neighbor_octets(text)
          octets = Pdu.dotted_octets(text)
          raise ArgumentError, "a neighbor ID is #{NEIGHBOR} octets: #{text.inspect}" unless octets.bytesize == NEIGHBOR

          octets
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
        "Extended IS Reachability #{@entries.join('; ')}#{note}"
      end

      private

      def encode_value
        out = ISIS.buffer
        @entries.each { |e| out << e.encode }
        out << @tail
      end

      def parse(octets)
        value = read_frame(octets)
        @entries = []
        i = 0
        while (entry = read_entry(value, i))
          @entries << entry.first
          i = entry.last
        end
        @tail = value.byteslice(i..).b
      end

      # The entry at +i+ and where the next starts, or nil if what is left
      # is not a whole entry.
      def read_entry(value, i)
        fixed = NEIGHBOR + 3 + 1
        return nil if value.bytesize < i + fixed

        declared = value.getbyte(i + fixed - 1)
        return nil if value.bytesize < i + fixed + declared

        neighbor = value.byteslice(i, NEIGHBOR)
        metric = ("\x00".b + value.byteslice(i + NEIGHBOR, 3)).unpack1("N")
        subtlvs = SubTlv::List.parse_under(TYPE, Octets.new(value.byteslice(i + fixed, declared)))
        [Entry.new(neighbor: neighbor, metric: metric, subtlvs: subtlvs), i + fixed + declared]
      end

      # ExtendedIsReachability.new({ neighbor: "0000.0000.0001.00", metric:
      # 10 }, ...), or one array of them. An Entry is taken as it is.
      def from_fields(*entries)
        entries = entries.first if entries.size == 1 && entries.first.is_a?(Array)
        @entries = entries.map { |e| entry(e) }
        @tail = "".b
      end

      # A hash with :entries is the unusual form; a single entry hash is
      # field values.
      def from_hash(hash)
        return from_fields(hash) unless hash.key?(:entries)

        from_fields(hash.fetch(:entries))
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end

      def entry(e)
        return e if e.is_a?(Entry)

        metric = Integer(e.fetch(:metric))
        raise ArgumentError, "metric #{metric} does not fit in 24 bits" unless (0..MAX_LINK_METRIC).cover?(metric)

        subtlvs = SubTlv::List.new(TYPE, { tlvs: e.fetch(:subtlvs, []), tail: e.fetch(:subtlv_tail, "") })
        Entry.new(neighbor: Entry.neighbor_octets(e.fetch(:neighbor)), metric: metric, subtlvs: subtlvs)
      end
    end

    register(ExtendedIsReachability::TYPE, :extended_is_reachability, ExtendedIsReachability)
  end
end
