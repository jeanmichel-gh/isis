# frozen_string_literal: true

module ISIS
  class SubTlv
    # A list of Maximum SID Depths, RFC 8491: "one or more pairs of a
    # 1-octet MSD-Type and 1-octet MSD-Value", the length "a multiple of 2
    # octets". The two sub-TLVs below share it and differ in their parent
    # and number. Not registered itself.
    #
    # Pairs are kept in order, a type repeated included: RFC 8491 section
    # 3 leaves which of two copies to use "undefined", which is the
    # receiver's question. An odd octet at the end is a tail.
    class Msd < SubTlv
      # The "IGP MSD-Types" registry: RFC 8491 section 6 for 1, RFC 9352
      # section 11.5 for the four SRv6 types, with section 4's meanings.
      TYPES = {
        1 => "Base MPLS Imposition",
        41 => "SRH Max SL",
        42 => "SRH Max End Pop",
        44 => "SRH Max H.encaps",
        45 => "SRH Max End D"
      }.freeze

      attr_reader :msds, :tail

      # The value for MSD-Type +type+, the first if it came twice, or nil.
      def [](type) = @msds.find { _1.first == type }&.last

      # A list of { type:, value: }. A hash with msds: when something
      # arrived unusual.
      def to_hash
        list = @msds.map { |t, v| { type: t, value: v } }
        return list if @tail.empty? && !unusual_type

        h = { msds: list }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        list = @msds.map { |t, v| "#{TYPES.fetch(t, "type #{t}")} #{v}" }
        note = @tail.empty? ? "" : ", tail of #{@tail.bytesize} octets"
        "#{self.class::NAME} #{list.empty? ? 'none' : list.join(', ')}#{note}"
      end

      private

      def encode_value
        @msds.flatten.pack("C*") + @tail
      end

      def parse(octets)
        value = read_frame(octets)
        whole = value.bytesize / 2 * 2
        @msds = value.byteslice(0, whole).unpack("C*").each_slice(2).to_a
        @tail = value.byteslice(whole..).b
      end

      # NodeMsd.new({ type: 41, value: 3 }, { type: 44, value: 2 }), or
      # one array of them.
      def from_fields(*msds, tail: "")
        msds = msds.first if msds.size == 1 && msds.first.is_a?(Array)
        @msds = msds.map do |m|
          [octet("type", m.fetch(:type)), octet("value", m.fetch(:value))]
        end
        @tail = [tail].pack("H*")
      end

      def octet(name, value)
        v = Integer(value)
        raise ArgumentError, "MSD #{name} #{v} does not fit in one octet" unless (0..255).cover?(v)

        v
      end

      def from_hash(hash)
        return from_fields(hash) unless hash.key?(:msds)

        from_fields(hash.fetch(:msds), tail: hash.fetch(:tail, ""))
        @type = hash[:type]
      end
    end

    # The Node MSD sub-TLV, RFC 8491 section 2: type 23 under TLV 242,
    # "the smallest MSD supported by the node on the set of interfaces
    # configured for use by the advertising IGP instance".
    class NodeMsd < Msd
      TYPE = 23
      NAME = "Node MSD"
    end

    # The Link MSD sub-TLV, RFC 8491 section 3: type 15 in TLV 22 (and 23,
    # 25, 141, 222 and 223, which have no class here), "the MSD of the
    # interface associated with the link". Section 4: "the value of the
    # Link MSD MUST take precedence over the Node MSD".
    class LinkMsd < Msd
      TYPE = 15
      NAME = "Link MSD"
    end

    register_under(Tlv::RouterCapability::TYPE, NodeMsd::TYPE, :node_msd, NodeMsd)
    register_under(Tlv::ExtendedIsReachability::TYPE, LinkMsd::TYPE, :link_msd, LinkMsd)
  end
end
