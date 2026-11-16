# frozen_string_literal: true

module ISIS
  class SubTlv
    # The SID/Label sub-TLV, RFC 8667 section 2.3: type 1, "If the length
    # is set to 3, then the 20 rightmost bits represent an MPLS label. If
    # the length is set to 4, then the value is a 32-bit index." It sits in
    # the SR-Capabilities and SR Local Block descriptors of TLV 242, and
    # its codepoint is in the registry "sub-TLVs for TLV 149 and 150"
    # (section 2.3), so it is registered under 149 here, and those
    # descriptors read it there. TLVs 149 and 150 have no class.
    class SidLabel < SubTlv
      include SidField

      TYPE = 1
      REGISTRY = 149

      def to_hash
        h = sid_hash({})
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        "SID/Label #{sid_text}"
      end

      private

      def encode_value
        sid_octets + @tail
      end

      def parse(octets)
        read_sid(read_frame(octets), true)
      end

      # SidLabel.new(label: 16000) or SidLabel.new(index: 1).
      def from_fields(**fields)
        sid_from(**fields)
      end

      def from_hash(hash)
        sid_from(**hash.slice(:index, :label, :label_high, :tail))
        @type = hash[:type]
      end
    end

    # The layout two sub-TLVs of TLV 242 share, RFC 8667 sections 3.1 and
    # 3.3: one octet of flags, then "One or more ... Descriptor entries",
    # each a 3-octet Range and a SID/Label sub-TLV (section 2.3) holding
    # the block's first label. "The range value MUST be higher than 0",
    # and the order of the descriptors is the order of the block.
    #
    # A descriptor's SID/Label is read from the registry under 149, where
    # section 2.3 puts its codepoint. Octets too few for a whole descriptor
    # are a tail.
    class LabelBlock < SubTlv
      include FlagOctet

      # One range: its size, and the SID/Label sub-TLV after it.
      Descriptor = Struct.new(:range, :sid_label) do
        def first_label
          l = sid_label.respond_to?(:label) ? sid_label.label : nil
          l && (l & 0xfffff)
        end

        def encode
          [range].pack("N").byteslice(1, 3) + sid_label.encode
        end

        # { range:, label: } when the sub-TLV is a plain 3-octet label;
        # otherwise the sub-TLV's own hash under its key.
        def to_hash
          h = { range: range }
          if sid_label.is_a?(SidLabel) && sid_label.to_hash.keys == [:label]
            h.merge(sid_label.to_hash)
          else
            h.merge(sid_label: { sid_label.class.hash_key => sid_label.to_hash })
          end
        end
      end

      attr_reader :flags, :descriptors, :tail

      # The block's labels, as [first, last] per descriptor, in order:
      # RFC 8660 section 2.3's [Ll(i), Lh(i)].
      def ranges
        @descriptors.filter_map { |d| [d.first_label, d.first_label + d.range - 1] if d.first_label }
      end

      # { short: "" } for a value with no flags octet at all.
      def to_hash
        return { short: "" }.merge(unusual_type ? { type: unusual_type } : {}) if @flags.nil?

        h = flags_hash({})
        h[:descriptors] = @descriptors.map(&:to_hash)
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        return "#{self.class::NAME}, empty" if @flags.nil?

        f = flag_letters.empty? ? "" : " flags #{flag_letters.join}"
        blocks = ranges.map { |lo, hi| "#{lo}-#{hi}" }
        "#{self.class::NAME} #{blocks.empty? ? 'empty' : blocks.join(', ')}#{f}"
      end

      private

      def encode_value
        return @tail if @flags.nil?

        out = ISIS.buffer
        out << [@flags].pack("C")
        @descriptors.each { |d| out << d.encode }
        out << @tail
      end

      def parse(octets)
        value = read_frame(octets)
        @descriptors = []
        if value.empty?
          @flags = nil
          @tail = "".b
          return
        end
        @flags = value.getbyte(0)
        rest = Octets.new(value.byteslice(1..))
        # A descriptor is read only when it is all there: its range, and its
        # sub-TLV to the end of its declared length. A cut one is the tail.
        while rest.bytesize >= 3 + Tlv::HEADER && rest.bytesize >= 3 + Tlv::HEADER + rest.getbyte(4)
          range = ("\x00".b + rest.byteslice(0, 3)).unpack1("N")
          inner = Octets.new(rest.byteslice(3..))
          sub = SubTlv.factory_under(SidLabel::REGISTRY, inner, boundary: inner.bytesize)
          @descriptors << Descriptor.new(range, sub)
          rest = inner
        end
        @tail = rest.b
      end

      # SrCapabilities.new(flags: %w[I], descriptors: [{ range: 8000,
      # label: 16000 }]).
      def from_fields(descriptors: [], flags: [], reserved: 0, tail: "")
        @flags = flags_from(flags, reserved)
        @descriptors = descriptors.map { |d| descriptor(d) }
        @tail = [tail].pack("H*")
      end

      def descriptor(d)
        return d if d.is_a?(Descriptor)

        range = Integer(d.fetch(:range))
        raise ArgumentError, "range #{range} does not fit in 3 octets" unless (0..0xff_ffff).cover?(range)

        sub = if d.key?(:sid_label)
                key, value = d[:sid_label].first
                SubTlv.key_under(SidLabel::REGISTRY, key).new(value)
              else
                SidLabel.new(**d.slice(:label, :index))
              end
        Descriptor.new(range, sub)
      end

      def from_hash(hash)
        from_fields(**hash.slice(:descriptors, :reserved, :tail), flags: hash.fetch(:flags, []))
        @flags = nil if hash.key?(:short)
        @type = hash[:type]
      end
    end

    # SR-Capabilities, RFC 8667 section 3.1: type 2, under TLV 242. Its
    # descriptors are the router's SRGB. "I-Flag: MPLS IPv4 Flag. If set,
    # then the router is capable of processing SR-MPLS-encapsulated IPv4
    # packets on all interfaces"; V the same for IPv6.
    class SrCapabilities < LabelBlock
      TYPE = 2
      NAME = "SR-Capabilities"
      FLAGS = %w[I V].freeze
    end

    # SR Local Block, RFC 8667 section 3.3: type 22, under TLV 242, "the
    # range of labels the node has reserved for Local SIDs". "Flags: 1
    # octet of flags. None are defined at this stage."
    class SrLocalBlock < LabelBlock
      TYPE = 22
      NAME = "SR Local Block"
      FLAGS = [].freeze
    end

    # SR-Algorithm, RFC 8667 section 3.2: type 19, under TLV 242, one
    # octet per algorithm. "0: SPF algorithm based on link metric"; "1:
    # Strict SPF". "When the originating router does advertise the
    # SR-Algorithm sub-TLV, then algorithm 0 MUST be present".
    class SrAlgorithm < SubTlv
      TYPE = 19

      attr_reader :algorithms

      # The algorithms, a list of integers. A hash under an unusual type.
      def to_hash
        unusual_type ? { algorithms: @algorithms, type: unusual_type } : @algorithms
      end

      def to_s
        "SR-Algorithm #{@algorithms.join(', ')}"
      end

      private

      def encode_value
        @algorithms.pack("C*")
      end

      def parse(octets)
        @algorithms = read_frame(octets).unpack("C*")
      end

      # SrAlgorithm.new([0]) or SrAlgorithm.new(0, 1).
      def from_fields(*algorithms)
        list = algorithms.flatten.map { Integer(_1) }
        bad = list.reject { (0..255).cover?(_1) }
        raise ArgumentError, "algorithms do not fit in one octet: #{bad.inspect}" unless bad.empty?

        @algorithms = list
      end

      def from_hash(hash)
        from_fields(hash.fetch(:algorithms))
        @type = hash[:type]
      end
    end

    register_under(SidLabel::REGISTRY, SidLabel::TYPE, :sid_label, SidLabel)
    register_under(Tlv::RouterCapability::TYPE, SrCapabilities::TYPE, :sr_capabilities, SrCapabilities)
    register_under(Tlv::RouterCapability::TYPE, SrAlgorithm::TYPE, :sr_algorithm, SrAlgorithm)
    register_under(Tlv::RouterCapability::TYPE, SrLocalBlock::TYPE, :sr_local_block, SrLocalBlock)
  end
end
