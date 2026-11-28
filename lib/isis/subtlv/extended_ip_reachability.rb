# frozen_string_literal: true

module ISIS
  class SubTlv
    # The Prefix-SID sub-TLV, RFC 8667 section 2.1: type 3, flags,
    # algorithm, then the SID/Index/Label of section 2.1.1.1. It "MAY be
    # present" in TLVs 135, 235, 236 and 237; isis4r has classes for 135
    # and 236, so it is registered under those two.
    #
    #   R  re-advertised from another level or protocol (2.1.1.2)
    #   N  a Node-SID, on a router's own /32 or /128 (2.1.1.2)
    #   P  no PHP: the penultimate hop keeps the label (2.1.1.3)
    #   E  explicit null instead of a pop (2.1.1.3)
    #   V  the SID is a value, not an index
    #   L  the value has local significance
    class PrefixSid < SubTlv
      include FlagOctet
      include SidField

      TYPE = 3
      FLAGS = %w[R N P E V L].freeze

      attr_reader :flags, :algorithm

      def to_hash
        return { short: @short.unpack1("H*") } if @short

        h = flags_hash({})
        h[:algorithm] = @algorithm
        sid_hash(h)
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        f = flag_letters.empty? ? "" : " flags #{flag_letters.join}"
        "Prefix-SID #{sid_text}, algorithm #{@algorithm}#{f}"
      end

      private

      def encode_value
        return @short if @short

        [@flags, @algorithm].pack("CC") + sid_octets + @tail
      end

      def parse(octets)
        value = read_frame(octets)
        @short = value.bytesize < 2 ? value : nil
        @flags = value.getbyte(0) || 0
        @algorithm = value.getbyte(1) || 0
        read_sid(value.byteslice(2..) || "".b, (@flags & 0x0c) == 0x0c)
      end

      # PrefixSid.new(index: 1, flags: %w[N]), or PrefixSid.new(label:
      # 16001), which sets V and L unless flags says otherwise.
      def from_fields(index: nil, label: nil, algorithm: 0, flags: nil, reserved: 0, label_high: 0, tail: "")
        flags ||= label ? %w[V L] : []
        @flags = flags_from(flags, reserved)
        @algorithm = Integer(algorithm)
        raise ArgumentError, "algorithm #{algorithm} does not fit in one octet" unless (0..255).cover?(@algorithm)

        @short = nil
        sid_from(index: index, label: label, label_high: label_high, tail: tail)
      end

      # { short: } is a value too short for flags and algorithm, kept as
      # it came.
      def from_hash(hash)
        from_fields(**hash.slice(:index, :label, :algorithm, :reserved, :label_high, :tail), flags: hash.fetch(:flags, []))
        @short = [hash[:short]].pack("H*") if hash.key?(:short)
        @type = hash[:type]
      end
    end

    # The Prefix Attribute Flags sub-TLV, RFC 7794 section 2.1: type 4,
    # "Length: Number of octets of the Value field", "(Length * 8) bits",
    # "defined/sent starting with Bit 0", the most significant bit of the
    # first octet. "Bits that are NOT transmitted MUST be treated as if
    # they are set to 0 on receipt."
    #
    #   X  bit 0, external: "redistributed from another protocol"; in TLVs
    #      236 and 237 "SHOULD always be sent as 0", their own X bit
    #      carrying it, but "valid when sent in the SRv6 Locator TLV" (RFC
    #      9352 section 6)
    #   R  bit 1, re-advertised: "leaked from one level to another"
    #   N  bit 2, node: "the prefix identifies the advertising router"
    #   E  bit 3, which the IANA registry "IS-IS Bit Values for Prefix
    #      Attribute Flags Sub-TLV" (fetched 2026-11-28) names the ELC
    #      flag, RFC 9088, not read here
    #   A  bit 4, anycast, RFC 9352 section 6
    #
    # In TLVs 135 and 236, and in TLV 27, whose sub-TLV space is theirs
    # (RFC 9352 section 7; 11.1.2 marks this one "y" for all five). The
    # bits no letter names are kept as reserved:, a list of bit numbers;
    # length: when the value has more octets than its highest bit needs,
    # or none at all.
    class PrefixAttributeFlags < SubTlv
      TYPE = 4
      FLAGS = %w[X R N E A].freeze

      # Every bit set, by number.
      def bits
        (0...(@octets.bytesize * 8)).select { |n| @octets.getbyte(n / 8).anybits?(0x80 >> (n % 8)) }
      end

      def flag?(letter) = bits.include?(FLAGS.index(letter.to_s.upcase))

      def flag_letters = bits.select { _1 < FLAGS.size }.map { FLAGS[_1] }

      def reserved_bits = bits.reject { _1 < FLAGS.size }

      def to_hash
        h = {}
        h[:flags] = flag_letters unless flag_letters.empty?
        h[:reserved] = reserved_bits unless reserved_bits.empty?
        h[:length] = @octets.bytesize unless @octets.bytesize == minimal(bits)
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        list = flag_letters + reserved_bits.map { "bit #{_1}" }
        "Prefix Attribute Flags #{list.empty? ? 'none' : list.join(', ')}"
      end

      private

      def minimal(list) = list.empty? ? 1 : (list.max / 8) + 1

      def encode_value = @octets

      def parse(octets)
        @octets = read_frame(octets).b
      end

      # PrefixAttributeFlags.new(flags: %w[N]); reserved: [9] for unnamed
      # bits, length: for another number of octets.
      def from_fields(flags: [], reserved: [], length: nil)
        list = Array(flags).map do |f|
          FLAGS.index(f.to_s.upcase) or raise ArgumentError, "no flag #{f.inspect}; the flags are #{FLAGS.join}"
        end + Array(reserved).map { Integer(_1) }
        length = length ? Integer(length) : minimal(list)
        out = Array.new(length, 0)
        list.each do |n|
          raise ArgumentError, "bit #{n} does not fit in #{length} octets" if n.negative? || n / 8 >= length

          out[n / 8] |= 0x80 >> (n % 8)
        end
        @octets = out.pack("C*")
      end

      def from_hash(hash)
        from_fields(**hash.slice(:flags, :reserved, :length))
        @type = hash[:type]
      end
    end

    register_under(Tlv::ExtendedIpReachability::TYPE, PrefixSid::TYPE, :prefix_sid, PrefixSid)
    register_under(Tlv::Ipv6Reachability::TYPE, PrefixSid::TYPE, :prefix_sid, PrefixSid)
    # TLV 27 shares the prefix sub-TLV space (RFC 9352 section 7), so a
    # number means there what it means under 135 and 236. Section 11.1.2
    # marks the Prefix-SID "n" for 27: it is read, and what a receiver does
    # with it is not the codec's question.
    register_under(Tlv::Srv6Locator::TYPE, PrefixSid::TYPE, :prefix_sid, PrefixSid)
    [Tlv::ExtendedIpReachability::TYPE, Tlv::Ipv6Reachability::TYPE, Tlv::Srv6Locator::TYPE].each do |parent|
      register_under(parent, PrefixAttributeFlags::TYPE, :prefix_attribute_flags, PrefixAttributeFlags)
    end
  end
end
