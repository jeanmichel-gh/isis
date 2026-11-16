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

    register_under(Tlv::ExtendedIpReachability::TYPE, PrefixSid::TYPE, :prefix_sid, PrefixSid)
    register_under(Tlv::Ipv6Reachability::TYPE, PrefixSid::TYPE, :prefix_sid, PrefixSid)
  end
end
