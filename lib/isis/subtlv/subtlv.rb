# frozen_string_literal: true

module ISIS
  # A sub-TLV: the same type, length and value framing as a TLV, inside the
  # value of a TLV. RFC 5305 section 2: "Each sub-TLV consists of three
  # fields, a one-octet Type field, a one-octet Length field, and zero or
  # more octets of Value."
  #
  # Two things differ from a TLV, and both are the parent's business:
  #
  # * The registry. The same sub-TLV number means different things under
  #   different parents, so classes register under a parent TLV type and
  #   an unregistered one is a SubTlv::Unknown.
  # * The framing of the list. TLV 22 always writes the sub-TLV length
  #   octet; TLV 135 writes it only behind a presence bit. So a parent
  #   reads a SubTlv::List at the boundary it decides, and writes the list's
  #   octets in the way its own layout asks. CLAUDE.md, "Sub-TLV framing
  #   belongs to the parent TLV".
  class SubTlv < Tlv
    @registries = Hash.new { |h, k| h[k] = {} }

    class << self
      # Register +klass+ as sub-TLV +type+ under parent TLV +parent+.
      def register_under(parent, type, key, klass)
        @registries[parent][type] = klass
        klass.instance_variable_set(:@hash_key, key)
        klass
      end

      def class_under(parent, type)
        @registries.fetch(parent, {}).fetch(type, Unknown)
      end

      def key_under(parent, key)
        return Unknown if key == :unknown

        @registries.fetch(parent, {}).values.find { |k| k.hash_key == key } or
          raise ArgumentError, "no sub-TLV #{key.inspect} under TLV #{parent}"
      end

      # Read one sub-TLV of parent +parent+ off the front of +octets+,
      # within +boundary+. The framing rules are a TLV's: a declared length
      # past the boundary is clamped and kept, and fewer than two octets is
      # not a sub-TLV.
      def factory_under(parent, octets, boundary:)
        boundary = [boundary, octets.bytesize].min
        return nil if boundary < Tlv::HEADER

        take = [octets.getbyte(1), boundary - Tlv::HEADER].min
        raw = Octets.new(octets.byteslice(0, Tlv::HEADER + take))
        octets.replace(octets.byteslice(Tlv::HEADER + take..) || "")
        class_under(parent, raw.getbyte(0)).new(raw)
      end
    end

    # A sub-TLV type isis4r does not implement under its parent, kept whole
    # and replayed, declared length included.
    class Unknown < Tlv::Unknown
      def to_s
        note = clamped? ? ", declared #{@declared_length}" : ""
        "sub-TLV #{@type}, #{@value.bytesize} octets#{note}"
      end
    end

    # The sub-TLVs of one parent entry, in order, with a tail for octets
    # that cannot be a sub-TLV. The parent says where the list ends.
    class List < Tlv::List
      attr_reader :parent

      # Read sub-TLVs of parent TLV +parent+ from the front of +octets+ until
      # +boundary+ octets have been consumed.
      def self.parse_under(parent, octets, boundary: octets.bytesize)
        list = allocate
        list.instance_variable_set(:@parent, parent)
        list.send(:parse_bounded, octets, [boundary, octets.bytesize].min, Tlv::DEFAULT_ID_WIDTH)
        list
      end

      # SubTlv::List.new(135, [sub-TLV, ...]), or from a hash, with the
      # parent named.
      def initialize(parent, *args)
        @parent = parent
        super(*args)
      end

      private

      def parse(octets, id_width: Tlv::DEFAULT_ID_WIDTH)
        parse_bounded(octets, octets.bytesize, id_width)
      end

      def read_one(octets, remaining, _id_width)
        SubTlv.factory_under(@parent, octets, boundary: remaining)
      end

      def class_for_key(key)
        SubTlv.key_under(@parent, key)
      end

      def from_fields(*subtlvs)
        subtlvs = [] if subtlvs.empty?
        super
      end
    end
  end
end
