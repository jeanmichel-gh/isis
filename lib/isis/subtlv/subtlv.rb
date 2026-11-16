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

    # A flags octet whose bits RFC 8667 names by letter, drawn as
    #
    #   0 1 2 3 4 5 6 7
    #   +-+-+-+-+-+-+-+-+
    #   |R|N|P|E|V|L|   |
    #
    # so the first letter is the most significant bit, 0x80. A class lists
    # its letters in FLAGS. Bits no letter names are kept as they arrived
    # and written back: zero when built from fields, echoed when replayed.
    module FlagOctet
      # The bit of +letter+ in this class's octet.
      def flag_bit(letter)
        i = self.class::FLAGS.index(letter.to_s.upcase) or
          raise ArgumentError, "no #{letter.inspect} flag in #{self.class::FLAGS.join}"
        0x80 >> i
      end

      def flag?(letter)
        (@flags & flag_bit(letter)).positive?
      end

      # The letters set, in the RFC's order.
      def flag_letters
        self.class::FLAGS.select { |l| flag?(l) }
      end

      # The bits no letter names.
      def reserved_bits
        named = self.class::FLAGS.each_index.sum { |i| 0x80 >> i }
        @flags & ~named & 0xff
      end

      private

      # The octet from a list of letters and the unnamed bits.
      def flags_from(letters, reserved = 0)
        Array(letters).sum(0) { |l| flag_bit(l) } | (Integer(reserved) & 0xff)
      end

      def flags_hash(h)
        h[:flags] = flag_letters unless flag_letters.empty?
        h[:reserved] = reserved_bits unless reserved_bits.zero?
        h
      end
    end

    # A SID or label field as RFC 8667 section 2.1.1.1 gives it: "a 4-octet
    # index" when the V and L flags are clear, "a 3-octet local label where
    # the 20 rightmost bits are used for encoding the label value" when
    # both are set. Prefix-SID, Adj-SID and LAN-Adj-SID end with one.
    #
    # It is read by its length, which the octets carry, and not by the
    # flags, which may disagree: section 2.1.1.1 says an invalid V and L
    # pair "MUST be ignored", which is the receiver's decision. The octets
    # replay either way. Past four octets the flags choose, and the rest is
    # a tail. The high four bits of a 3-octet label are kept.
    module SidField
      attr_reader :index, :label, :tail

      private

      def sid_octets
        if @index then [@index].pack("N")
        elsif @label then [@label].pack("N").byteslice(1, 3)
        else "".b
        end
      end

      def read_sid(rest, label_first)
        @index = @label = nil
        width = case rest.bytesize
                when 3 then 3
                when 4 then 4
                when 0..2 then 0
                else label_first ? 3 : 4
                end
        @tail = rest.byteslice(width..).b
        case width
        when 3 then @label = ("\x00".b + rest.byteslice(0, 3)).unpack1("N")
        when 4 then @index = rest.byteslice(0, 4).unpack1("N")
        end
      end

      def sid_hash(h)
        h[:index] = @index if @index
        if @label
          h[:label] = @label & 0xfffff
          h[:label_high] = @label >> 20 unless (@label >> 20).zero?
        end
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h
      end

      def sid_from(index: nil, label: nil, label_high: 0, tail: "")
        raise ArgumentError, "a SID is an index or a label, not both" if index && label
        raise ArgumentError, "index #{index} does not fit in 4 octets" if index && !(0..0xffff_ffff).cover?(index)
        raise ArgumentError, "label #{label} does not fit in 20 bits" if label && !(0..0xfffff).cover?(label)

        @index = index
        @label = label && (label | (Integer(label_high) << 20))
        @tail = [tail].pack("H*")
      end

      def sid_text
        if @index then "index #{@index}"
        elsif @label then "label #{@label & 0xfffff}"
        else "no SID"
        end
      end
    end
  end
end
