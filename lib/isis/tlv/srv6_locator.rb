# frozen_string_literal: true

require "ipaddr"

module ISIS
  class Tlv
    # TLV 27, the SRv6 Locator TLV, RFC 9352 section 7.1:
    #
    #   R R R R, MTID     2 octets: four reserved bits, "MUST be set to
    #                     zero on transmission and MUST be ignored on
    #                     receipt", then a 12-bit MTID, "the value 0 is
    #                     legal"
    #   Locator entries   one or more
    #
    # and each entry
    #
    #   Metric            4 octets, "as described in Section 4 of [RFC5305]"
    #   Flags             1 octet: D, the up/down bit, then seven reserved
    #   Algorithm         1 octet
    #   Loc-Size          1 octet, the locator's length in bits, "MUST be
    #                     from the range (1-128)"
    #   Locator           "encoded in the minimal number of octets for the
    #                     given number of bits"
    #   Sub-TLV-length    1 octet, always there
    #   Sub-TLVs          that many octets
    #
    # The sub-TLV length octet is written whether or not there are
    # sub-TLVs, as TLV 22's is and not behind a bit as TLV 135's is. The
    # sub-TLVs come from the registry of the prefix reachability TLVs:
    # "This new TLV shares the sub-TLV space defined for TLVs 135, 235,
    # 236, and 237" (section 7).
    #
    # Building never validates. A Loc-Size of 0 or past 128 ("The entire
    # TLV MUST be ignored", which is the receiver's decision) is kept and
    # replayed: the parse reads (size + 7) / 8 octets of locator, at most
    # 16, and goes on from there. Trailing bits that arrived set are kept.
    # Octets that do not make a whole entry are a tail.
    class Srv6Locator < Tlv
      TYPE = 27
      MTID_MASK = 0x0fff
      HEADER_OCTETS = 2
      # Metric, flags, algorithm and Loc-Size.
      ENTRY_FIXED = 7

      # One locator. +locator_octets+ is what the wire carries for it,
      # as many as Loc-Size needs, at most 16.
      class Entry
        include SubTlv::FlagOctet
        include SubTlv::FramedList

        FLAGS = %w[D].freeze

        attr_reader :metric, :flags, :algorithm, :size, :locator_octets

        # Entry.new(locator: "fc00:0:1::/48", metric: 0, algorithm: 0,
        # flags: %w[D], subtlvs: [{ end_sid: { ... } }]), or with size: and
        # octets: (hex) for a locator that is not a canonical prefix.
        def initialize(metric: 0, algorithm: 0, flags: [], reserved: 0, locator: nil, size: nil, octets: nil,
                       subtlvs: [], subtlv_tail: "")
          @metric = Integer(metric)
          raise ArgumentError, "metric #{metric} does not fit in 32 bits" unless (0..0xffff_ffff).cover?(@metric)

          @algorithm = Integer(algorithm)
          raise ArgumentError, "algorithm #{algorithm} does not fit in one octet" unless (0..255).cover?(@algorithm)

          @flags = flags_from(flags, reserved)
          if locator
            @size, @locator_octets = self.class.canonical(locator)
          else
            @size = Integer(size)
            raise ArgumentError, "Loc-Size #{size} does not fit in one octet" unless (0..255).cover?(@size)

            @locator_octets = [octets.to_s].pack("H*")
            raise ArgumentError, "a locator is at most 16 octets" if @locator_octets.bytesize > 16
          end
          framed_list_from(TYPE, subtlvs, subtlv_tail)
        end

        # The entry at the front of +rest+, and the octets after it; nil
        # when +rest+ is not a whole entry.
        def self.read(rest)
          return nil if rest.bytesize < ENTRY_FIXED

          metric, flags, algorithm, size = rest.unpack("NCCC")
          n = [(size + 7) / 8, 16].min
          return nil if rest.bytesize < ENTRY_FIXED + n + 1

          e = allocate
          e.send(:read, metric, flags, algorithm, size, rest.byteslice(ENTRY_FIXED, n))
          after = e.send(:read_framed_list, rest.byteslice(ENTRY_FIXED + n..), TYPE)
          [e, after]
        end

        # The length and octets of a prefix such as "fc00:0:1::/48".
        def self.canonical(text)
          a = IPAddr.new(text.to_s)
          raise ArgumentError, "not an IPv6 prefix: #{text.inspect}" unless a.ipv6?

          [a.prefix, a.hton.byteslice(0, (a.prefix + 7) / 8)]
        end

        # The locator as "fc00:0:1::/48", or nil when the octets are not a
        # canonical prefix: a Loc-Size outside 1 to 128, a count of octets
        # not the fewest, or trailing bits set.
        def locator
          return nil unless (1..128).cover?(@size) && @locator_octets.bytesize == (@size + 7) / 8

          text = "#{IPAddr.new_ntoh(@locator_octets.ljust(16, "\x00".b)).mask(@size)}/#{@size}"
          text if self.class.canonical(text).last == @locator_octets
        end

        def up_down? = flag?("D")

        # The sub-TLVs of +klass+, in order.
        def subtlvs_of(klass) = @subtlvs.select { _1.is_a?(klass) }

        def encode
          out = ISIS.buffer
          out << [@metric, @flags, @algorithm, @size].pack("NCCC") << @locator_octets
          out << framed_list_octets
        end

        def to_hash
          text = locator
          h = text ? { locator: text } : { size: @size, octets: @locator_octets.unpack1("H*") }
          h[:metric] = @metric
          h[:algorithm] = @algorithm
          flags_hash(h)
          framed_list_hash(h)
        end

        def to_s
          [locator || "#{@locator_octets.unpack1('H*')}/#{@size}", "metric #{@metric}", "algorithm #{@algorithm}",
           ("down" if up_down?), *@subtlvs.map(&:to_s)].compact.join(", ")
        end

        private

        def read(metric, flags, algorithm, size, octets)
          @metric = metric
          @flags = flags
          @algorithm = algorithm
          @size = size
          @locator_octets = octets.b
        end
      end

      attr_reader :mtid, :reserved, :entries, :tail, :short

      # { entries: [...] }, with mtid: and reserved: when not zero, tail:
      # for octets that are not a whole entry, and short: for a value too
      # short for the MTID.
      def to_hash
        h = if @short
              { short: @short.unpack1("H*") }
            else
              base = {}
              base[:mtid] = @mtid unless @mtid.zero?
              base[:reserved] = @reserved unless @reserved.zero?
              base[:entries] = @entries.map(&:to_hash)
              base[:tail] = @tail.unpack1("H*") unless @tail.empty?
              base
            end
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        return "SRv6 Locator, #{@short.bytesize} octets" if @short

        mt = @mtid.zero? ? "" : " MTID #{@mtid}"
        note = @tail.empty? ? "" : ", tail of #{@tail.bytesize} octets"
        "SRv6 Locator#{mt} #{@entries.join('; ')}#{note}"
      end

      private

      def encode_value
        return @short if @short

        out = ISIS.buffer
        out << [(@reserved << 12) | @mtid].pack("n")
        @entries.each { |e| out << e.encode }
        out << @tail
      end

      def parse(octets)
        value = read_frame(octets)
        @entries = []
        @tail = "".b
        if value.bytesize < HEADER_OCTETS
          @short = value
          @mtid = @reserved = 0
          return
        end
        @short = nil
        word = value.unpack1("n")
        @mtid = word & MTID_MASK
        @reserved = word >> 12
        rest = value.byteslice(HEADER_OCTETS..).b
        while (entry = Entry.read(rest))
          @entries << entry.first
          rest = entry.last
        end
        @tail = rest
      end

      # Srv6Locator.new(entries: [{ locator: "fc00:0:1::/48", ... }]),
      # mtid: for a topology other than 0.
      def from_fields(entries: [], mtid: 0, reserved: 0, tail: "")
        @mtid = Integer(mtid)
        raise ArgumentError, "MTID #{mtid} does not fit in 12 bits" unless (0..MTID_MASK).cover?(@mtid)

        @reserved = Integer(reserved)
        raise ArgumentError, "reserved #{reserved} does not fit in 4 bits" unless (0..15).cover?(@reserved)

        @entries = entries.map { |e| e.is_a?(Entry) ? e : Entry.new(**e) }
        @tail = [tail].pack("H*")
        @short = nil
      end

      def from_hash(hash)
        if hash.key?(:short)
          from_fields
          @short = [hash[:short]].pack("H*")
        else
          from_fields(**hash.slice(:entries, :mtid, :reserved, :tail))
        end
        @type = hash[:type]
      end
    end

    register(Srv6Locator::TYPE, :locator, Srv6Locator)
  end
end
