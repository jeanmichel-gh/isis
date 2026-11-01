# frozen_string_literal: true

require "ipaddr"

module ISIS
  class Tlv
    # TLV 135, Extended IP Reachability. RFC 5305 section 4: "The extended IP
    # reachability TLV is TLV type 135." Each entry is
    #
    #   Metric            4 octets, a 32 bit unsigned integer
    #   Control           1 octet: "1 bit of up/down information", "1 bit
    #                     indicating the presence of sub-TLVs" and "6 bits of
    #                     prefix length", in that order
    #   Prefix            "the minimal number of octets for the given number
    #                     of significant bits", (length + 7) / 8
    #   Sub-TLV length    1 octet, only when the presence bit is set (section
    #                     4.2: "the first octet after the prefix will be
    #                     interpreted as the length of all sub-TLVs")
    #   Sub-TLVs          that many octets
    #
    # The RFC lists the control fields in order and gives no bit numbers, so
    # up/down as 0x80 and presence as 0x40 follow from that order, with the
    # length in the low six bits. A captured FRR 8.4.4 LSP confirms the low
    # six bits (0x18 for a /24) and has both flags clear.
    #
    # The prefix octets are kept as they arrived, host bits and all, and the
    # six bit length is kept even when it is over 32, so any entry replays.
    # Octets that do not make a whole entry, a sub-TLV length that runs past
    # the value included, are kept as a tail.
    class ExtendedIpReachability < Tlv
      TYPE = 135
      UP_DOWN = 0x80
      SUBTLVS = 0x40
      LENGTH = 0x3f
      # RFC 5305 section 4: a metric above MAX_PATH_METRIC keeps the prefix
      # out of the normal SPF; section 3 gives the value, 0xFE000000.
      MAX_PATH_METRIC = 0xfe00_0000

      # One prefix. prefix_octets are the octets on the wire; length is the
      # six bit field. subtlvs is a SubTlv::List, or nil when the presence
      # bit is clear.
      class Entry
        attr_accessor :metric, :up_down, :length, :prefix_octets, :subtlvs

        def initialize(metric:, length:, prefix_octets:, up_down: false, subtlvs: nil)
          @metric = metric
          @length = length
          @prefix_octets = prefix_octets.b
          @up_down = up_down
          @subtlvs = subtlvs
        end

        # The control octet, built from its three fields. Its own method,
        # since a flag and a width in one octet is the shape most often read
        # with the wrong mask.
        def control
          (@up_down ? UP_DOWN : 0) | (@subtlvs ? SUBTLVS : 0) | (@length & LENGTH)
        end

        # The prefix as "10.0.12.0/24", or nil when it cannot be one: a
        # length over 32, or octets that are not the minimal count for it.
        def prefix
          return nil if @length > 32 || @prefix_octets.bytesize != (@length + 7) / 8

          "#{IPAddr.new_ntoh(@prefix_octets.ljust(4, "\x00".b)).mask(@length)}/#{@length}"
        end

        # True when the octets carry bits past the length, which the
        # presentation form cannot show, or cannot be a prefix at all.
        def unusual?
          prefix.nil? || canonical_octets(prefix) != @prefix_octets
        end

        def encode
          out = ISIS.buffer
          out << [@metric, control].pack("NC") << @prefix_octets
          if @subtlvs
            body = @subtlvs.encode
            out << [body.bytesize].pack("C") << body
          end
          out
        end

        def to_hash
          h = unusual? ? { length: @length, octets: @prefix_octets.unpack1("H*") } : { prefix: prefix }
          h[:metric] = @metric
          h[:up_down] = true if @up_down
          h[:subtlvs] = @subtlvs.to_hash[:tlvs] if @subtlvs
          h
        end

        def to_s
          [prefix || "#{@prefix_octets.unpack1('H*')}/#{@length}", "metric #{@metric}",
           ("down" if @up_down), ("#{@subtlvs.size} sub-TLVs" if @subtlvs)].compact.join(" ")
        end

        def self.canonical(text)
          a = IPAddr.new(text.to_s)
          raise ArgumentError, "not an IPv4 prefix: #{text.inspect}" unless a.ipv4?

          [a.prefix, a.hton.byteslice(0, (a.prefix + 7) / 8)]
        end

        private

        def canonical_octets(text)
          self.class.canonical(text).last
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
        "Extended IP Reachability #{@entries.join('; ')}#{note}"
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
        return nil if value.bytesize < i + 5

        metric, control = value.byteslice(i, 5).unpack("NC")
        length = control & LENGTH
        size = (length + 7) / 8
        at = i + 5 + size
        return nil if value.bytesize < at

        prefix = value.byteslice(i + 5, size)
        subtlvs = nil
        if control & SUBTLVS != 0
          return nil if value.bytesize < at + 1

          declared = value.getbyte(at)
          return nil if value.bytesize < at + 1 + declared

          subtlvs = SubTlv::List.parse_under(TYPE, Octets.new(value.byteslice(at + 1, declared)))
          at += 1 + declared
        end
        [Entry.new(metric: metric, length: length, prefix_octets: prefix, up_down: control & UP_DOWN != 0,
                   subtlvs: subtlvs), at]
      end

      # ExtendedIpReachability.new({ prefix: "10.0.12.0/24", metric: 10 }, ...),
      # or one array of them. An Entry is taken as it is.
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

        length, octets =
          if e.key?(:prefix)
            Entry.canonical(e.fetch(:prefix))
          else
            [e.fetch(:length), [e.fetch(:octets)].pack("H*")]
          end
        raise ArgumentError, "prefix length #{length} does not fit in six bits" unless (0..LENGTH).cover?(length)

        metric = Integer(e.fetch(:metric))
        raise ArgumentError, "metric #{metric} does not fit in 32 bits" unless (0..0xffff_ffff).cover?(metric)

        subtlvs = e.key?(:subtlvs) ? SubTlv::List.new(TYPE, { tlvs: e[:subtlvs] }) : nil
        Entry.new(metric: metric, length: length, prefix_octets: octets, up_down: e.fetch(:up_down, false),
                  subtlvs: subtlvs)
      end
    end

    register(ExtendedIpReachability::TYPE, :extended_ip_reachability, ExtendedIpReachability)
  end
end
