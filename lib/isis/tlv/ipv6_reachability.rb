# frozen_string_literal: true

require "ipaddr"

module ISIS
  class Tlv
    # TLV 236, IPv6 Reachability. RFC 5308 section 2: "The "IPv6
    # Reachability" TLV is TLV type 236 (0xEC)." Each entry is
    #
    #   Metric            4 octets
    #   Control           1 octet: U, the up/down bit, then X, external,
    #                     then S, sub-TLVs present, then five reserved bits,
    #                     as the section's figure draws them, "|U|X|S| Reserve
    #                     |", most significant first
    #   Prefix Len        1 octet, 0 to 128
    #   Prefix            packed to the octets the length needs, (len + 7) / 8
    #   Sub-TLV length    1 octet, only with S set
    #   Sub-TLVs          that many octets
    #
    # Unlike TLV 135, the prefix length has an octet of its own, so the
    # control octet's low bits are reserved: kept and echoed, not zeroed.
    # The prefix octets are kept as they arrived, host bits and all, so any
    # entry replays. Octets that do not make a whole entry are kept as a
    # tail.
    class Ipv6Reachability < Tlv
      TYPE = 236
      UP_DOWN = 0x80
      EXTERNAL = 0x40
      SUBTLVS = 0x20
      RESERVED = 0x1f
      # RFC 5308 section 5: MAX_V6_PATH_METRIC, 0xFE000000.
      MAX_V6_PATH_METRIC = 0xfe00_0000

      # One prefix. reserved is the control octet's low five bits as they
      # arrived. subtlvs is a SubTlv::List, or nil when S is clear.
      class Entry
        attr_accessor :metric, :up_down, :external, :reserved, :length, :prefix_octets, :subtlvs

        def initialize(metric:, length:, prefix_octets:, up_down: false, external: false, reserved: 0, subtlvs: nil)
          @metric = metric
          @length = length
          @prefix_octets = prefix_octets.b
          @up_down = up_down
          @external = external
          @reserved = reserved
          @subtlvs = subtlvs
        end

        # The control octet, from its four fields.
        def control
          (@up_down ? UP_DOWN : 0) | (@external ? EXTERNAL : 0) | (@subtlvs ? SUBTLVS : 0) | (@reserved & RESERVED)
        end

        # The prefix as "2001:db8::/64", or nil when it cannot be one: a
        # length over 128, or octets that are not the minimal count for it.
        def prefix
          return nil if @length > 128 || @prefix_octets.bytesize != (@length + 7) / 8

          "#{IPAddr.new_ntoh(@prefix_octets.ljust(16, "\x00".b)).mask(@length)}/#{@length}"
        end

        def unusual?
          prefix.nil? || self.class.canonical(prefix).last != @prefix_octets || !@reserved.zero?
        end

        def encode
          out = ISIS.buffer
          out << [@metric, control, @length].pack("NCC") << @prefix_octets
          if @subtlvs
            body = @subtlvs.encode
            out << [body.bytesize].pack("C") << body
          end
          out
        end

        def to_hash
          canonical = prefix && self.class.canonical(prefix).last == @prefix_octets
          h = canonical ? { prefix: prefix } : { length: @length, octets: @prefix_octets.unpack1("H*") }
          h[:metric] = @metric
          h[:up_down] = true if @up_down
          h[:external] = true if @external
          h[:reserved] = @reserved unless @reserved.zero?
          if @subtlvs
            sub = @subtlvs.to_hash
            h[:subtlvs] = sub[:tlvs]
            h[:subtlv_tail] = sub[:tail] if sub[:tail]
          end
          h
        end

        def to_s
          [prefix || "#{@prefix_octets.unpack1('H*')}/#{@length}", "metric #{@metric}",
           ("down" if @up_down), ("external" if @external),
           ("#{@subtlvs.size} sub-TLVs" if @subtlvs)].compact.join(" ")
        end

        def self.canonical(text)
          a = IPAddr.new(text.to_s)
          raise ArgumentError, "not an IPv6 prefix: #{text.inspect}" unless a.ipv6?

          [a.prefix, a.hton.byteslice(0, (a.prefix + 7) / 8)]
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
        "IPv6 Reachability #{@entries.join('; ')}#{note}"
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
        return nil if value.bytesize < i + 6

        metric, control, length = value.byteslice(i, 6).unpack("NCC")
        size = (length + 7) / 8
        at = i + 6 + size
        return nil if value.bytesize < at

        prefix = value.byteslice(i + 6, size)
        subtlvs = nil
        if control & SUBTLVS != 0
          return nil if value.bytesize < at + 1

          declared = value.getbyte(at)
          return nil if value.bytesize < at + 1 + declared

          subtlvs = SubTlv::List.parse_under(TYPE, Octets.new(value.byteslice(at + 1, declared)))
          at += 1 + declared
        end
        [Entry.new(metric: metric, length: length, prefix_octets: prefix, up_down: control & UP_DOWN != 0,
                   external: control & EXTERNAL != 0, reserved: control & RESERVED, subtlvs: subtlvs), at]
      end

      # Ipv6Reachability.new({ prefix: "2001:db8::/64", metric: 10 }, ...),
      # or one array of them. An Entry is taken as it is.
      def from_fields(*entries)
        entries = entries.first if entries.size == 1 && entries.first.is_a?(Array)
        @entries = entries.map { |e| entry(e) }
        @tail = "".b
      end

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
        raise ArgumentError, "prefix length #{length} does not fit in an octet" unless (0..255).cover?(length)

        metric = Integer(e.fetch(:metric))
        raise ArgumentError, "metric #{metric} does not fit in 32 bits" unless (0..0xffff_ffff).cover?(metric)

        reserved = Integer(e.fetch(:reserved, 0))
        raise ArgumentError, "reserved #{reserved} does not fit in five bits" unless (0..RESERVED).cover?(reserved)

        subtlvs = if e.key?(:subtlvs) || e.key?(:subtlv_tail)
                    SubTlv::List.new(TYPE, { tlvs: e.fetch(:subtlvs, []), tail: e.fetch(:subtlv_tail, "") })
                  end
        Entry.new(metric: metric, length: length, prefix_octets: octets, up_down: e.fetch(:up_down, false),
                  external: e.fetch(:external, false), reserved: reserved, subtlvs: subtlvs)
      end
    end

    register(Ipv6Reachability::TYPE, :ipv6_reachability, Ipv6Reachability)
  end
end
