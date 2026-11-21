# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 148, BFD-Enabled. RFC 6213 section 6, read 2026-11-21:
    #
    #   Type   148
    #   Length # of octets in the value field (3 to 255)
    #   Value  3 octets specifying the MTID/NLPID for each
    #          topology/data protocol for which BFD support is enabled
    #
    #   |R|R|R|R|   MTID        |     2
    #   |      NLPID            |     1
    #
    # So each entry is four reserved bits and a 12 bit MTID in two octets,
    # then one NLPID octet. "The TLV SHALL only be included in an IIH", which
    # is the originator's and validation's business, not the codec's.
    #
    # The NLPID names are TLV 129's (ProtocolsSupported::NAMES), second hand
    # as that class says. Reserved bits that arrived set are kept and
    # echoed; octets that do not make a whole entry are kept as a tail.
    class BfdEnabled < Tlv
      TYPE = TLV_BFD_ENABLED
      MTID_MASK = 0x0fff
      RESERVED_MASK = 0xf000

      # One MTID/NLPID pair. +reserved+ is the high four bits of the MTID
      # octets, as they arrived, zero when built.
      Entry = Struct.new(:mtid, :nlpid, :reserved) do
        def pair = [mtid, nlpid]
      end

      attr_accessor :entries, :tail

      # The MTID/NLPID pairs, [[0, 0xcc], ...].
      def pairs = @entries.map(&:pair)

      # [{ mtid: 0, nlpid: :ipv4 }, ...], with a bare number for an NLPID
      # that has no name, and reserved: only when some arrived set. A hash
      # only when a tail or an unusual type arrived.
      def to_hash
        list = @entries.map do |e|
          h = { mtid: e.mtid, nlpid: ProtocolsSupported::NAMES.fetch(e.nlpid, e.nlpid) }
          h[:reserved] = e.reserved unless e.reserved.zero?
          h
        end
        return list if @tail.empty? && !unusual_type

        h = { entries: list }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        list = @entries.map do |e|
          name = ProtocolsSupported::NAMES.fetch(e.nlpid) { format("0x%02x", e.nlpid) }
          "MTID #{e.mtid} #{name}"
        end
        note = @tail.empty? ? "" : ", tail of #{@tail.bytesize} octets"
        "BFD Enabled #{list.join(', ')}#{note}"
      end

      private

      def encode_value
        out = ISIS.buffer
        @entries.each { |e| out << [(e.reserved << 12) | e.mtid, e.nlpid].pack("nC") }
        out << @tail
      end

      def parse(octets)
        value = read_frame(octets)
        whole = value.bytesize - (value.bytesize % 3)
        @entries = (0...whole).step(3).map do |i|
          mt, nlpid = value.byteslice(i, 3).unpack("nC")
          Entry.new(mt & MTID_MASK, nlpid, (mt & RESERVED_MASK) >> 12)
        end
        @tail = value.byteslice(whole..).b
      end

      # BfdEnabled.new([0, :ipv4], [0, :ipv6]), pairs of MTID and NLPID, or
      # hashes { mtid:, nlpid: }, or one array of either.
      def from_fields(*entries)
        entries = entries.first if entries.size == 1 && entries.first.is_a?(Array) && !entries.first.first.is_a?(Integer)
        @entries = entries.map { |e| entry(e) }
        @tail = "".b
      end

      def from_hash(hash)
        from_fields(hash.fetch(:entries))
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end

      def entry(e)
        mtid, nlpid, reserved = e.is_a?(Hash) ? e.values_at(:mtid, :nlpid, :reserved) : e
        mtid = Integer(mtid)
        reserved = Integer(reserved || 0)
        raise ArgumentError, "MTID #{mtid} does not fit in 12 bits" unless (0..MTID_MASK).cover?(mtid)
        raise ArgumentError, "reserved #{reserved} does not fit in 4 bits" unless (0..15).cover?(reserved)

        Entry.new(mtid, nlpid_number(nlpid), reserved)
      end

      def nlpid_number(nlpid)
        n = if nlpid.is_a?(Symbol)
              ProtocolsSupported::NUMBERS.fetch(nlpid) { raise ArgumentError, "no NLPID named #{nlpid.inspect}" }
            else
              Integer(nlpid)
            end
        raise ArgumentError, "NLPID #{n} does not fit in one octet" unless (0..255).cover?(n)

        n
      end
    end

    register(BfdEnabled::TYPE, :bfd_enabled, BfdEnabled)
  end
end
