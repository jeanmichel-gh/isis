# frozen_string_literal: true

require "ipaddr"

module ISIS
  class SubTlv
    # A sub-TLV whose value is one IPv4 address, four octets. The two under
    # TLV 22 below share this layout and differ in their number and their
    # meaning. Not registered itself.
    #
    # Octets past the four, or fewer than four, are kept as a tail, so a
    # sub-TLV with the wrong length replays as it arrived.
    class Ipv4Address < SubTlv
      attr_accessor :address, :tail

      # The address as a String, "192.0.2.1". A hash only when something
      # arrived unusual.
      def to_hash
        return @address.to_s if @address && @tail.empty? && !unusual_type

        h = {}
        h[:address] = @address.to_s if @address
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        note = @tail.empty? ? "" : ", tail of #{@tail.bytesize} octets"
        "#{self.class::NAME} #{@address}#{note}"
      end

      private

      def encode_value
        out = ISIS.buffer
        out << @address.hton if @address
        out << @tail
      end

      def parse(octets)
        value = read_frame(octets)
        if value.bytesize >= 4
          @address = IPAddr.new_ntoh(value.byteslice(0, 4))
          @tail = value.byteslice(4..).b
        else
          @address = nil
          @tail = value
        end
      end

      # Ipv4InterfaceAddress.new("192.0.2.1").
      def from_fields(address)
        a = IPAddr.new(address.to_s)
        raise ArgumentError, "not an IPv4 address: #{address.inspect}" unless a.ipv4? && a.prefix == 32

        @address = a
        @tail = "".b
      end

      def from_hash(hash)
        if hash.key?(:address)
          from_fields(hash[:address])
        else
          @address = nil
        end
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end
    end

    # TLV 22 sub-TLV 6, IPv4 Interface Address. RFC 5305 section 3.2: "a
    # 4-octet IPv4 address for the interface described by the (main) TLV.
    # This sub-TLV can occur multiple times." Section 3's table gives its
    # length as 4.
    class Ipv4InterfaceAddress < Ipv4Address
      TYPE = 6
      NAME = "IPv4 Interface Address"
    end

    # TLV 22 sub-TLV 8, IPv4 Neighbor Address. RFC 5305 section 3.3: "a
    # single IPv4 address for a neighboring router on this link. This
    # sub-TLV can occur multiple times." A router doing traffic engineering
    # "MUST include this sub-TLV on point-to-point adjacencies".
    class Ipv4NeighborAddress < Ipv4Address
      TYPE = 8
      NAME = "IPv4 Neighbor Address"
    end

    # The Adj-SID sub-TLV, RFC 8667 section 2.2.1: type 31, flags, weight,
    # then the SID/Label/Index of section 2.1.1.1. In TLV 22 (and 23, 25,
    # 141, 222 and 223, which isis4r has no class for).
    #
    #   F  the adjacency carries IPv6, not IPv4
    #   B  eligible for protection
    #   V  a value, "By default, the flag is SET"
    #   L  local significance, "By default, the flag is SET"
    #   S  the SID is shared by a set of adjacencies
    #   P  persistent across restarts
    class AdjSid < SubTlv
      include FlagOctet
      include SidField

      TYPE = 31
      FLAGS = %w[F B V L S P].freeze

      attr_reader :flags, :weight

      def to_hash
        return { short: @short.unpack1("H*") } if @short

        h = flags_hash({})
        h[:weight] = @weight unless @weight.zero?
        sid_hash(h)
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        f = flag_letters.empty? ? "" : " flags #{flag_letters.join}"
        w = @weight.zero? ? "" : ", weight #{@weight}"
        "#{self.class::NAME} #{sid_text}#{w}#{f}"
      end

      NAME = "Adj-SID"

      private

      def encode_value
        return @short if @short

        [@flags, @weight].pack("CC") + neighbor_octets + sid_octets + @tail
      end

      def neighbor_octets
        "".b
      end

      def parse(octets)
        value = read_frame(octets)
        @short = value.bytesize < 2 ? value : nil
        @flags = value.getbyte(0) || 0
        @weight = value.getbyte(1) || 0
        read_sid(read_neighbor(value.byteslice(2..) || "".b), (@flags & 0x30) == 0x30)
      end

      def read_neighbor(rest)
        rest
      end

      # AdjSid.new(label: 15000), which sets V and L as section 2.2.1's
      # defaults say, or AdjSid.new(index: 5, flags: []).
      def from_fields(index: nil, label: nil, weight: 0, flags: nil, reserved: 0, label_high: 0, tail: "")
        flags ||= label ? %w[V L] : []
        @flags = flags_from(flags, reserved)
        @weight = Integer(weight)
        raise ArgumentError, "weight #{weight} does not fit in one octet" unless (0..255).cover?(@weight)

        @short = nil
        sid_from(index: index, label: label, label_high: label_high, tail: tail)
      end

      def from_hash(hash)
        from_fields(**hash.slice(:index, :label, :weight, :reserved, :label_high, :tail), flags: hash.fetch(:flags, []))
        @short = [hash[:short]].pack("H*") if hash.key?(:short)
        @type = hash[:type]
      end
    end

    # The LAN-Adj-SID sub-TLV, RFC 8667 section 2.2.2: type 32, the
    # Adj-SID's flags and weight, then the neighbor's "IS-IS System-ID of
    # length 'ID Length'", then the SID. A router on a LAN puts one per LAN
    # neighbor in its TLV 22 entry to the DIS.
    #
    # A sub-TLV is read without the PDU's ID Length (SubTlv.factory_under
    # takes none), so the System ID is read as six octets, the usual
    # width. Octets that do not fit replay as they came.
    class LanAdjSid < AdjSid
      TYPE = 32
      NAME = "LAN-Adj-SID"

      attr_reader :neighbor

      def to_hash
        h = super
        return h if @short || @neighbor.nil?

        { neighbor: SystemId.from_bytes(@neighbor).to_s }.merge(h)
      end

      def to_s
        super.sub(NAME, "#{NAME} #{@neighbor ? SystemId.from_bytes(@neighbor) : '?'}")
      end

      private

      def neighbor_octets
        @neighbor || "".b
      end

      def read_neighbor(rest)
        if rest.bytesize >= SystemId::LENGTH
          @neighbor = rest.byteslice(0, SystemId::LENGTH).b
          rest.byteslice(SystemId::LENGTH..)
        else
          @neighbor = nil
          rest
        end
      end

      # LanAdjSid.new(neighbor: "0000.0000.0002", label: 15001). Without a
      # neighbor, the octets after the weight are the SID alone.
      def from_fields(neighbor: nil, **fields)
        @neighbor = neighbor && SystemId.new(neighbor.to_s).encode.b
        super(**fields)
      end

      def from_hash(hash)
        from_fields(neighbor: hash[:neighbor], **hash.slice(:index, :label, :weight, :reserved, :label_high, :tail),
                    flags: hash.fetch(:flags, []))
        @short = [hash[:short]].pack("H*") if hash.key?(:short)
        @type = hash[:type]
      end
    end

    # Under TLV 22 only: the same numbers mean other things under other
    # parents.
    register_under(Tlv::ExtendedIsReachability::TYPE, Ipv4InterfaceAddress::TYPE,
                   :ipv4_interface_address, Ipv4InterfaceAddress)
    register_under(Tlv::ExtendedIsReachability::TYPE, Ipv4NeighborAddress::TYPE,
                   :ipv4_neighbor_address, Ipv4NeighborAddress)
    register_under(Tlv::ExtendedIsReachability::TYPE, AdjSid::TYPE, :adj_sid, AdjSid)
    register_under(Tlv::ExtendedIsReachability::TYPE, LanAdjSid::TYPE, :lan_adj_sid, LanAdjSid)
  end
end
