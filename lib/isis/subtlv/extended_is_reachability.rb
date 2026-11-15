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

    # Under TLV 22 only: the same numbers mean other things under other
    # parents.
    register_under(Tlv::ExtendedIsReachability::TYPE, Ipv4InterfaceAddress::TYPE,
                   :ipv4_interface_address, Ipv4InterfaceAddress)
    register_under(Tlv::ExtendedIsReachability::TYPE, Ipv4NeighborAddress::TYPE,
                   :ipv4_neighbor_address, Ipv4NeighborAddress)
  end
end
