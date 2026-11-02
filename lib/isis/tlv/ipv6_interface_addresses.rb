# frozen_string_literal: true

require "ipaddr"

module ISIS
  class Tlv
    # TLV 232, IPv6 Interface Address. RFC 5308 section 3: TLV 232 "maps
    # directly to "IP Interface Address" TLV in [RFC1195]", with 16 octet
    # IPv6 addresses in place of 4 octet IPv4 ones. In hellos it holds only
    # the interface's link-local addresses, and in LSPs only non-link-local
    # ones; that is the originator's job and validation's business, so this
    # class carries any.
    #
    # Octets that do not make a whole address are kept as a tail.
    class Ipv6InterfaceAddresses < Tlv
      TYPE = 232

      attr_accessor :addresses, :tail

      # A list: ["fe80::1"]. A hash only when something arrived unusual.
      def to_hash
        list = @addresses.map(&:to_s)
        return list if @tail.empty? && !unusual_type

        h = { addresses: list }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        note = @tail.empty? ? "" : ", tail of #{@tail.bytesize} octets"
        "IPv6 Interface Addresses #{@addresses.join(', ')}#{note}"
      end

      private

      def encode_value
        out = ISIS.buffer
        @addresses.each { |a| out << a.hton }
        out << @tail
      end

      def parse(octets)
        value = read_frame(octets)
        whole = value.bytesize - (value.bytesize % 16)
        @addresses = (0...whole).step(16).map { |i| IPAddr.new_ntoh(value.byteslice(i, 16)) }
        @tail = value.byteslice(whole..).b
      end

      # Ipv6InterfaceAddresses.new("fe80::1", "2001:db8::1"), or one array.
      def from_fields(*addresses)
        addresses = addresses.first if addresses.size == 1 && addresses.first.is_a?(Array)
        @addresses = addresses.map { |a| ipv6(a) }
        @tail = "".b
      end

      def from_hash(hash)
        from_fields(hash.fetch(:addresses))
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end

      def ipv6(text)
        a = IPAddr.new(text.to_s)
        raise ArgumentError, "not an IPv6 address: #{text.inspect}" unless a.ipv6? && a.prefix == 128

        a
      end
    end

    register(Ipv6InterfaceAddresses::TYPE, :ipv6_interface_addresses, Ipv6InterfaceAddresses)
  end
end
