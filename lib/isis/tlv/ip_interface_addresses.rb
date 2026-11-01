# frozen_string_literal: true

require "ipaddr"

module ISIS
  class Tlv
    # TLV 132, IP Interface Address. RFC 1195 section 5.3.1: "CODE - 132",
    # "LENGTH - total length of the value field (four octets per address)",
    # each value entry a "4 octet IP Address of the Interface". In hellos it
    # "occurs once only" with "up to a maximum of 63 IP addresses"; that is
    # validation's business, so this class carries any number.
    #
    # Octets that do not make a whole address are kept as a tail.
    class IpInterfaceAddresses < Tlv
      TYPE = 132

      attr_accessor :addresses, :tail

      # A list: ["10.0.0.1"]. A hash only when something arrived unusual.
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
        "IP Interface Addresses #{@addresses.join(', ')}#{note}"
      end

      private

      def encode_value
        out = ISIS.buffer
        @addresses.each { |a| out << a.hton }
        out << @tail
      end

      def parse(octets)
        value = read_frame(octets)
        whole = value.bytesize - (value.bytesize % 4)
        @addresses = (0...whole).step(4).map { |i| IPAddr.new_ntoh(value.byteslice(i, 4)) }
        @tail = value.byteslice(whole..).b
      end

      # IpInterfaceAddresses.new("10.0.0.1", "10.0.0.2"), or one array.
      def from_fields(*addresses)
        addresses = addresses.first if addresses.size == 1 && addresses.first.is_a?(Array)
        @addresses = addresses.map { |a| ipv4(a) }
        @tail = "".b
      end

      def from_hash(hash)
        from_fields(hash.fetch(:addresses))
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end

      def ipv4(text)
        a = IPAddr.new(text.to_s)
        raise ArgumentError, "not an IPv4 address: #{text.inspect}" unless a.ipv4? && a.prefix == 32

        a
      end
    end

    register(IpInterfaceAddresses::TYPE, :ip_interface_addresses, IpInterfaceAddresses)
  end
end
