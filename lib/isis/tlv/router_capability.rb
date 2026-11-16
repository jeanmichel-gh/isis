# frozen_string_literal: true

require "ipaddr"

module ISIS
  class Tlv
    # TLV 242, the IS-IS Router CAPABILITY TLV. RFC 7981 section 2: "a
    # variable length value field that starts with 4 octets of Router ID,
    # indicating the source of the TLV, followed by 1 octet of flags. A set
    # of optional sub-TLVs may follow the flag field."
    #
    #   Router ID   4 octets
    #   Flags       1 octet: | Reserved |D|S|, "S bit (0x01)", "D bit (0x02)"
    #   Sub-TLVs    the rest of the value, with no length octet of their own
    #
    # S floods the TLV across the whole routing domain; D marks one leaked
    # from Level 2 to Level 1. RFC 8667 section 3 puts its SR sub-TLVs here
    # with S clear.
    #
    # A value shorter than five octets is kept as a tail and replays.
    class RouterCapability < Tlv
      TYPE = 242
      S = 0x01
      D = 0x02

      attr_accessor :router_id, :flags, :subtlvs, :tail

      def s?
        (@flags & S).positive?
      end

      def d?
        (@flags & D).positive?
      end

      # { router_id:, subtlvs: }, with s:, d:, reserved:, tail: and type:
      # only when they are set.
      def to_hash
        return { tail: @tail.unpack1("H*") }.merge(unusual_type ? { type: unusual_type } : {}) if @router_id.nil?

        h = { router_id: @router_id.to_s }
        h[:s] = true if s?
        h[:d] = true if d?
        h[:reserved] = @flags & ~(S | D) unless (@flags & ~(S | D)).zero?
        sub = @subtlvs.to_hash
        h[:subtlvs] = sub[:tlvs] unless sub[:tlvs].empty?
        h[:subtlv_tail] = sub[:tail] if sub[:tail]
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        return "Router Capability, #{@tail.bytesize} octets" if @router_id.nil?

        f = [("S" if s?), ("D" if d?)].compact.join
        lines = ["Router Capability #{@router_id}#{f.empty? ? '' : " flags #{f}"}"]
        @subtlvs.each { |t| lines << "  #{t}" }
        lines.join("\n")
      end

      private

      def encode_value
        return @tail if @router_id.nil?

        @router_id.hton + [@flags].pack("C") + @subtlvs.encode
      end

      def parse(octets)
        value = read_frame(octets)
        if value.bytesize < 5
          @router_id = nil
          @flags = 0
          @subtlvs = SubTlv::List.new(TYPE, [])
          @tail = value
          return
        end
        @router_id = IPAddr.new_ntoh(value.byteslice(0, 4))
        @flags = value.getbyte(4)
        @subtlvs = SubTlv::List.parse_under(TYPE, Octets.new(value.byteslice(5..)))
        @tail = "".b
      end

      # RouterCapability.new(router_id: "10.255.0.1", subtlvs: [...]), the
      # sub-TLVs as objects or as hashes.
      def from_fields(router_id:, s: false, d: false, reserved: 0, subtlvs: [], subtlv_tail: "")
        a = IPAddr.new(router_id.to_s)
        raise ArgumentError, "not an IPv4 address: #{router_id.inspect}" unless a.ipv4? && a.prefix == 32

        @router_id = a
        @flags = (s ? S : 0) | (d ? D : 0) | (Integer(reserved) & 0xfc)
        @subtlvs = if subtlvs.all? { _1.is_a?(Hash) }
                     SubTlv::List.new(TYPE, { tlvs: subtlvs, tail: subtlv_tail })
                   else
                     SubTlv::List.new(TYPE, subtlvs)
                   end
        @tail = "".b
      end

      def from_hash(hash)
        if hash.key?(:router_id)
          from_fields(**hash.slice(:router_id, :s, :d, :reserved, :subtlv_tail), subtlvs: hash.fetch(:subtlvs, []))
        else
          @router_id = nil
          @flags = 0
          @subtlvs = SubTlv::List.new(TYPE, [])
          @tail = [hash.fetch(:tail, "")].pack("H*")
        end
        @type = hash[:type]
      end
    end

    register(RouterCapability::TYPE, :router_capability, RouterCapability)
  end
end
