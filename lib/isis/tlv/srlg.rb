# frozen_string_literal: true

require "ipaddr"

module ISIS
  class Tlv
    # What the two SRLG TLVs share: the neighbour, seven octets, as TLV 22
    # prints it, and the list of SRLG values, four octets each, to the end
    # of the value. Octets past the last whole value are a tail.
    module SrlgValues
      NEIGHBOR = 7

      attr_reader :neighbor, :srlgs, :tail, :short

      def neighbor_s
        hex = @neighbor.unpack1("H*")
        (hex[0...-2].scan(/.{1,4}/) + [hex[-2, 2]]).join(".")
      end

      private

      def read_srlgs(rest)
        whole = rest.bytesize / 4 * 4
        @srlgs = rest.byteslice(0, whole).unpack("N*")
        @tail = rest.byteslice(whole..).b
      end

      def srlg_octets
        @srlgs.pack("N*") + @tail
      end

      def srlgs_from(srlgs, tail)
        @srlgs = srlgs.map do |s|
          v = Integer(s)
          raise ArgumentError, "SRLG #{v} does not fit in 4 octets" unless (0..0xffff_ffff).cover?(v)

          v
        end
        @tail = [tail].pack("H*")
      end

      def neighbor_from(text)
        @neighbor = ExtendedIsReachability::Entry.neighbor_octets(text.to_s)
      end

      def srlg_hash(h)
        h[:srlgs] = @srlgs
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h
      end

      def short_hash
        { short: @short.unpack1("H*") }
      end
    end

    # TLV 138, the Shared Risk Link Group TLV, RFC 5307 section 1.4:
    #
    #   System ID (6), Pseudonode Number (1), Flags (1),
    #   IPv4 interface address or Link Local Identifier (4),
    #   IPv4 neighbor address or Link Remote Identifier (4),
    #   SRLG values, 4 octets each
    #
    # "The least significant bit of the Flag octet indicates whether the
    # interface is numbered (set to 1) or unnumbered (set to 0)." So the
    # two link fields print as IPv4 addresses when that bit is set, and as
    # numbers when it is clear. Fewer than 16 octets: kept whole as +short+.
    class Srlg < Tlv
      include SrlgValues

      TYPE = 138
      FIXED = 16
      NUMBERED = 0x01

      attr_reader :flags, :local, :remote

      def numbered? = @flags.anybits?(NUMBERED)

      def to_hash
        h = @short ? short_hash : body_hash
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        return "SRLG, #{@short.bytesize} octets" if @short

        "SRLG #{neighbor_s} #{link_text(@local)}/#{link_text(@remote)}: #{@srlgs.join(', ')}"
      end

      private

      def body_hash
        h = { neighbor: neighbor_s, numbered: numbered? }
        h[:reserved] = @flags & ~NUMBERED unless (@flags & ~NUMBERED).zero?
        h[:local] = link_text(@local)
        h[:remote] = link_text(@remote)
        srlg_hash(h)
      end

      def link_text(n)
        numbered? ? IPAddr.new(n, Socket::AF_INET).to_s : n
      end

      def link_value(v)
        numbered? ? IPAddr.new(v.to_s).to_i : Integer(v)
      end

      def encode_value
        return @short if @short

        @neighbor + [@flags, @local, @remote].pack("CNN") + srlg_octets
      end

      def parse(octets)
        value = read_frame(octets)
        if value.bytesize < FIXED
          @short = value
          return
        end
        @short = nil
        @neighbor = value.byteslice(0, NEIGHBOR).b
        @flags, @local, @remote = value.byteslice(NEIGHBOR, 9).unpack("CNN")
        read_srlgs(value.byteslice(FIXED..))
      end

      # Srlg.new(neighbor: "0000.0000.0002.00", local: "10.0.12.1", remote:
      # "10.0.12.2", srlgs: [10, 20]); numbered: false takes identifiers.
      def from_fields(neighbor:, local:, remote:, srlgs: [], numbered: true, reserved: 0, tail: "")
        @short = nil
        neighbor_from(neighbor)
        @flags = (numbered ? NUMBERED : 0) | (Integer(reserved) & 0xfe)
        @local = link_value(local)
        @remote = link_value(remote)
        srlgs_from(srlgs, tail)
      end

      def from_hash(hash)
        if hash.key?(:short)
          @short = [hash[:short]].pack("H*")
        else
          from_fields(**hash.slice(:neighbor, :local, :remote, :srlgs, :numbered, :reserved, :tail))
        end
        @type = hash[:type]
      end
    end

    # TLV 238, the Application-Specific SRLG TLV, RFC 9479 section 4.3:
    #
    #   Neighbor System-ID + pseudonode ID (7 octets)
    #   Application Identifier Bit Mask (section 4.1)
    #   Length of sub-TLVs (1 octet)
    #   Link Identifier sub-TLVs (variable)
    #   0 or more SRLG values (each value is 4 octets)
    #
    # The link identifier sub-TLVs are read from this TLV's own registry,
    # with section 4.3's Table 2: 4, 6, 8, 12 and 13. A value that cannot
    # be read that far (a short neighbour or mask, or a sub-TLV length
    # past the end) is kept whole as +short+.
    class AslaSrlg < Tlv
      include SrlgValues
      include SubTlv::ApplicationMask

      TYPE = 238

      attr_reader :links

      def to_hash
        h = @short ? short_hash : body_hash
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        return "Application-Specific SRLG, #{@short.bytesize} octets" if @short

        "Application-Specific SRLG #{neighbor_s} #{mask_text} [#{@links.map(&:to_s).join('; ')}]: #{@srlgs.join(', ')}"
      end

      private

      def body_hash
        h = mask_hash({ neighbor: neighbor_s })
        sub = @links.to_hash
        h[:links] = sub[:tlvs]
        h[:link_tail] = sub[:tail] if sub[:tail]
        srlg_hash(h)
      end

      def encode_value
        return @short if @short

        links = @links.encode
        @neighbor + mask_octets + [links.bytesize].pack("C") + links + srlg_octets
      end

      def parse(octets)
        value = read_frame(octets)
        @short = value
        return if value.bytesize < NEIGHBOR

        rest = read_mask(value.byteslice(NEIGHBOR..))
        return if rest.nil? || rest.empty? || rest.bytesize < 1 + rest.getbyte(0)

        @short = nil
        @neighbor = value.byteslice(0, NEIGHBOR).b
        n = rest.getbyte(0)
        @links = SubTlv::List.parse_under(TYPE, Octets.new(rest.byteslice(1, n)))
        read_srlgs(rest.byteslice((1 + n)..))
      end

      # AslaSrlg.new(neighbor: "0000.0000.0002.00", applications: %w[X],
      # links: [{ ipv4_interface_address: "10.0.12.1" }], srlgs: [10]).
      def from_fields(neighbor:, links: [], link_tail: "", srlgs: [], tail: "", **mask)
        @short = nil
        neighbor_from(neighbor)
        mask_from(**mask)
        @links = if links.all? { _1.is_a?(Hash) }
                   SubTlv::List.new(TYPE, { tlvs: links, tail: link_tail })
                 else
                   SubTlv::List.new(TYPE, links)
                 end
        srlgs_from(srlgs, tail)
      end

      def from_hash(hash)
        if hash.key?(:short)
          @short = [hash[:short]].pack("H*")
        else
          from_fields(**hash.slice(:neighbor, :links, :link_tail, :srlgs, :tail, *MASK_KEYS))
        end
        @type = hash[:type]
      end
    end

    register(Srlg::TYPE, :srlg, Srlg)
    register(AslaSrlg::TYPE, :asla_srlg, AslaSrlg)
  end

  class SubTlv
    # The link identifiers of TLV 238, RFC 9479 section 4.3, Table 2.
    [[LinkIdentifiers, :link_identifiers], [Ipv4InterfaceAddress, :ipv4_interface_address],
     [Ipv4NeighborAddress, :ipv4_neighbor_address], [Ipv6InterfaceAddress, :ipv6_interface_address],
     [Ipv6NeighborAddress, :ipv6_neighbor_address]].each do |klass, key|
      register_under(Tlv::AslaSrlg::TYPE, klass::TYPE, key, klass)
    end
  end

  class Tlv
    class AslaSrlg
      # The classes of Table 2.
      LINK_IDENTIFIERS = [SubTlv::LinkIdentifiers, SubTlv::Ipv4InterfaceAddress, SubTlv::Ipv4NeighborAddress,
                          SubTlv::Ipv6InterfaceAddress, SubTlv::Ipv6NeighborAddress].freeze
    end
  end
end
