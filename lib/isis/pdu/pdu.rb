# frozen_string_literal: true

module ISIS
  # An IS-IS PDU: the common header, a layout specific fixed header, and a
  # body. This file holds what every PDU shares: the common header, the
  # type registry, the factory with its parse policy, and the PDUs that
  # are not a layout: Unknown, Truncated and Malformed.
  #
  # Sources for the header fields. Not read in ISO/IEC 10589 or RFC 1142:
  # every field below is second hand, from two independent open source
  # implementations that agree, Wireshark (epan/dissectors/packet-isis.c
  # and packet-isis.h) and FRR (isisd/isis_pdu.c and isis_pdu.h), read on
  # 2026-10-31. Check each against the standard before relying on it.
  class Pdu
    include Node

    # Eight octets in every PDU. Wireshark and FRR (ISIS_FIXED_HDR_LEN).
    COMMON_HEADER = 8
    IRPD = 0x83
    # The type is the low five bits of the PDU Type octet, and the top
    # three are reserved. Wireshark: ISIS_TYPE_MASK, ISIS_TYPE_RESERVED_MASK.
    TYPE_MASK = 0x1f
    TYPE_RESERVED_MASK = 0xe0

    # The nine PDU types. Wireshark packet-isis.h and FRR isis_pdu.h agree.
    TYPES = {
      15 => :l1_lan_hello, 16 => :l2_lan_hello, 17 => :p2p_hello,
      18 => :l1_lsp, 20 => :l2_lsp,
      24 => :l1_csnp, 25 => :l2_csnp,
      26 => :l1_psnp, 27 => :l2_psnp
    }.freeze

    # How many octets a System ID is, from the ID Length field. Zero means
    # the default of six, 255 means a null System ID of no octets, and
    # anything else is the length itself. Second hand: Wireshark,
    # "zero means 6-octet ID field length" and "255 means null ID field".
    # FRR accepts only 0 and 6. Neither enforces a range, and nor does
    # this, since building never validates.
    def self.id_width(id_length)
      case id_length
      when 0 then 6
      when 255 then 0
      else id_length
      end
    end

    # The ID Length octet to write for a System ID of +width+ octets: the
    # default spelling for six, 255 for none.
    def self.id_length_for(width)
      case width
      when 6 then 0
      when 0 then 255
      else width
      end
    end

    @layouts = {}

    class << self
      # PDU type number => layout class. Unregistered types are Unknown.
      def register(type, klass)
        @layouts[type] = klass
      end

      def layout_for(type)
        @layouts[type]
      end

      # Read one PDU off the front of +octets+, within +boundary+ octets
      # (default: all of them). Consumes exactly the PDU's own octets and
      # leaves the rest, which belongs to the level above. CLAUDE.md, parse
      # rules 5 to 7:
      #
      # * fewer than eight octets, or fewer than the layout's fixed header:
      #   Truncated, holding what arrived, no layout built;
      # * a type with no layout: Unknown, opaque, not framed into TLVs;
      # * a declared PDU Length shorter than the fixed header: Malformed;
      # * a declared PDU Length past the boundary: the layout, with the
      #   TLVs that arrived, and the declared length kept for replay;
      # * a declared PDU Length inside the boundary: the layout, consuming
      #   exactly the declared extent.
      def factory(octets, boundary: octets.bytesize)
        boundary = [boundary, octets.bytesize].min
        return take(Truncated, octets, boundary) if boundary < COMMON_HEADER

        type = octets.getbyte(4) & TYPE_MASK
        layout = layout_for(type)
        return take(Unknown, octets, boundary) if layout.nil?

        fixed = COMMON_HEADER + layout.fixed_length(id_width(octets.getbyte(3)))
        return take(Truncated, octets, boundary) if boundary < fixed

        declared = layout.declared_pdu_length(octets)
        return take(Malformed, octets, boundary) if declared < fixed

        take(layout, octets, [declared, boundary].min)
      end

      private

      # Build +klass+ from the first +count+ octets, and remove them.
      def take(klass, octets, count)
        raw = Octets.new(octets.byteslice(0, count))
        octets.replace(octets.byteslice(count..) || "")
        klass.new(raw)
      end
    end

    # The common header, as a value. The Length Indicator is not here: it
    # is a computed field and belongs to the PDU, which knows its layout.
    class Header
      attr_accessor :version_ext, :id_length, :type_octet, :version, :reserved,
                    :max_area_addresses

      # Built from values, everything takes the value the specification
      # asks an encoder for, and the reserved bits are zero. Parsed,
      # everything is kept as it arrived, reserved bits included.
      def initialize(type:, id_length: 0, max_area_addresses: 0, version_ext: 1,
                     version: 1, reserved: 0)
        @type_octet = type
        @id_length = id_length
        @max_area_addresses = max_area_addresses
        @version_ext = version_ext
        @version = version
        @reserved = reserved
      end

      def self.parse(octets)
        new(type: octets.getbyte(4), id_length: octets.getbyte(3), max_area_addresses: octets.getbyte(7),
            version_ext: octets.getbyte(2), version: octets.getbyte(5), reserved: octets.getbyte(6))
      end

      def type
        @type_octet & TYPE_MASK
      end

      def reserved_type_bits
        @type_octet & TYPE_RESERVED_MASK
      end

      def id_width
        Pdu.id_width(@id_length)
      end

      def encode(length_indicator)
        [IRPD, length_indicator, @version_ext, @id_length, @type_octet, @version, @reserved,
         @max_area_addresses].pack("C8")
      end

      # The ordinary fields, plus any field that arrived unusual: a set
      # reserved bit, a version other than 1. An ordinary header hashes
      # without them, so the hash stays readable.
      def to_hash
        h = { type: Pdu::TYPES.fetch(type, type) }
        h[:id_length] = @id_length unless @id_length.zero?
        h[:max_area_addresses] = @max_area_addresses unless @max_area_addresses.zero?
        h[:type_bits] = reserved_type_bits unless reserved_type_bits.zero?
        h[:version_ext] = @version_ext unless @version_ext == 1
        h[:version] = @version unless @version == 1
        h[:reserved] = @reserved unless @reserved.zero?
        h
      end

      # Apply the unusual fields a hash carried, after a layout built the
      # ordinary ones.
      def apply_unusual(hash)
        @id_length = hash[:id_length] if hash.key?(:id_length)
        @type_octet = (@type_octet & TYPE_MASK) | hash[:type_bits] if hash.key?(:type_bits)
        @version_ext = hash[:version_ext] if hash.key?(:version_ext)
        @version = hash[:version] if hash.key?(:version)
        @reserved = hash[:reserved] if hash.key?(:reserved)
        self
      end
    end

    # A PDU whose type isis4r has no layout for. Opaque: nothing establishes
    # that its body is TLVs, or where they begin, so it is not framed into
    # them. It keeps every octet and replays them.
    class Unknown < Pdu
      attr_reader :octets

      # The PDU type number, or nil if the octets stop before it.
      def type
        @octets.getbyte(4)&.&(TYPE_MASK)
      end

      def encode
        @octets.b
      end

      def to_hash
        { octets: @octets.unpack1("H*") }
      end

      def to_s
        "PDU type #{type}, #{@octets.bytesize} octets, no layout"
      end

      private

      def parse(octets)
        @octets = octets.b
        octets.replace("")
      end

      def from_fields(octets)
        @octets = octets.b
      end

      def from_hash(hash)
        @octets = [hash.fetch(:octets)].pack("H*")
      end
    end

    # A PDU that stopped before its fixed header was complete. No layout is
    # built, because building one would invent octets that never arrived.
    # It keeps what did arrive and replays exactly that.
    class Truncated < Unknown
      def to_s
        "truncated PDU, #{@octets.bytesize} octets"
      end
    end

    # A PDU whose declared PDU Length is shorter than the fixed header its
    # own type requires, zero included. There is no honest reading of it,
    # so it is kept whole and the declared value never reaches arithmetic.
    class Malformed < Unknown
      def to_s
        "malformed PDU type #{type}, #{@octets.bytesize} octets"
      end
    end

    # What every layout shares: the common header, a fixed header written
    # by the subclass, and a TLV body. Lengths are computed fields:
    # computed when built from values, and replayed when parsed, until an
    # edit changes the octets they describe.
    class Layout < Pdu
      attr_reader :header, :tlvs

      class << self
        # Octets of this layout's fixed header after the common header, for
        # a System ID of +id_width+ octets.
        def fixed_length(_id_width)
          raise NotImplementedError
        end

        # The PDU Length a sender wrote, read from wire +octets+.
        def declared_pdu_length(_octets)
          raise NotImplementedError
        end
      end

      def type
        @header.type
      end

      def fixed_length
        COMMON_HEADER + self.class.fixed_length(@header.id_width)
      end

      # The octets of this PDU. If it was parsed and nothing has moved
      # since, the lengths it arrived with are written back, right or
      # wrong. Otherwise they are computed from the octets that exist.
      def encode
        body = @tlvs.encode
        if preserved?
          assemble(@declared_li, @declared_pdu_length, body)
        else
          assemble(fixed_length, fixed_length + body.bytesize, body)
        end
      end

      # True when this PDU was parsed and encode will replay the lengths it
      # arrived with, because no field and no TLV has changed since.
      def preserved?
        return false if @declared_li.nil?

        normalized == @retained
      end

      # Stop replaying the lengths this PDU arrived with. Encode computes
      # them from now on.
      def recompute!
        @declared_li = nil
        @declared_pdu_length = nil
        @retained = nil
        self
      end

      def declared_pdu_length
        @declared_pdu_length
      end

      private

      # The octets with both computed lengths zeroed. Compared against the
      # same view taken at parse time, it tells whether anything moved,
      # with no help from any child.
      def normalized
        assemble(0, 0, @tlvs.encode)
      end

      def assemble(length_indicator, pdu_length, body)
        out = ISIS.buffer
        out << @header.encode(length_indicator) << encode_fixed(pdu_length) << body
        out
      end

      # Consumes the declared extent, or everything given if the declared
      # length runs past it. Refuses octets this layout cannot hold, a
      # fixed header cut short or a PDU Length below it, which
      # Pdu.factory turns into Truncated or Malformed instead.
      def parse(octets)
        header_end = COMMON_HEADER + self.class.fixed_length(Pdu.id_width(octets.getbyte(3) || 0))
        raise ArgumentError, "#{octets.bytesize} octets cannot hold this fixed header; use Pdu.factory" if octets.bytesize < header_end

        @header = Header.parse(octets)
        @declared_li = octets.getbyte(1)
        @declared_pdu_length = self.class.declared_pdu_length(octets)
        raise ArgumentError, "declared PDU Length #{@declared_pdu_length} is below the fixed header; use Pdu.factory" if @declared_pdu_length < header_end

        extent = [@declared_pdu_length, octets.bytesize].min
        parse_fixed(octets.byteslice(COMMON_HEADER, header_end - COMMON_HEADER))
        @tlvs = Tlv::List.new(Octets.new(octets.byteslice(header_end, extent - header_end)))
        octets.replace(octets.byteslice(extent..) || "")
        @retained = normalized
      end
    end
  end
end
