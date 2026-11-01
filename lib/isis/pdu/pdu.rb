# frozen_string_literal: true

module ISIS
  # An IS-IS PDU: the common header, a layout specific fixed header, and a
  # body. This file holds what every PDU shares: the common header, the
  # type registry, the factory with its parse policy, and the PDUs that
  # are not a layout: Unknown, Truncated and Malformed.
  #
  # Sources for the header fields. Read in RFC 1142 clause 9 (the 1990
  # republication, so historical confirmation and not ISO/IEC 10589:2002),
  # and checked against two open source implementations, Wireshark
  # (epan/dissectors/packet-isis.c, packet-isis.h) and FRR (isisd/isis_pdu.c,
  # isis_pdu.h), on 2026-10-31. Where RFC 1142 and the implementations
  # differ, the comment beside the field says so.
  class Pdu
    include Node

    # Eight octets in every PDU: RFC 1142 clauses 9.5 to 9.13 all begin
    # with the same eight. Wireshark and FRR (ISIS_FIXED_HDR_LEN) agree.
    COMMON_HEADER = 8
    IRPD = 0x83
    # RFC 1142 clause 9.5: "PDU Type (bits 1 through 5) ... Note bits 6, 7
    # and 8 are Reserved". Bit 1 is the least significant (clause 9.1).
    TYPE_MASK = 0x1f
    TYPE_RESERVED_MASK = 0xe0

    # The nine PDU types, one per clause in RFC 1142 9.5 to 9.13.
    TYPES = {
      15 => :l1_lan_hello, 16 => :l2_lan_hello, 17 => :p2p_hello,
      18 => :l1_lsp, 20 => :l2_lsp,
      24 => :l1_csnp, 25 => :l2_csnp,
      26 => :l1_psnp, 27 => :l2_psnp
    }.freeze

    # How many octets a System ID is, from the ID Length field. RFC 1142
    # clause 9.5: "An integer between 1 and 8, inclusive, indicating an ID
    # field of the corresponding length", "The value zero, which indicates
    # a 6 octet ID field length", "The value 255, which means a null ID
    # field (i.e. zero length)", and "All other values are illegal". The
    # illegal values are validation's business, so this reads them as a
    # length, since building never validates. FRR accepts only 0 and 6.
    def self.id_width(id_length)
      case id_length
      when 0 then 6
      when 255 then 0
      else id_length
      end
    end

    # Dotted hex, "1921.6800.1001.00", to octets. Dots are separators only,
    # so any grouping parses. The forms routers print are conventions with
    # no clause behind them.
    def self.dotted_octets(text)
      hex = text.to_s.delete(".")
      raise ArgumentError, "not dotted hex: #{text.inspect}" unless hex.match?(/\A(\h\h)*\z/)

      [hex].pack("H*").b
    end

    # An LSP ID as routers print it, "1921.6800.1001.00-00": the System ID
    # in groups of four hex digits, the pseudonode octet after a dot and the
    # LSP Number after a hyphen. A convention with no clause behind it, and
    # lsp_id_octets reads it back.
    def self.lsp_id_s(octets)
      hex = octets.unpack1("H*")
      "#{(hex[0...-4].scan(/.{1,4}/) + [hex[-4, 2]]).join('.')}-#{hex[-2, 2]}"
    end

    # "1921.6800.1001.00-00" to octets. The hyphen is a separator like the
    # dots.
    def self.lsp_id_octets(text)
      dotted_octets(text.to_s.tr("-", "."))
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
    # RFC 1142 clause 9.5: "Length of the fixed header in octets".
    #
    # Octets 7 and 8 are where the editions part. RFC 1142 calls them ECO
    # and User ECO, both "transmitted as zero, ignored on receipt". Wireshark
    # and FRR read them as Reserved and Maximum Area Addresses, which is the
    # later edition's layout and what routers send. Both readings put zero
    # there by default, and the octets are kept as they arrive either way.
    # Maximum Area Addresses, and zero meaning three, are second hand from
    # Wireshark until ISO/IEC 10589:2002 is read.
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
    #
    # Authentication. When the TLVs hold an HMAC-MD5 Authentication TLV
    # (RFC 5304), encode fills its Authentication Value after the lengths
    # are written, and an LSP computes its checksum after that, over the
    # finished digest: CLAUDE.md, "One retained input per calculation". The
    # digest covers the whole PDU with the Authentication Value zeroed, and
    # an LSP also zeroes its Checksum and Remaining Lifetime (RFC 5304
    # section 2). Like the lengths, a parsed digest is replayed while
    # nothing it covers has moved. Once something has, a new one needs the
    # key; with none, encode raises, unless preserve_authentication! asks
    # for the retained digest on purpose. replay returns the octets as they
    # arrived, with no encode at all.
    class Layout < Pdu
      attr_reader :header, :tlvs
      # The authentication key, for the HMAC-MD5 digest. Never on the wire
      # and never in the hash.
      attr_accessor :key

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
        authenticate(lengths_encode)
      end

      # The octets this PDU was parsed from, exactly, or nil if it was
      # built. No encode step, so nothing to recompute and nothing to raise.
      def replay
        @replay
      end

      # True when this PDU was parsed with an HMAC-MD5 digest and encode
      # will replay it, because nothing the digest covers has moved.
      def authentication_preserved?
        at = auth_value_offset
        return false if at.nil? || @declared_auth.nil?

        digest_input(lengths_encode, at) == @retained_digest_input
      end

      # Encode with the digest this PDU arrived with even after what it
      # covers has moved: a PDU whose digest is wrong on purpose.
      def preserve_authentication!
        @preserve_authentication = true
        self
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
        @declared_auth = nil
        @retained_digest_input = nil
        @preserve_authentication = false
        self
      end

      def declared_pdu_length
        @declared_pdu_length
      end

      private

      # The octets with both computed lengths zeroed. Compared against the
      # same view taken at parse time, it tells whether anything moved,
      # with no help from any child.
      # The Authentication Value needs no zeroing here: encode writes the
      # digest into the octets and never into the TLV, so this view of it
      # does not move when a digest is computed.
      def normalized
        assemble(0, 0, @tlvs.encode)
      end

      def lengths_encode
        body = @tlvs.encode
        if preserved?
          assemble(@declared_li, @declared_pdu_length, body)
        else
          assemble(fixed_length, fixed_length + body.bytesize, body)
        end
      end

      def zero_digest
        ("\x00" * Tlv::Authentication::HMAC_MD5_LENGTH).b
      end

      # Where the first HMAC-MD5 Authentication Value sits in the encoded
      # PDU, or nil if there is none: past the fixed header and every TLV
      # before it, each measured by encoding it, then past that TLV's type,
      # length and authentication type octets.
      def auth_value_offset
        offset = fixed_length
        @tlvs.each do |t|
          return offset + 3 if t.is_a?(Tlv::Authentication) && t.hmac_md5?

          offset += t.encode.bytesize
        end
        nil
      end

      # What the digest is computed over: the PDU with the Authentication
      # Value zeroed, and whatever else the layout zeroes.
      def digest_input(octets, at)
        input = octets.b
        input[at, 16] = zero_digest
        digest_normalize(input)
      end

      # RFC 5304 section 2 zeroes nothing else in a hello or an SNP.
      def digest_normalize(input)
        input
      end

      def authenticate(octets)
        at = auth_value_offset
        return octets if at.nil? || octets.bytesize < at + 16

        input = digest_input(octets, at)
        octets[at, 16] =
          if @declared_auth && input == @retained_digest_input then @declared_auth
          elsif @key then ISIS.hmac_md5(@key, input)
          elsif @declared_auth && @preserve_authentication then @declared_auth
          else
            raise Error, "the HMAC-MD5 Authentication Value covers octets that #{@declared_auth ? 'changed' : 'were built'}; " \
                         "a key is needed to compute it (or preserve_authentication! to keep a stale one)"
          end
        octets
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
        @tlvs = Tlv::List.new(Octets.new(octets.byteslice(header_end, extent - header_end)),
                              id_width: @header.id_width)
        @replay = Octets.new(octets.byteslice(0, extent))
        octets.replace(octets.byteslice(extent..) || "")
        @retained = normalized
        retain_digest
      end

      def retain_digest
        at = auth_value_offset
        return unless at && @replay.bytesize >= at + 16

        @declared_auth = @replay.byteslice(at, 16).b
        @retained_digest_input = digest_input(@replay, at)
      end
    end
  end
end
