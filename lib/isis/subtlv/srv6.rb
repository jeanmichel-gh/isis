# frozen_string_literal: true

require "ipaddr"

module ISIS
  class SubTlv
    # What the three SRv6 SID sub-TLVs of RFC 9352 share: some fixed
    # fields, an Endpoint Behavior of "2 octets, as defined in [RFC8986]",
    # the "SID: 16 octets", then a Sub-sub-TLV-length octet and the
    # sub-sub-TLVs, from the registry "IS-IS Sub-Sub-TLVs for SRv6 SID
    # Sub-TLVs" (section 11.6), REGISTRY. Not registered itself.
    #
    # The behaviour is kept as its number, whatever it is: "Unsupported or
    # unrecognized behavior values are ignored by the receiver", which is
    # the receiver's decision, not the codec's. Its name comes from
    # ISIS::Srv6::BEHAVIORS. A value too short for the fixed fields and
    # the length octet is kept whole as +short+. Octets after a
    # sub-sub-TLV length shorter than what was left are a tail.
    class Srv6Sid < SubTlv
      include FlagOctet
      include FramedList

      REGISTRY = "srv6-sid"

      attr_reader :flags, :behavior, :sid_octets, :short, :tail

      # The SID as "fc00:0:1::".
      def sid = IPAddr.new_ntoh(@sid_octets).to_s

      def behavior_name = Srv6.behavior_name(@behavior)

      # The SID Structure sub-sub-TLV, the first if there are several.
      def structure = @subtlvs.find { _1.is_a?(Srv6SidStructure) }

      def to_hash
        h = if @short
              { short: @short.unpack1("H*") }
            else
              fixed_hash(flags_hash({})).merge(behavior: behavior_name, sid: sid).then { framed_list_hash(_1) }
            end
        h[:tail] = @tail.unpack1("H*") unless @short || @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        return "#{self.class::NAME}, #{@short.bytesize} octets" if @short

        f = flag_letters.empty? ? "" : " flags #{flag_letters.join}"
        inner = @subtlvs.map(&:to_s)
        ["#{self.class::NAME}#{fixed_text} #{sid} #{behavior_name}#{f}", *inner].join("; ")
      end

      private

      # The fixed fields before the behaviour, as octets: a subclass's.
      def fixed_octets = [@flags].pack("C")

      def fixed_hash(h) = h

      def fixed_text = ""

      # How many octets of fixed fields come before the behaviour.
      def fixed_width = 1

      def read_fixed(octets)
        @flags = octets.getbyte(0)
      end

      def encode_value
        return @short if @short

        fixed_octets + [@behavior].pack("n") + @sid_octets + framed_list_octets + @tail
      end

      def parse(octets)
        value = read_frame(octets)
        @tail = "".b
        head = fixed_width + 2 + 16
        if value.bytesize < head + 1
          @short = value
          @flags = 0
          @subtlvs = SubTlv::List.new(REGISTRY, [])
          return
        end
        @short = nil
        read_fixed(value.byteslice(0, fixed_width))
        @behavior = value.byteslice(fixed_width, 2).unpack1("n")
        @sid_octets = value.byteslice(fixed_width + 2, 16).b
        @tail = read_framed_list(value.byteslice(head..), REGISTRY)
      end

      def sid_from(sid)
        a = IPAddr.new(sid.to_s)
        raise ArgumentError, "not an IPv6 address: #{sid.inspect}" unless a.ipv6?

        a.hton.b
      end

      def behavior_from(behavior)
        n = Srv6.behavior_number(behavior)
        raise ArgumentError, "behaviour #{n} does not fit in 2 octets" unless (0..0xffff).cover?(n)

        n
      end

      def octet(name, value)
        v = Integer(value)
        raise ArgumentError, "#{name} #{v} does not fit in one octet" unless (0..255).cover?(v)

        v
      end

      def common_from(flags:, reserved:, behavior:, sid:, subtlvs:, subtlv_tail:, tail:)
        @short = nil
        @flags = flags_from(flags, reserved)
        @behavior = behavior_from(behavior)
        @sid_octets = sid_from(sid)
        framed_list_from(REGISTRY, subtlvs, subtlv_tail)
        @tail = [tail].pack("H*")
      end

      def from_hash(hash)
        if hash.key?(:short)
          from_fields(**self.class::EXAMPLE)
          @short = [hash[:short]].pack("H*")
          @subtlvs = SubTlv::List.new(REGISTRY, [])
        else
          from_fields(**hash.except(:type, :flags), flags: hash.fetch(:flags, []))
        end
        @type = hash[:type]
      end
    end

    # The SRv6 End SID sub-TLV, RFC 9352 section 7.2: type 5, in TLV 27.
    # "Flags: 1 octet. No flags are currently defined", so every bit is
    # reserved, kept and echoed. "SRv6 End SIDs inherit the
    # topology/algorithm from the parent locator."
    class Srv6EndSid < Srv6Sid
      TYPE = 5
      NAME = "End SID"
      FLAGS = [].freeze
      EXAMPLE = { behavior: 1, sid: "::" }.freeze

      private

      # Srv6EndSid.new(behavior: "End", sid: "fc00:0:1::",
      # subtlvs: [{ sid_structure: { block: 32, node: 16, function: 16, argument: 0 } }]).
      def from_fields(behavior:, sid:, flags: [], reserved: 0, subtlvs: [], subtlv_tail: "", tail: "")
        common_from(flags: flags, reserved: reserved, behavior: behavior, sid: sid, subtlvs: subtlvs,
                    subtlv_tail: subtlv_tail, tail: tail)
      end
    end

    # The SRv6 End.X SID sub-TLV, RFC 9352 section 8.1: type 43, in TLV
    # 22 (and 23, 25, 141, 222 and 223, which have no class here). Flags,
    # algorithm and weight before the behaviour; "the algorithm is
    # specified in the individual SID", not inherited.
    #
    #   B  backup: "the SID is eligible for protection"
    #   S  set: "the SID refers to a set of adjacencies"
    #   P  persistent: "the SID value remains consistent across router
    #      restart and/or interface flap"
    class Srv6EndXSid < Srv6Sid
      TYPE = 43
      NAME = "End.X SID"
      FLAGS = %w[B S P].freeze
      EXAMPLE = { behavior: 5, sid: "::" }.freeze

      attr_reader :algorithm, :weight

      private

      def fixed_width = 3

      def fixed_octets = [@flags, @algorithm, @weight].pack("CCC")

      def read_fixed(octets)
        @flags, @algorithm, @weight = octets.unpack("CCC")
      end

      def fixed_hash(h)
        h[:algorithm] = @algorithm
        h[:weight] = @weight unless @weight.zero?
        h
      end

      def fixed_text = @algorithm.zero? && @weight.zero? ? "" : " algorithm #{@algorithm} weight #{@weight}"

      # Srv6EndXSid.new(behavior: "End.X", sid: "fc00:0:1:1::",
      # flags: %w[B], algorithm: 0, weight: 0).
      def from_fields(behavior:, sid:, algorithm: 0, weight: 0, flags: [], reserved: 0, subtlvs: [], subtlv_tail: "",
                      tail: "")
        @algorithm = octet("algorithm", algorithm)
        @weight = octet("weight", weight)
        common_from(flags: flags, reserved: reserved, behavior: behavior, sid: sid, subtlvs: subtlvs,
                    subtlv_tail: subtlv_tail, tail: tail)
      end
    end

    # The SRv6 LAN End.X SID sub-TLV, RFC 9352 section 8.2: type 44, the
    # "Neighbor System-ID (ID length octets)" first, then the End.X SID's
    # fields. Unlike RFC 8667's LAN-Adj-SID, the System ID comes before
    # the flags.
    #
    # A sub-TLV is read without the PDU's ID Length (SubTlv.factory_under
    # takes none), so the System ID is read as six octets, as LanAdjSid
    # reads its own.
    class Srv6LanEndXSid < Srv6EndXSid
      TYPE = 44
      NAME = "LAN End.X SID"
      EXAMPLE = { neighbor: "0000.0000.0000", behavior: 5, sid: "::" }.freeze

      attr_reader :neighbor

      def neighbor_id = SystemId.from_bytes(@neighbor)

      private

      def fixed_width = SystemId::LENGTH + 3

      def fixed_octets = @neighbor + super

      def read_fixed(octets)
        @neighbor = octets.byteslice(0, SystemId::LENGTH).b
        super(octets.byteslice(SystemId::LENGTH..))
      end

      def fixed_hash(h) = { neighbor: neighbor_id.to_s }.merge(super)

      def fixed_text = " #{neighbor_id}#{super}"

      # Srv6LanEndXSid.new(neighbor: "0000.0000.0002", behavior: "End.X",
      # sid: "fc00:0:1:2::").
      def from_fields(neighbor:, **fields)
        @neighbor = SystemId.new(neighbor.to_s).encode.b
        super(**fields)
      end
    end

    # The SRv6 SID Structure sub-sub-TLV, RFC 9352 section 9: type 1 under
    # sub-TLVs 5, 43 and 44, "The length value is 4 octets": the locator
    # block, locator node, function and argument lengths in bits, one
    # octet each. Building never validates: a sum past 128, which makes
    # the receiver ignore the parent, is kept.
    class Srv6SidStructure < SubTlv
      include FixedValue

      TYPE = 1
      WIDTH = 4
      FIELDS = %i[block node function argument].freeze
      DEFAULTS = { block: 0, node: 0, function: 0, argument: 0 }.freeze

      attr_reader :block, :node, :function, :argument

      def total = @block + @node + @function + @argument

      def to_s
        @short ? "SID Structure, #{@short.bytesize} octets" : "SID Structure #{@block}/#{@node}/#{@function}/#{@argument}"
      end

      private

      def read_fields(octets)
        @block, @node, @function, @argument = octets ? octets.unpack("C4") : [nil] * 4
      end

      def field_octets = [@block, @node, @function, @argument].pack("C4")

      def fields_hash = { block: @block, node: @node, function: @function, argument: @argument }

      # Srv6SidStructure.new(block: 32, node: 16, function: 16, argument: 0).
      def from_fields(block:, node:, function:, argument: 0, tail: "")
        @block = check("block", block, 8)
        @node = check("node", node, 8)
        @function = check("function", function, 8)
        @argument = check("argument", argument, 8)
        setup(tail)
      end
    end

    # The SRv6 Capabilities sub-TLV, RFC 9352 section 2: type 25 under TLV
    # 242. "Flags: 2 octets", drawn "| |O|  Reserved  |": O, at bit 1,
    # "the router supports use of the O-bit in the SRH". "The remaining
    # bits, including bit 0, are reserved", kept and echoed, as reserved:.
    # Then "optional sub-sub-TLVs", from the registry "IS-IS Sub-Sub-TLVs
    # for SRv6 Capabilities Sub-TLV" (section 11.3), REGISTRY, in which
    # none is defined, so each is an Unknown. A value under two octets is
    # kept whole as +short+.
    class Srv6Capabilities < SubTlv
      TYPE = 25
      REGISTRY = "242.25"
      O_FLAG = 0x4000

      attr_reader :flags, :subtlvs, :short

      def o? = (@flags & O_FLAG).positive?

      def reserved_bits = @flags & ~O_FLAG & 0xffff

      def to_hash
        h = if @short
              { short: @short.unpack1("H*") }
            else
              base = {}
              base[:flags] = ["O"] if o?
              base[:reserved] = reserved_bits unless reserved_bits.zero?
              sub = @subtlvs.to_hash
              base[:subtlvs] = sub[:tlvs] unless sub[:tlvs].empty?
              base[:subtlv_tail] = sub[:tail] if sub[:tail]
              base
            end
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        return "SRv6 Capabilities, #{@short.bytesize} octets" if @short

        inner = @subtlvs.map(&:to_s)
        ["SRv6 Capabilities#{' flags O' if o?}", *inner].join("; ")
      end

      private

      def encode_value
        @short || ([@flags].pack("n") + @subtlvs.encode)
      end

      def parse(octets)
        value = read_frame(octets)
        if value.bytesize < 2
          @short = value
          @flags = 0
          @subtlvs = SubTlv::List.new(REGISTRY, [])
          return
        end
        @short = nil
        @flags = value.unpack1("n")
        @subtlvs = SubTlv::List.parse_under(REGISTRY, Octets.new(value.byteslice(2..)))
      end

      # Srv6Capabilities.new, or Srv6Capabilities.new(flags: %w[O]).
      def from_fields(flags: [], reserved: 0, subtlvs: [], subtlv_tail: "")
        bad = Array(flags).map(&:to_s).map(&:upcase) - ["O"]
        raise ArgumentError, "no flag #{bad.first.inspect}; the only flag is O" unless bad.empty?

        @short = nil
        @flags = (Array(flags).empty? ? 0 : O_FLAG) | (Integer(reserved) & 0xffff)
        @subtlvs = if Array(subtlvs).all? { _1.is_a?(Hash) }
                     SubTlv::List.new(REGISTRY, { tlvs: Array(subtlvs), tail: subtlv_tail })
                   else
                     SubTlv::List.new(REGISTRY, subtlvs)
                   end
      end

      def from_hash(hash)
        if hash.key?(:short)
          from_fields
          @short = [hash[:short]].pack("H*")
        else
          from_fields(**hash.slice(:flags, :reserved, :subtlvs, :subtlv_tail))
        end
        @type = hash[:type]
      end
    end

    register_under(Tlv::Srv6Locator::TYPE, Srv6EndSid::TYPE, :end_sid, Srv6EndSid)
    register_under(Tlv::ExtendedIsReachability::TYPE, Srv6EndXSid::TYPE, :end_x_sid, Srv6EndXSid)
    register_under(Tlv::ExtendedIsReachability::TYPE, Srv6LanEndXSid::TYPE, :lan_end_x_sid, Srv6LanEndXSid)
    register_under(Srv6Sid::REGISTRY, Srv6SidStructure::TYPE, :sid_structure, Srv6SidStructure)
    register_under(Tlv::RouterCapability::TYPE, Srv6Capabilities::TYPE, :srv6_capabilities, Srv6Capabilities)
  end
end
