# frozen_string_literal: true

require "ipaddr"

module ISIS
  class SubTlv
    # A sub-TLV whose value is a fixed number of octets of fields. Fewer
    # octets than that cannot be read as fields and are kept whole as
    # +short+; more are a tail. Either way the octets replay as they came.
    #
    # A class sets WIDTH and FIELDS and defines read_fields, field_octets,
    # fields_hash and fields_from.
    module FixedValue
      attr_reader :short, :tail

      def to_hash
        h = @short ? { short: @short.unpack1("H*") } : fields_hash
        h[:tail] = @tail.unpack1("H*") unless @short || @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      private

      def encode_value
        @short || (field_octets + @tail)
      end

      def parse(octets)
        value = read_frame(octets)
        if value.bytesize < self.class::WIDTH
          @short = value
          @tail = "".b
          read_fields(nil)
        else
          @short = nil
          read_fields(value.byteslice(0, self.class::WIDTH))
          @tail = value.byteslice(self.class::WIDTH..).b
        end
      end

      def from_hash(hash)
        if hash.key?(:short)
          from_fields(**self.class::DEFAULTS)
          @short = [hash[:short]].pack("H*")
        else
          from_fields(**hash.slice(*self.class::FIELDS))
          @tail = [hash.fetch(:tail, "")].pack("H*")
        end
        @type = hash[:type]
      end

      def setup(tail)
        @short = nil
        @tail = [tail].pack("H*")
      end

      def check(name, value, bits)
        v = Integer(value)
        raise ArgumentError, "#{name} #{v} does not fit in #{bits} bits" unless (0...(1 << bits)).cover?(v)

        v
      end
    end

    # Admin groups as bits in 32-bit words, for the Administrative Group
    # sub-TLV (one word) and the Extended Administrative Group (any number).
    # RFC 5305 section 3.1: "the least significant bit is referred to as
    # 'group 0', and the most significant bit is referred to as 'group
    # 31'". RFC 7308 section 2.2: "bits 0-31 in the EAG have the same
    # meaning and MUST have the same values as an AG".
    #
    # Past bit 31, each word holds the next 32 groups, its least
    # significant bit first: group 32 is the low bit of the second word.
    # RFC 7308 section 2.2's own example ("the least significant bit in the
    # fifth byte of an 8-byte EAG is referred to as bit 32") can be read
    # otherwise. FRR 10.7.1 numbers by word, as here: with affinity bit
    # positions 1, 32 and 40 it sent 0e08 00000002 00000101, measured on
    # ospflab, 2026-11-25 (test/fixtures/frr-10.7.1-l2-lsp-flex-algo.hex).
    module GroupWords
      # The groups set, in ascending order.
      def groups
        @words.each_with_index.flat_map do |w, i|
          (0..31).select { |b| w[b] == 1 }.map { |b| (i * 32) + b }
        end
      end

      def group?(n)
        w = @words[n / 32]
        !w.nil? && w[n % 32] == 1
      end

      private

      def words_from(groups, count)
        words = Array.new(count, 0)
        groups.each do |g|
          g = Integer(g)
          raise ArgumentError, "group #{g} is negative" if g.negative?
          raise ArgumentError, "group #{g} does not fit in #{count * 32} bits" if g / 32 >= count

          words[g / 32] |= 1 << (g % 32)
        end
        words
      end

      def words_octets
        @words.pack("N*")
      end

      def groups_text
        groups.empty? ? "none" : groups.join(", ")
      end
    end

    # The Administrative Group sub-TLV, RFC 5305 section 3.1: type 3 under
    # TLV 22, "a 4-octet bit mask assigned by the network administrator".
    # RFC 9479 section 4.2 gives it the same number under the ASLA sub-TLV.
    class AdminGroup < SubTlv
      include FixedValue
      include GroupWords

      TYPE = 3
      WIDTH = 4
      FIELDS = %i[groups].freeze
      DEFAULTS = {}.freeze

      def to_s
        "Admin Group #{groups_text}"
      end

      private

      def read_fields(octets)
        @words = octets ? octets.unpack("N") : [0]
      end

      def field_octets
        words_octets
      end

      def fields_hash
        { groups: groups }
      end

      # AdminGroup.new(groups: [1, 5]).
      def from_fields(groups: [], tail: "")
        @words = words_from(groups, 1)
        setup(tail)
      end
    end

    # The Extended Administrative Group sub-TLV, RFC 7308 section 2.1: type
    # 14 for IS-IS. "The EAG may be of any non-zero length, but it MUST be
    # a multiple of 4 bytes." Octets past the last whole word are a tail.
    # Its size, in octets, is in the hash only when it is not the fewest
    # words that hold the groups (one word when none is set).
    class ExtendedAdminGroup < SubTlv
      include GroupWords

      TYPE = 14

      attr_reader :tail

      def size
        @words.size * 4
      end

      def to_hash
        h = { groups: groups }
        h[:size] = size unless size == minimal_size
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        "Extended Admin Group #{groups_text}"
      end

      private

      def minimal_size
        groups.empty? ? 4 : ((groups.max / 32) + 1) * 4
      end

      def encode_value
        words_octets + @tail
      end

      def parse(octets)
        value = read_frame(octets)
        whole = value.bytesize / 4 * 4
        @words = value.byteslice(0, whole).unpack("N*")
        @tail = value.byteslice(whole..).b
      end

      # ExtendedAdminGroup.new(groups: [1, 32, 40]), in the fewest words;
      # size: 12 for more.
      def from_fields(groups: [], size: nil, tail: "")
        g = groups.map { Integer(_1) }
        size ||= g.empty? ? 4 : ((g.max / 32) + 1) * 4
        raise ArgumentError, "size #{size} is not a multiple of 4" unless (size % 4).zero?

        @words = words_from(g, size / 4)
        @tail = [tail].pack("H*")
      end

      def from_hash(hash)
        from_fields(**hash.slice(:groups, :size, :tail))
        @type = hash[:type]
      end
    end

    # The Traffic Engineering Default Metric sub-TLV, RFC 5305 section
    # 3.7: type 18, "a 24-bit unsigned integer".
    class TeDefaultMetric < SubTlv
      include FixedValue

      TYPE = 18
      WIDTH = 3
      FIELDS = %i[metric].freeze
      DEFAULTS = { metric: 0 }.freeze

      attr_reader :metric

      def to_s
        @short ? "TE Default Metric, #{@short.bytesize} octets" : "TE Default Metric #{@metric}"
      end

      private

      def read_fields(octets)
        @metric = octets && ("\x00".b + octets).unpack1("N")
      end

      def field_octets
        [@metric].pack("N").byteslice(1, 3)
      end

      def fields_hash
        { metric: @metric }
      end

      # TeDefaultMetric.new(metric: 100).
      def from_fields(metric:, tail: "")
        @metric = check("metric", metric, 24)
        setup(tail)
      end
    end

    # The Unidirectional Link Delay sub-TLV, RFC 8570 section 4.1: type 33,
    # length 4, "|A|  RESERVED   |   Delay   |": the anomalous bit, seven
    # reserved bits, and "the average link delay ... in microseconds" in 24
    # bits. FRR 10.7.1 sends this one for its link-params delay, inside its
    # ASLA too, not the Min/Max sub-TLV.
    class LinkDelay < SubTlv
      include FixedValue

      TYPE = 33
      WIDTH = 4
      FIELDS = %i[delay anomalous reserved].freeze
      DEFAULTS = { delay: 0 }.freeze

      attr_reader :delay, :reserved

      def anomalous? = @anomalous

      def to_s
        return "Link Delay, #{@short.bytesize} octets" if @short

        "Link Delay #{@delay} us#{' anomalous' if @anomalous}"
      end

      private

      def read_fields(octets)
        first, @delay = octets ? split_delay(octets) : [0, nil]
        @anomalous = first.anybits?(0x80)
        @reserved = first & 0x7f
      end

      def split_delay(octets)
        [octets.getbyte(0), ("\x00".b + octets.byteslice(1, 3)).unpack1("N")]
      end

      def field_octets
        [(@anomalous ? 0x80 : 0) | @reserved].pack("C") + [@delay].pack("N").byteslice(1, 3)
      end

      def fields_hash
        h = { delay: @delay }
        h[:anomalous] = true if @anomalous
        h[:reserved] = @reserved unless @reserved.zero?
        h
      end

      # LinkDelay.new(delay: 5000), in microseconds.
      def from_fields(delay:, anomalous: false, reserved: 0, tail: "")
        @delay = check("delay", delay, 24)
        @anomalous = anomalous ? true : false
        @reserved = check("reserved", reserved, 7)
        setup(tail)
      end
    end

    # The Min/Max Unidirectional Link Delay sub-TLV, RFC 8570 section 4.2:
    # type 34, length 8, "|A| RESERVED | Min Delay |" then "| RESERVED |
    # Max Delay |", each delay in microseconds in 24 bits. RFC 9350 section
    # 5.1's metric type 1 is its Min Delay.
    class MinMaxLinkDelay < SubTlv
      include FixedValue

      TYPE = 34
      WIDTH = 8
      FIELDS = %i[min max anomalous reserved max_reserved].freeze
      DEFAULTS = { min: 0, max: 0 }.freeze

      attr_reader :min, :max, :reserved, :max_reserved

      def anomalous? = @anomalous

      def to_s
        return "Min/Max Link Delay, #{@short.bytesize} octets" if @short

        "Min/Max Link Delay #{@min}/#{@max} us#{' anomalous' if @anomalous}"
      end

      private

      def read_fields(octets)
        octets ||= "\x00".b * 8
        a, @min = [octets.getbyte(0), ("\x00".b + octets.byteslice(1, 3)).unpack1("N")]
        @max_reserved, @max = [octets.getbyte(4), ("\x00".b + octets.byteslice(5, 3)).unpack1("N")]
        @anomalous = a.anybits?(0x80)
        @reserved = a & 0x7f
      end

      def field_octets
        [(@anomalous ? 0x80 : 0) | @reserved].pack("C") + [@min].pack("N").byteslice(1, 3) +
          [@max_reserved].pack("C") + [@max].pack("N").byteslice(1, 3)
      end

      def fields_hash
        h = { min: @min, max: @max }
        h[:anomalous] = true if @anomalous
        h[:reserved] = @reserved unless @reserved.zero?
        h[:max_reserved] = @max_reserved unless @max_reserved.zero?
        h
      end

      # MinMaxLinkDelay.new(min: 5000, max: 6000), in microseconds.
      def from_fields(min:, max:, anomalous: false, reserved: 0, max_reserved: 0, tail: "")
        @min = check("min", min, 24)
        @max = check("max", max, 24)
        @anomalous = anomalous ? true : false
        @reserved = check("reserved", reserved, 7)
        @max_reserved = check("max_reserved", max_reserved, 8)
        setup(tail)
      end
    end

    # The Link Local/Remote Identifiers sub-TLV, RFC 5307 section 1.1: type
    # 4, "4 octets of Link Local Identifier followed by 4 octets of Link
    # Remote Identifier". RFC 9479 section 4.3 uses it as a link
    # identifier in TLV 238.
    class LinkIdentifiers < SubTlv
      include FixedValue

      TYPE = 4
      WIDTH = 8
      FIELDS = %i[local remote].freeze
      DEFAULTS = { local: 0, remote: 0 }.freeze

      attr_reader :local, :remote

      def to_s
        @short ? "Link Identifiers, #{@short.bytesize} octets" : "Link Identifiers #{@local}/#{@remote}"
      end

      private

      def read_fields(octets)
        @local, @remote = octets ? octets.unpack("NN") : [0, 0]
      end

      def field_octets
        [@local, @remote].pack("NN")
      end

      def fields_hash
        { local: @local, remote: @remote }
      end

      # LinkIdentifiers.new(local: 7, remote: 0); 0 when the remote one is
      # unknown (section 1.1).
      def from_fields(local:, remote: 0, tail: "")
        @local = check("local", local, 32)
        @remote = check("remote", remote, 32)
        setup(tail)
      end
    end

    # A sub-TLV whose value is one IPv6 address, sixteen octets: RFC 6119
    # sections 4.2 and 4.3, types 12 and 13 under TLV 22. RFC 9479 section
    # 4.3 uses both as link identifiers in TLV 238.
    class Ipv6Address < SubTlv
      include FixedValue

      WIDTH = 16
      FIELDS = %i[address].freeze
      DEFAULTS = { address: "::" }.freeze

      attr_reader :address

      def to_s
        @short ? "#{self.class::NAME}, #{@short.bytesize} octets" : "#{self.class::NAME} #{@address}"
      end

      private

      def read_fields(octets)
        @address = octets && IPAddr.new_ntoh(octets)
      end

      def field_octets
        @address.hton
      end

      def fields_hash
        { address: @address.to_s }
      end

      # Ipv6InterfaceAddress.new(address: "2001:db8::1").
      def from_fields(address:, tail: "")
        a = IPAddr.new(address.to_s)
        raise ArgumentError, "not an IPv6 address: #{address.inspect}" unless a.ipv6? && a.prefix == 128

        @address = a
        setup(tail)
      end
    end

    # RFC 6119 section 4.2: "The IPv6 Interface Address sub-TLV of the
    # Extended IS Reachability TLV has sub-TLV type 12."
    class Ipv6InterfaceAddress < Ipv6Address
      TYPE = 12
      NAME = "IPv6 Interface Address"
    end

    # RFC 6119 section 4.3: type 13.
    class Ipv6NeighborAddress < Ipv6Address
      TYPE = 13
      NAME = "IPv6 Neighbor Address"
    end

    # The Application Identifier Bit Mask, RFC 9479 section 4.1, which the
    # ASLA sub-TLV and TLV 238 share:
    #
    #   |L| SABM Length |   |R| UDABM Length|   SABM (0-8)   UDABM (0-8)
    #
    # Bits are numbered from the most significant bit of the first octet.
    # Standard bits 0 to 2 are R (RSVP-TE), S (SR Policy) and F (LFA)
    # (section 4.1); bit 3 is X, flex-algo (RFC 9350 section 12). So X is
    # 0x10.
    #
    # A length is kept as it arrived, past 8 too: section 4.2's "MUST be
    # ignored" is the receiver's decision. Too few octets for the masks the
    # lengths declare is not a mask; the class that includes this keeps
    # the whole value as +short+.
    module ApplicationMask
      APPLICATIONS = %w[R S F X].freeze

      attr_reader :sabm_length, :udabm_length

      def legacy? = @legacy

      # The standard applications set, by letter.
      def applications
        APPLICATIONS.each_index.select { bit?(@sabm, _1) }.map { APPLICATIONS[_1] }
      end

      def application?(letter)
        applications.include?(letter.to_s.upcase)
      end

      # Every SABM bit set, by number.
      def sabm_bits = bits(@sabm)

      # Every UDABM bit set, by number.
      def udabm_bits = bits(@udabm)

      private

      def bit?(octets, n)
        o = octets.getbyte(n / 8)
        !o.nil? && o.anybits?(0x80 >> (n % 8))
      end

      def bits(octets)
        (0...(octets.bytesize * 8)).select { bit?(octets, _1) }
      end

      # The rest of +value+ after the mask, or nil when the mask does not
      # fit in it.
      def read_mask(value)
        return nil if value.bytesize < 2

        a = value.getbyte(0)
        b = value.getbyte(1)
        @legacy = a.anybits?(0x80)
        @sabm_length = a & 0x7f
        @udabm_reserved = b.anybits?(0x80)
        @udabm_length = b & 0x7f
        return nil if value.bytesize < 2 + @sabm_length + @udabm_length

        @sabm = value.byteslice(2, @sabm_length).b
        @udabm = value.byteslice(2 + @sabm_length, @udabm_length).b
        value.byteslice((2 + @sabm_length + @udabm_length)..).b
      end

      def mask_octets
        [(@legacy ? 0x80 : 0) | @sabm_length, (@udabm_reserved ? 0x80 : 0) | @udabm_length].pack("CC") +
          @sabm + @udabm
      end

      def mask_hash(h)
        named = applications
        other = sabm_bits.reject { _1 < APPLICATIONS.size && named.include?(APPLICATIONS[_1]) }
        h[:applications] = named unless named.empty?
        h[:sabm_bits] = other unless other.empty?
        h[:sabm_length] = @sabm_length unless @sabm_length == minimal(sabm_bits)
        h[:legacy] = true if @legacy
        h[:udabm] = udabm_bits unless udabm_bits.empty?
        h[:udabm_length] = @udabm_length unless @udabm_length == minimal(udabm_bits)
        h[:udabm_reserved] = true if @udabm_reserved
        h
      end

      def minimal(list)
        list.empty? ? 0 : (list.max / 8) + 1
      end

      def mask_from(applications: [], sabm_bits: [], sabm_length: nil, legacy: false,
                    udabm: [], udabm_length: nil, udabm_reserved: false)
        std = Array(applications).map do |l|
          APPLICATIONS.index(l.to_s.upcase) or
            raise ArgumentError, "no application #{l.inspect}; they are #{APPLICATIONS.join}"
        end + Array(sabm_bits).map { Integer(_1) }
        user = Array(udabm).map { Integer(_1) }
        @sabm_length = sabm_length ? Integer(sabm_length) : minimal(std)
        @udabm_length = udabm_length ? Integer(udabm_length) : minimal(user)
        [@sabm_length, @udabm_length].each do |n|
          raise ArgumentError, "a mask length is 7 bits, not #{n}" unless (0..127).cover?(n)
        end
        @sabm = mask_octets_from(std, @sabm_length)
        @udabm = mask_octets_from(user, @udabm_length)
        @legacy = legacy ? true : false
        @udabm_reserved = udabm_reserved ? true : false
      end

      def mask_octets_from(list, length)
        out = Array.new(length, 0)
        list.each do |n|
          raise ArgumentError, "bit #{n} does not fit in a #{length} octet mask" if n.negative? || n / 8 >= length

          out[n / 8] |= 0x80 >> (n % 8)
        end
        out.pack("C*")
      end

      def mask_text
        apps = applications + (udabm_bits.empty? ? [] : ["user #{udabm_bits.join(',')}"])
        text = apps.empty? ? "any application" : apps.join(" ")
        @legacy ? "#{text}, legacy" : text
      end

      MASK_KEYS = %i[applications sabm_bits sabm_length legacy udabm udabm_length udabm_reserved].freeze
    end

    # The Application-Specific Link Attributes sub-TLV, RFC 9479 section
    # 4.2: type 16 under TLV 22. The Application Identifier Bit Mask, then
    # "Link Attribute sub-sub-TLVs -- format matches the existing formats
    # defined in [RFC5305], [RFC7308], and [RFC8570]", under the legacy
    # numbers (section 7.3). They are read from their own registry,
    # REGISTRY, where the classes above are registered a second time.
    #
    # Value too short for the mask it declares: kept whole as +short+.
    class Asla < SubTlv
      include ApplicationMask

      TYPE = 16
      # The registry of the sub-sub-TLVs: section 7.3's "IS-IS Sub-Sub-TLV
      # Codepoints for Application-Specific Link Attributes".
      REGISTRY = "22.16"

      attr_reader :subtlvs, :short

      # The attribute of class +klass+, or nil.
      def attribute(klass)
        @subtlvs&.find { _1.is_a?(klass) }
      end

      def to_hash
        if @short
          h = { short: @short.unpack1("H*") }
        else
          h = mask_hash({})
          sub = @subtlvs.to_hash
          h[:subtlvs] = sub[:tlvs] unless sub[:tlvs].empty?
          h[:subtlv_tail] = sub[:tail] if sub[:tail]
        end
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        return "ASLA, #{@short.bytesize} octets" if @short

        inner = @subtlvs.map(&:to_s)
        "ASLA #{mask_text}#{": #{inner.join('; ')}" unless inner.empty?}"
      end

      private

      def encode_value
        @short || (mask_octets + @subtlvs.encode)
      end

      def parse(octets)
        value = read_frame(octets)
        rest = read_mask(value)
        if rest.nil?
          @short = value
          @subtlvs = nil
        else
          @short = nil
          @subtlvs = SubTlv::List.parse_under(REGISTRY, Octets.new(rest))
        end
      end

      # Asla.new(applications: %w[X], subtlvs: [{ te_default_metric: {
      # metric: 100 } }]), the attributes as objects or hashes.
      def from_fields(subtlvs: [], subtlv_tail: "", **mask)
        mask_from(**mask)
        @short = nil
        @subtlvs = if subtlvs.all? { _1.is_a?(Hash) }
                     SubTlv::List.new(REGISTRY, { tlvs: subtlvs, tail: subtlv_tail })
                   else
                     SubTlv::List.new(REGISTRY, subtlvs)
                   end
      end

      def from_hash(hash)
        if hash.key?(:short)
          @short = [hash[:short]].pack("H*")
          @subtlvs = nil
        else
          from_fields(**hash.slice(*MASK_KEYS, :subtlv_tail), subtlvs: hash.fetch(:subtlvs, []))
        end
        @type = hash[:type]
      end
    end

    # Under TLV 22 (RFC 5305, 5307, 6119, 7308, 8570, 9479).
    [[AdminGroup, :admin_group], [ExtendedAdminGroup, :extended_admin_group], [TeDefaultMetric, :te_default_metric],
     [LinkDelay, :link_delay], [MinMaxLinkDelay, :min_max_link_delay], [LinkIdentifiers, :link_identifiers],
     [Ipv6InterfaceAddress, :ipv6_interface_address], [Ipv6NeighborAddress, :ipv6_neighbor_address],
     [Asla, :asla]].each do |klass, key|
      register_under(Tlv::ExtendedIsReachability::TYPE, klass::TYPE, key, klass)
    end

    # Under the ASLA sub-TLV, the numbers RFC 9479 section 7.3's Table 5
    # gives them. The bandwidth and loss sub-sub-TLVs stay unknown.
    [[AdminGroup, :admin_group], [ExtendedAdminGroup, :extended_admin_group], [TeDefaultMetric, :te_default_metric],
     [LinkDelay, :link_delay], [MinMaxLinkDelay, :min_max_link_delay]].each do |klass, key|
      register_under(Asla::REGISTRY, klass::TYPE, key, klass)
    end
  end
end
