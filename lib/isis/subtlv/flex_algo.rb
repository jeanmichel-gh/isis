# frozen_string_literal: true

module ISIS
  class SubTlv
    # The Flexible Algorithm Definition sub-TLV, RFC 9350 section 5.1:
    # type 26 under TLV 242.
    #
    #   Flex-Algorithm (1), Metric-Type (1), Calc-Type (1), Priority (1),
    #   then sub-TLVs (section 6), read from the FAD's own registry,
    #   REGISTRY.
    #
    # Metric types 0, the IGP metric; 1, the minimum unidirectional link
    # delay; 2, the TE default metric. A calculation type of 0 is SPF.
    # Building never validates: an algorithm outside 128 to 255, or a metric
    # type past 2, is kept as given (Validation's FAD rules). A value too
    # short for the four fixed octets is kept whole as +short+.
    class Fad < SubTlv
      TYPE = 26
      # Section 18.1.3's "IS-IS Sub-Sub-TLVs for Flexible Algorithm
      # Definition Sub-TLV" registry.
      REGISTRY = "242.26"
      FIXED = 4
      METRIC_TYPES = { 0 => "igp", 1 => "delay", 2 => "te" }.freeze

      attr_reader :algorithm, :metric_type, :calc_type, :priority, :subtlvs, :short

      # The four fixed octets, which section 6 holds identical across the
      # FADs one system splits an algorithm into.
      def fixed = [@algorithm, @metric_type, @calc_type, @priority]

      # The metric type by name, or its number when unknown.
      def metric_name = METRIC_TYPES.fetch(@metric_type, @metric_type)

      def to_hash
        if @short
          h = { short: @short.unpack1("H*") }
        else
          h = { algorithm: @algorithm, metric_type: metric_name, calc_type: @calc_type, priority: @priority }
          sub = @subtlvs.to_hash
          h[:subtlvs] = sub[:tlvs] unless sub[:tlvs].empty?
          h[:subtlv_tail] = sub[:tail] if sub[:tail]
        end
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        return "FAD, #{@short.bytesize} octets" if @short

        head = "FAD #{@algorithm}: metric #{metric_name}, calc #{@calc_type}, priority #{@priority}"
        inner = @subtlvs.map(&:to_s)
        inner.empty? ? head : "#{head}; #{inner.join('; ')}"
      end

      private

      def encode_value
        @short || (fixed.pack("C4") + @subtlvs.encode)
      end

      def parse(octets)
        value = read_frame(octets)
        if value.bytesize < FIXED
          @short = value
          @subtlvs = nil
          return
        end
        @short = nil
        @algorithm, @metric_type, @calc_type, @priority = value.unpack("C4")
        @subtlvs = SubTlv::List.parse_under(REGISTRY, Octets.new(value.byteslice(FIXED..)))
      end

      # Fad.new(algorithm: 128, metric_type: "delay", priority: 200,
      # subtlvs: [{ fad_exclude_admin_group: { groups: [1] } }]). The
      # metric type by name or number.
      def from_fields(algorithm:, metric_type: 0, calc_type: 0, priority: 0, subtlvs: [], subtlv_tail: "")
        @short = nil
        @algorithm = octet("algorithm", algorithm)
        @metric_type = octet("metric_type", METRIC_TYPES.key(metric_type.to_s) || metric_type)
        @calc_type = octet("calc_type", calc_type)
        @priority = octet("priority", priority)
        @subtlvs = if subtlvs.all? { _1.is_a?(Hash) }
                     SubTlv::List.new(REGISTRY, { tlvs: subtlvs, tail: subtlv_tail })
                   else
                     SubTlv::List.new(REGISTRY, subtlvs)
                   end
      end

      def octet(name, value)
        v = Integer(value)
        raise ArgumentError, "#{name} #{v} does not fit in one octet" unless (0..255).cover?(v)

        v
      end

      def from_hash(hash)
        if hash.key?(:short)
          @short = [hash[:short]].pack("H*")
          @subtlvs = nil
        else
          from_fields(**hash.slice(:algorithm, :metric_type, :calc_type, :priority, :subtlv_tail),
                      subtlvs: hash.fetch(:subtlvs, []))
        end
        @type = hash[:type]
      end
    end

    # The three admin group rules of a FAD, RFC 9350 sections 6.1 to 6.3:
    # types 1 (exclude), 2 (include-any) and 3 (include-all), each an
    # Extended Admin Group, as RFC 7308 defines it. The group numbering is
    # ExtendedAdminGroup's. A length that is not a multiple of 4 leaves a
    # tail (Validation's fad_eag_length).
    class FadExcludeAdminGroup < ExtendedAdminGroup
      TYPE = 1
      NAME = "exclude"

      def to_s = "#{self.class::NAME} #{groups_text}"
    end

    class FadIncludeAnyAdminGroup < FadExcludeAdminGroup
      TYPE = 2
      NAME = "include-any"
    end

    class FadIncludeAllAdminGroup < FadExcludeAdminGroup
      TYPE = 3
      NAME = "include-all"
    end

    # The FAD Flags sub-TLV, RFC 9350 section 6.4: type 4, any number of
    # octets of flags, "starting with bit 0", the most significant bit of
    # the first octet. Bit 0 is M. "Bits that are not transmitted MUST be
    # treated as if they are set to 0."
    class FadFlags < SubTlv
      TYPE = 4
      FLAGS = %w[M].freeze

      # Every bit set, by number.
      def bits
        (0...(@octets.bytesize * 8)).select { |n| @octets.getbyte(n / 8).anybits?(0x80 >> (n % 8)) }
      end

      def m? = bits.include?(0)

      # { flags: ["M"], bits: [other bits], length: when not the fewest }.
      def to_hash
        named = bits.select { _1 < FLAGS.size }.map { FLAGS[_1] }
        h = { flags: named }
        other = bits.reject { _1 < FLAGS.size }
        h[:bits] = other unless other.empty?
        h[:length] = @octets.bytesize unless @octets.bytesize == minimal(bits)
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        list = bits.map { _1 < FLAGS.size ? FLAGS[_1] : "bit #{_1}" }
        "flags #{list.empty? ? 'none' : list.join(', ')}"
      end

      private

      def minimal(list) = list.empty? ? 1 : (list.max / 8) + 1

      def encode_value = @octets

      def parse(octets)
        @octets = read_frame(octets).b
      end

      # FadFlags.new(flags: %w[M]); bits: [9] for others, length: for more
      # octets than they need.
      def from_fields(flags: [], bits: [], length: nil)
        list = Array(flags).map do |f|
          FLAGS.index(f.to_s.upcase) or raise ArgumentError, "no flag #{f.inspect}; the flags are #{FLAGS.join}"
        end + Array(bits).map { Integer(_1) }
        length = length ? Integer(length) : minimal(list)
        out = Array.new(length, 0)
        list.each do |n|
          raise ArgumentError, "bit #{n} does not fit in #{length} octets" if n.negative? || n / 8 >= length

          out[n / 8] |= 0x80 >> (n % 8)
        end
        @octets = out.pack("C*")
      end

      def from_hash(hash)
        from_fields(**hash.slice(:flags, :bits, :length))
        @type = hash[:type]
      end
    end

    # The FAD Exclude SRLG sub-TLV, RFC 9350 section 6.5: type 5, SRLG
    # values of 4 octets each. Octets past the last whole value are a tail.
    class FadExcludeSrlg < SubTlv
      TYPE = 5

      attr_reader :srlgs, :tail

      def to_hash
        h = { srlgs: @srlgs }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s = "exclude SRLG #{@srlgs.empty? ? 'none' : @srlgs.join(', ')}"

      private

      def encode_value = @srlgs.pack("N*") + @tail

      def parse(octets)
        value = read_frame(octets)
        whole = value.bytesize / 4 * 4
        @srlgs = value.byteslice(0, whole).unpack("N*")
        @tail = value.byteslice(whole..).b
      end

      # FadExcludeSrlg.new(srlgs: [10, 20]).
      def from_fields(srlgs: [], tail: "")
        @srlgs = srlgs.map do |s|
          v = Integer(s)
          raise ArgumentError, "SRLG #{v} does not fit in 4 octets" unless (0..0xffff_ffff).cover?(v)

          v
        end
        @tail = [tail].pack("H*")
      end

      def from_hash(hash)
        from_fields(**hash.slice(:srlgs, :tail))
        @type = hash[:type]
      end
    end

    # The Flexible Algorithm Prefix Metric sub-TLV, RFC 9350 section 8:
    # type 6 under TLVs 135 and 236 (235 and 237 have no class here). The
    # algorithm, one octet, then "4 octets of metric information". Length 5.
    class Fapm < SubTlv
      include FixedValue

      TYPE = 6
      WIDTH = 5
      FIELDS = %i[algorithm metric].freeze
      DEFAULTS = { algorithm: 0, metric: 0 }.freeze

      attr_reader :algorithm, :metric

      def to_s
        @short ? "FAPM, #{@short.bytesize} octets" : "FAPM algorithm #{@algorithm} metric #{@metric}"
      end

      private

      def read_fields(octets)
        @algorithm, @metric = octets ? octets.unpack("CN") : [nil, nil]
      end

      def field_octets = [@algorithm, @metric].pack("CN")

      def fields_hash = { algorithm: @algorithm, metric: @metric }

      # Fapm.new(algorithm: 128, metric: 20).
      def from_fields(algorithm:, metric:, tail: "")
        @algorithm = check("algorithm", algorithm, 8)
        @metric = check("metric", metric, 32)
        setup(tail)
      end
    end

    register_under(Tlv::RouterCapability::TYPE, Fad::TYPE, :fad, Fad)
    [[FadExcludeAdminGroup, :fad_exclude_admin_group], [FadIncludeAnyAdminGroup, :fad_include_any_admin_group],
     [FadIncludeAllAdminGroup, :fad_include_all_admin_group], [FadFlags, :fad_flags],
     [FadExcludeSrlg, :fad_exclude_srlg]].each do |klass, key|
      register_under(Fad::REGISTRY, klass::TYPE, key, klass)
    end
    register_under(Tlv::ExtendedIpReachability::TYPE, Fapm::TYPE, :fapm, Fapm)
    register_under(Tlv::Ipv6Reachability::TYPE, Fapm::TYPE, :fapm, Fapm)
  end
end
