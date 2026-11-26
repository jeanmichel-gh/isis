# frozen_string_literal: true

module ISIS
  # The algorithms this system takes part in, from the configuration's
  # flex_algo list (docs/design/flex-algo.md, "Configuration"), with the
  # FADs it advertises and the Prefix-SIDs each prefix has per algorithm:
  #
  #   flex_algo:
  #     - algorithm: 128          128 to 255 (RFC 9350 section 5.3)
  #       advertise: true         send the FAD; false: take part only
  #       priority: 128           0 to 255
  #       metric_type: igp        igp, delay or te (section 5.1)
  #       exclude_any: [red]      colors, names in affinity_map
  #       include_any: []
  #       include_all: []
  #       exclude_srlg: [10]      SRLG values
  #   prefixes:
  #     - prefix: 10.255.0.1/32
  #       sid: 1
  #       algorithm_sids: {128: 101}   one index per algorithm
  #
  # A key not listed here is refused, as is an algorithm twice, a color
  # not in affinity_map, or algorithm_sids for an algorithm not in
  # flex_algo. It needs segment_routing: participation is announced in
  # SR-Algorithm (RFC 9350 section 11). The M flag is not configurable
  # until the step that builds it.
  class FlexAlgoConfig
    KEYS = %i[algorithm advertise priority metric_type exclude_any include_any include_all exclude_srlg].freeze
    METRIC_TYPES = %w[igp delay te].freeze
    RULES = { exclude_any: :fad_exclude_admin_group, include_any: :fad_include_any_admin_group,
              include_all: :fad_include_all_admin_group }.freeze

    # One configured algorithm, its colors as groups.
    Entry = Struct.new(:algorithm, :advertise, :priority, :metric_type, :exclude_any, :include_any, :include_all,
                       :exclude_srlg, keyword_init: true) do
      # The FAD sub-TLV this system sends for it.
      def fad
        subs = RULES.filter_map { |key, sub| { sub => { groups: self[key] } } unless self[key].empty? }
        subs << { fad_exclude_srlg: { srlgs: exclude_srlg } } unless exclude_srlg.empty?
        SubTlv::Fad.new(algorithm: algorithm, metric_type: metric_type, priority: priority, subtlvs: subs)
      end

      def to_hash
        h = { algorithm: algorithm, advertise: advertise, priority: priority, metric_type: metric_type }
        %i[exclude_any include_any include_all exclude_srlg].each { |k| h[k] = self[k] unless self[k].empty? }
        h
      end
    end

    attr_reader :entries

    # +list+ the flex_algo list, +affinity_map+ names to groups (Router),
    # +segment_routing+ whether the configuration has it.
    def initialize(list, affinity_map:, segment_routing:)
      list = Array(list)
      raise ArgumentError, "flex_algo needs segment_routing" if !list.empty? && !segment_routing

      @affinity_map = affinity_map
      @entries = list.map { entry(_1) }
      twice = @entries.map(&:algorithm).tally.select { |_, n| n > 1 }.keys
      raise ArgumentError, "flex_algo: algorithm #{twice.join(', ')} more than once" unless twice.empty?
    end

    def algorithms = @entries.map(&:algorithm)

    def [](algorithm) = @entries.find { _1.algorithm == algorithm }

    def empty? = @entries.empty?

    # The FAD sub-TLVs this system advertises.
    def fads = @entries.select(&:advertise).map(&:fad)

    # Entry +algorithm+ changed by +changes+ (policy.flex_algo), checked as
    # the file is. Returns the new entry.
    def change(algorithm, changes)
      i = @entries.index { _1.algorithm == Integer(algorithm) }
      raise ArgumentError, "flex_algo has no algorithm #{algorithm}; it has #{algorithms.join(', ')}" unless i

      # The entry holds its colors as groups; they are checked again as
      # names, so each goes back to a name of the map.
      names = @affinity_map.invert
      base = @entries[i].to_hash.to_h { |k, v| [k, RULES.key?(k) ? v.map { names.fetch(_1) } : v] }
      e = entry(base.merge(changes.transform_keys(&:to_sym)).merge(algorithm: @entries[i].algorithm))
      @entries[i] = e
    end

    # The algorithm_sids of a prefix, { algorithm => index }, checked
    # against the configured algorithms.
    def algorithm_sids(prefix)
      sids = prefix[:algorithm_sids] or return {}
      raise ArgumentError, "prefix #{prefix[:prefix]}: algorithm_sids is a map of algorithm to index" unless sids.is_a?(Hash)

      sids.to_h do |a, index|
        a = Integer(a.to_s)
        raise ArgumentError, "prefix #{prefix[:prefix]}: algorithm_sids names #{a}, not in flex_algo" unless algorithms.include?(a)

        [a, Integer(index)]
      end
    end

    private

    def entry(h)
      raise ArgumentError, "a flex_algo entry is a map with algorithm" unless h.is_a?(Hash)

      h = h.transform_keys(&:to_sym)
      unknown = h.keys - KEYS
      unless unknown.empty?
        raise ArgumentError, "flex_algo: unknown #{unknown.size == 1 ? 'key' : 'keys'} #{unknown.join(', ')}; " \
                             "the keys are #{KEYS.join(', ')}"
      end
      algorithm = Integer(h.fetch(:algorithm) { raise ArgumentError, "a flex_algo entry needs algorithm" })
      raise ArgumentError, "flex_algo: algorithm #{algorithm} is not in 128 to 255" unless (128..255).cover?(algorithm)

      priority = Integer(h.fetch(:priority, 128))
      raise ArgumentError, "flex_algo #{algorithm}: priority #{priority} is not in 0 to 255" unless (0..255).cover?(priority)

      metric = h.fetch(:metric_type, "igp").to_s
      unless METRIC_TYPES.include?(metric)
        raise ArgumentError, "flex_algo #{algorithm}: metric_type is #{METRIC_TYPES.join(', ')}, not #{metric}"
      end

      Entry.new(algorithm: algorithm, advertise: h.fetch(:advertise, true) ? true : false, priority: priority,
                metric_type: metric, exclude_any: groups(algorithm, h[:exclude_any]),
                include_any: groups(algorithm, h[:include_any]), include_all: groups(algorithm, h[:include_all]),
                exclude_srlg: Array(h[:exclude_srlg]).map { srlg(algorithm, _1) }.uniq)
    end

    def groups(algorithm, colors)
      Array(colors).map do |c|
        @affinity_map.fetch(c.to_s) do
          raise ArgumentError, "flex_algo #{algorithm}: color #{c} is not in affinity_map" \
                               "#{@affinity_map.empty? ? '' : " (#{@affinity_map.keys.join(', ')})"}"
        end
      end.uniq.sort
    end

    def srlg(algorithm, v)
      return v if v.is_a?(Integer) && v.between?(0, 0xffff_ffff)

      raise ArgumentError, "flex_algo #{algorithm}: an SRLG is 0 to #{0xffff_ffff}, not #{v.inspect}"
    end
  end
end
