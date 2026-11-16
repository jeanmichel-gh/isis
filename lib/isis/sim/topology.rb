# frozen_string_literal: true

require "ipaddr"

module ISIS
  module Sim
    # A simulated IS-IS area, as plain data: the simulator, which is a real
    # IS-IS system with interfaces, the simulated systems behind it, and the
    # links between them. The simulator turns it into LSPs; this class only
    # reads, expands and checks it.
    #
    # The file, after ospfv2's simulator:
    #
    #   simulator:                  the real system: isisd's own keys
    #     system_id: 0000.0000.0009   (ISIS::Router), and lsp_lifetime for
    #     hostname: s1                the simulated LSPs
    #     areas: [49.0001]
    #     level: 1
    #     interfaces: [...]
    #     lsp_lifetime: 1200
    #   grid:                       optional: rows x columns, r1c1 .. rRcC
    #     columns: 4
    #     rows: 4
    #     metric: 10
    #     system_id_base: 0000.0001.0000   r2c3 is the base plus 0x0203
    #     loopbacks: 10.200.0.0/24         a /32 each, row by row, metric 0
    #   routers:                    more systems, or more on a grid one
    #     - name: edge
    #       system_id: 0000.0000.0100
    #       level: 1-2
    #       attached: true
    #       loopback: 10.255.1.1
    #       prefixes: [{ prefix: 30.0.0.0/24, count: 50, metric: 10 }]
    #       externals: [{ prefix: 50.0.0.0/24, count: 200, metric: 20 }]
    #   links:
    #     - { from: s1, to: r1c1, metric: 10 }
    #   segment_routing:            optional: SR-MPLS (RFC 8667) for every
    #     srgb: [{ start: 16000, size: 8000 }]   simulated system, with
    #     srlb: { start: 15000, size: 1000 }     these blocks by default
    #
    # With segment_routing, a grid's sids gives r1c1 that index and each
    # next system the next, row by row, on its loopback; a router's sid gives
    # its loopback's, and its srgb its own block. A system with a sid needs
    # an IPv4 loopback, the Router ID its TLV 242 carries.
    #
    # It refuses what cannot be put in an LSP: a metric too large for the
    # metric style, a System ID that is not six octets, a lifetime over
    # sixteen bits. Odd but sendable choices, a one way link or a link
    # metric of 0xFFFFFF, are kept, since a simulator exists to send them.
    # Every problem in a file is reported at once, with where it is.
    class Topology
      class Error < StandardError; end

      # One prefix as it goes in an LSP. +group+ is the prefix a count was
      # given from, so a group can be withdrawn by its first prefix.
      Prefix = Struct.new(:prefix, :metric, :group, :sid, keyword_init: true) do
        def to_h = sid ? { prefix: prefix, metric: metric, sid: sid } : { prefix: prefix, metric: metric }
      end

      # One system. +levels+ is [1], [2] or [1, 2]; +grid+ is [row, column]
      # for a grid system.
      System = Struct.new(:name, :system_id, :hostname, :levels, :areas, :attached, :overload, :loopback,
                          :prefixes, :externals, :lsp_buffer_size, :grid, :simulator, :sid, :srgb,
                          keyword_init: true) do
        def simulator? = simulator ? true : false
      end

      # One link, named "from--to". +levels+ are those it is carried at:
      # the levels both ends run, Level 1 only with an area in common.
      Link = Struct.new(:from, :to, :metric, :one_way, :state, :levels, keyword_init: true) do
        def name = "#{from}--#{to}"
        def up? = state != :down
      end

      TOP_KEYS = %w[simulator grid routers links segment_routing].freeze
      GRID_KEYS = %w[columns rows metric system_id_base loopbacks level areas sids].freeze
      ROUTER_KEYS = %w[name system_id hostname level areas attached overload loopback prefixes externals
                       lsp_buffer_size sid srgb].freeze
      SR_KEYS = %w[srgb srlb].freeze
      PREFIX_KEYS = %w[prefix count metric].freeze
      LINK_KEYS = %w[from to metric one_way state].freeze
      SIM_ONLY_KEYS = %w[lsp_lifetime].freeze

      # The largest value each metric style can carry: the six bit original
      # metric (RFC 1142 9.8, RFC 1195 5.3.4), and RFC 5305's three octet
      # link metric (section 3) and four octet prefix metric (section 4).
      # Transition sends both, so it takes the narrow limits.
      LIMITS = { wide: { link: 0xFFFFFF, prefix: 0xFFFFFFFF }, narrow: { link: 63, prefix: 63 },
                 transition: { link: 63, prefix: 63 } }.freeze
      MAX_COUNT = 100_000
      DEFAULT_LIFETIME = Database::MAX_AGE
      DEFAULT_GRID_BASE = "0000.0001.0000"

      attr_reader :simulator, :systems, :links, :warnings, :lsp_lifetime, :metric_style, :router_config, :source
      # The segment_routing block as { srgb: [[first, size]], srlb: [first,
      # size] }, or nil when the file has none.
      attr_reader :segment_routing

      def self.load(path)
        from_hash(ConfigFile.load(path), source: path)
      rescue ArgumentError => e
        raise Error, e.message
      rescue SystemCallError => e
        raise Error, "#{path}: #{e.message}"
      end

      def self.from_hash(hash, source: "topology")
        new(hash, source: source)
      end

      def initialize(hash, source: "topology")
        @source = source
        @errors = []
        @warnings = []
        @systems = []
        @links = []
        read(stringify(hash || {}))
        raise Error, (["#{source}: #{@errors.size} problem#{'s' unless @errors.size == 1}"] + @errors).join("\n  ") unless @errors.empty?
      end

      # The simulator first, then every simulated system.
      def all_systems = [@simulator] + @systems

      # A system by name or System ID; the simulator also answers to "sim".
      def system(ref)
        ref = ref.to_s
        return @simulator if ref == "sim"

        all_systems.find { |s| s.name == ref || s.system_id == ref }
      end

      # A link by name, either way round, or by its number from 1.
      def link(ref)
        return @links[Integer(ref) - 1] if ref.is_a?(Integer) || ref.to_s.match?(/\A\d+\z/)

        a, b = ref.to_s.split("--", 2)
        @links.find { |l| [l.from, l.to] == [a, b] || [l.from, l.to] == [b, a] }
      end

      # The links of +system+, by name.
      def links_of(name) = @links.select { |l| l.from == name || l.to == name }

      def counts
        { systems: @systems.size, links: @links.size, prefixes: @systems.sum { _1.prefixes.size },
          externals: @systems.sum { _1.externals.size } }
      end

      # Every system and link written out, grid and counts expanded: a
      # topology this hash builds again, system by system.
      def to_h
        sim = @router_config.merge(lsp_lifetime: @lsp_lifetime)
        block = ->(list) { list.map { |first, size| { start: first, size: size } } }
        routers = @systems.map do |s|
          # The loopback goes back as loopback:, its sid as sid:, so the
          # file reads again; it leads the prefixes, as reading puts it.
          lo = s.loopback && s.prefixes.first&.prefix == s.loopback
          { name: s.name, system_id: s.system_id, hostname: s.hostname, level: level_text(s.levels), areas: s.areas,
            attached: s.attached, overload: s.overload, loopback: lo ? s.loopback.split("/").first : nil,
            prefixes: (lo ? s.prefixes.drop(1) : s.prefixes).map { _1.to_h.except(:sid) },
            externals: s.externals.map(&:to_h), lsp_buffer_size: s.lsp_buffer_size, sid: s.sid,
            srgb: s.srgb && block.(s.srgb) }.compact
        end
        sr = @segment_routing && { segment_routing: { srgb: block.(@segment_routing[:srgb]),
                                                      srlb: block.([@segment_routing[:srlb]]).first } }
        { simulator: sim, routers: routers,
          links: @links.map { |l| { from: l.from, to: l.to, metric: l.metric, one_way: l.one_way || nil, state: l.state == :down ? "down" : nil }.compact } }
          .merge(sr || {})
      end

      private

      def read(h)
        unknown(h, TOP_KEYS, "top level")
        read_simulator(h["simulator"])
        return unless @simulator

        read_segment_routing(h["segment_routing"]) if h.key?("segment_routing")
        read_grid(h["grid"]) if h.key?("grid")
        Array(h["routers"]).each_with_index { |r, i| read_router(r, "routers[#{i}]") }
        read_ids
        Array(h["links"]).each_with_index { |l, i| read_link(l, "links[#{i}]") }
        read_reachable
        check_sids
      end

      # The blocks every simulated system with SR uses by default. They must
      # be blocks SegmentRouting would advertise.
      def read_segment_routing(sr)
        return error("segment_routing", "is a map of #{SR_KEYS.join(', ')}") unless sr.is_a?(Hash)

        unknown(sr, SR_KEYS, "segment_routing")
        srgb = sr.key?("srgb") ? blocks(sr["srgb"], "segment_routing.srgb") : SegmentRouting::SRGB.map(&:dup)
        srlb = sr.key?("srlb") ? blocks([sr["srlb"]], "segment_routing.srlb")&.first : SegmentRouting::SRLB.dup
        return unless srgb && srlb

        begin
          SegmentRouting.check_blocks(srgb + [srlb])
        rescue ArgumentError => e
          return error("segment_routing", e.message)
        end
        @segment_routing = { srgb: srgb, srlb: srlb }
      end

      # A list of { start, size } as [[first, size]], or nil after an error.
      def blocks(list, at)
        return error(at, "is a list of { start, size }") unless list.is_a?(Array) && list.all?(Hash)

        list.each_with_index.map do |b, i|
          first = integer(b["start"], "#{at}[#{i}].start", 16, 0xfffff) or return nil
          size = integer(b["size"], "#{at}[#{i}].size", 1, 0xfffff) or return nil
          [first, size]
        end
      end

      # A sid needs segment_routing and an IPv4 loopback; an index used twice
      # is kept, since a simulator exists to send it, and warned of.
      def check_sids
        with = all_systems.select(&:sid)
        return if with.empty?

        with.each do |sys|
          error("#{sys.name}.sid", "needs a segment_routing section") unless @segment_routing
          error("#{sys.name}.sid", "needs an IPv4 loopback, the Router ID of its TLV 242") unless sys.loopback && !sys.loopback.include?(":")
        end
        with.group_by(&:sid).each do |sid, list|
          @warnings << "index #{sid} is the Prefix-SID of #{list.map(&:name).join(' and ')}" if list.size > 1
        end
      end

      def read_simulator(s)
        return error("simulator", "is needed: the real system, with its system_id and interfaces") unless s.is_a?(Hash)

        @lsp_lifetime = s.key?("lsp_lifetime") ? integer(s["lsp_lifetime"], "simulator.lsp_lifetime", 1, 0xFFFF) : DEFAULT_LIFETIME
        config = s.reject { |k, _| SIM_ONLY_KEYS.include?(k) }
        begin
          @router_config = Router.normalize(config)
          levels = Router.levels(@router_config.fetch(:level, 1))
        rescue ArgumentError => e
          return error("simulator", e.message)
        end
        @metric_style = @router_config.fetch(:metric_style, "wide").to_sym
        return error("simulator.metric_style", "is wide, narrow or transition") unless LIMITS.key?(@metric_style)

        id = system_id(s["system_id"], "simulator.system_id") or return
        name = (s["hostname"] || "sim").to_s
        @simulator = System.new(name: name, system_id: id, hostname: name, levels: levels,
                                areas: areas(s["areas"] || ["49.0001"], "simulator.areas"), prefixes: [], externals: [],
                                simulator: true)
      end

      def read_grid(g)
        return error("grid", "is a map of #{GRID_KEYS.join(', ')}") unless g.is_a?(Hash)

        unknown(g, GRID_KEYS, "grid")
        rows = integer(g["rows"], "grid.rows", 1, 255)
        columns = integer(g["columns"], "grid.columns", 1, 255)
        return unless rows && columns

        metric = g.key?("metric") ? link_metric(g["metric"], "grid.metric") : 10
        base = system_id(g["system_id_base"] || DEFAULT_GRID_BASE, "grid.system_id_base") or return
        base = base.delete(".").to_i(16)
        levels = level(g["level"], "grid.level") || @simulator.levels
        grid_areas = g.key?("areas") ? areas(g["areas"], "grid.areas") : @simulator.areas
        loopbacks = grid_loopbacks(g["loopbacks"], rows * columns)
        sids = g.key?("sids") ? integer(g["sids"], "grid.sids", 0, 0xffff_ffff - (rows * columns)) : nil
        error("grid.sids", "needs grid.loopbacks: a SID goes on a loopback") if sids && !loopbacks
        (1..rows).each do |r|
          (1..columns).each do |c|
            n = (r - 1) * columns + c
            id = format("%012x", base + (r << 8) + c).scan(/.{4}/).join(".")
            lo = loopbacks && loopbacks[n - 1]
            @systems << System.new(name: "r#{r}c#{c}", system_id: id, hostname: "r#{r}c#{c}", levels: levels,
                                   areas: grid_areas, attached: false, overload: false, loopback: lo,
                                   prefixes: lo ? [Prefix.new(prefix: lo, metric: 0, group: lo, sid: sids && sids + n - 1)] : [],
                                   externals: [], grid: [r, c], sid: sids && sids + n - 1)
          end
        end
        (1..rows).each do |r|
          (1..columns).each do |c|
            add_link("r#{r}c#{c}", "r#{r}c#{c + 1}", metric, false, :up, "grid") if c < columns
            add_link("r#{r}c#{c}", "r#{r + 1}c#{c}", metric, false, :up, "grid") if r < rows
          end
        end
      end

      def grid_loopbacks(block, count)
        return nil if block.nil?

        net = ip(block, "grid.loopbacks") or return nil
        room = (net.ipv4? ? 32 : 128) - net.prefix
        return error("grid.loopbacks", "#{block} holds fewer than the #{count} the grid needs") if room < 63 && (2**room) - 1 < count

        host = net.ipv4? ? 32 : 128
        (1..count).map { |i| "#{IPAddr.new(net.to_i + i, net.family)}/#{host}" }
      end

      def read_router(r, at)
        return error(at, "is a map with a name") unless r.is_a?(Hash) && r["name"]

        unknown(r, ROUTER_KEYS, at)
        name = r["name"].to_s
        sys = system(name)
        if sys&.simulator?
          return error("#{at}.name", "#{name} is the simulator; its own prefixes go in simulator:")
        elsif sys
          error("#{at}.system_id", "#{name} is a grid system, whose System ID the grid gives") if r.key?("system_id")
        else
          id = system_id(r["system_id"], "#{at}.system_id") or return
          sys = System.new(name: name, system_id: id, hostname: name, levels: @simulator.levels,
                           areas: @simulator.areas, attached: false, overload: false, prefixes: [], externals: [])
          @systems << sys
        end
        sys.hostname = r["hostname"].to_s if r.key?("hostname")
        error("#{at}.hostname", "is over 255 octets, more than TLV 137 holds") if sys.hostname.bytesize > 255
        sys.levels = level(r["level"], "#{at}.level") || sys.levels if r.key?("level")
        sys.areas = areas(r["areas"], "#{at}.areas") if r.key?("areas")
        sys.attached = flag(r["attached"], "#{at}.attached") if r.key?("attached")
        sys.overload = flag(r["overload"], "#{at}.overload") if r.key?("overload")
        sys.lsp_buffer_size = integer(r["lsp_buffer_size"], "#{at}.lsp_buffer_size", 64, 0xFFFF) if r.key?("lsp_buffer_size")
        if r.key?("loopback")
          lo = ip(r["loopback"], "#{at}.loopback")
          if lo
            sys.loopback = "#{lo}/#{lo.ipv4? ? 32 : 128}"
            sys.prefixes << Prefix.new(prefix: sys.loopback, metric: 0, group: sys.loopback)
          end
        end
        sys.prefixes.concat(prefixes(r["prefixes"], "#{at}.prefixes"))
        sys.externals.concat(prefixes(r["externals"], "#{at}.externals"))
        if r.key?("srgb")
          sys.srgb = blocks(r["srgb"], "#{at}.srgb")
          begin
            SegmentRouting.check_blocks(sys.srgb + [@segment_routing&.dig(:srlb)].compact) if sys.srgb
          rescue ArgumentError => e
            error("#{at}.srgb", e.message)
          end
        end
        if r.key?("sid")
          sys.sid = integer(r["sid"], "#{at}.sid", 0, 0xffff_ffff)
          lo = sys.prefixes.find { _1.prefix == sys.loopback }
          lo.sid = sys.sid if lo
        end
      end

      def prefixes(list, at)
        return [] if list.nil?
        return error(at, "is a list of { prefix:, count:, metric: }") || [] unless list.is_a?(Array)

        list.each_with_index.flat_map do |p, i|
          where = "#{at}[#{i}]"
          next(error(where, "is a map with a prefix") || []) unless p.is_a?(Hash) && p["prefix"]

          unknown(p, PREFIX_KEYS, where)
          expand(p, where)
        end
      end

      # count prefixes from +prefix+, each the next block of the same length:
      # 30.0.0.0/24 with count 3 is 30.0.0.0/24, 30.0.1.0/24, 30.0.2.0/24.
      def expand(p, at)
        net = ip(p["prefix"], "#{at}.prefix") or return []
        text = p["prefix"].to_s
        return error("#{at}.prefix", "#{text} has host bits set; the network is #{net}/#{net.prefix}") || [] if
          text.include?("/") && IPAddr.new(text.split("/").first).to_i != net.to_i

        count = p.key?("count") ? integer(p["count"], "#{at}.count", 1, MAX_COUNT) : 1
        metric = p.key?("metric") ? prefix_metric(p["metric"], "#{at}.metric") : 10
        return [] unless count && metric

        bits = net.ipv4? ? 32 : 128
        step = 2**(bits - net.prefix)
        last = net.to_i + step * count - 1
        return error("#{at}.count", "#{count} blocks from #{net}/#{net.prefix} run past the address space") || [] if last >= 2**bits

        group = "#{net}/#{net.prefix}"
        (0...count).map do |k|
          Prefix.new(prefix: "#{IPAddr.new(net.to_i + k * step, net.family)}/#{net.prefix}", metric: metric, group: group)
        end
      end

      def read_ids
        all_systems.group_by(&:system_id).each do |id, list|
          error("routers", "System ID #{id} is given to #{list.map(&:name).join(' and ')}") if list.size > 1
        end
      end

      def read_link(l, at)
        return error(at, "is a map with from and to") unless l.is_a?(Hash) && l["from"] && l["to"]

        unknown(l, LINK_KEYS, at)
        from = system(l["from"])
        to = system(l["to"])
        error("#{at}.from", "no system named #{l['from']}") unless from
        error("#{at}.to", "no system named #{l['to']}") unless to
        return unless from && to
        return error(at, "#{from.name} to itself") if from == to

        metric = l.key?("metric") ? link_metric(l["metric"], "#{at}.metric") : 10
        state = (l["state"] || "up").to_s
        return error("#{at}.state", "is up or down") unless %w[up down].include?(state)

        one_way = l.key?("one_way") ? flag(l["one_way"], "#{at}.one_way") : false
        add_link(from.name, to.name, metric, one_way || false, state.to_sym, at)
      end

      def add_link(from, to, metric, one_way, state, at)
        return if metric.nil?

        if link("#{from}--#{to}")
          return error(at, "#{from}--#{to} is there already; a parallel link would share its name")
        end

        a = system(from)
        b = system(to)
        levels = a.levels & b.levels
        levels -= [1] if (a.areas & b.areas).empty?
        if levels.empty?
          return error(at, "#{from}--#{to}: no level in common" \
                           "#{' (Level 1 needs an area in common)' if (a.levels & b.levels) == [1]}")
        end

        @links << Link.new(from: from, to: to, metric: metric, one_way: one_way, state: state, levels: levels)
      end

      # A system the simulator reaches by no link floods nothing anyone
      # will use: worth saying, not refusing.
      def read_reachable
        seen = { @simulator.name => true }
        todo = [@simulator.name]
        until todo.empty?
          n = todo.shift
          links_of(n).each do |l|
            other = l.from == n ? l.to : l.from
            todo << other unless seen[other]
            seen[other] = true
          end
        end
        lost = @systems.reject { |s| seen[s.name] }
        return if lost.empty?

        @warnings << "#{lost.size} system#{'s' unless lost.size == 1} no link joins to #{@simulator.name}: " \
                     "#{lost.first(5).map(&:name).join(', ')}#{' ...' if lost.size > 5}"
      end

      def system_id(v, at)
        text = v.to_s
        return error(at, "is needed") && nil if v.nil?

        octets = Pdu.dotted_octets(text)
        return error(at, "#{text} is #{octets.bytesize} octets; a System ID here is 6") && nil unless octets.bytesize == 6

        octets.unpack1("H*").scan(/.{4}/).join(".")
      rescue ArgumentError
        error(at, "#{text} is not a System ID like 0000.0000.0001") && nil
      end

      def level(v, at)
        return nil if v.nil?

        Router.levels(v)
      rescue ArgumentError
        error(at, "is 1, 2 or 1-2") && nil
      end

      def level_text(levels) = levels == [1, 2] ? "1-2" : levels.first

      def areas(v, at)
        list = Array(v).map(&:to_s)
        list.each { |a| AreaAddress.new(a) }
        error(at, "needs at least one area") if list.empty?
        list
      rescue ArgumentError => e
        error(at, e.message)
        []
      end

      def ip(v, at)
        IPAddr.new(v.to_s)
      rescue IPAddr::Error, ArgumentError
        error(at, "#{v} is not an address or prefix") && nil
      end

      def integer(v, at, min, max)
        return error(at, "is a whole number, #{min} to #{max}") && nil unless v.is_a?(Integer) && v.between?(min, max)

        v
      end

      def link_metric(v, at)
        max = LIMITS.fetch(@metric_style)[:link]
        integer(v, at, 0, max).tap { |m| hint(at, max) unless m }
      end

      def prefix_metric(v, at)
        max = LIMITS.fetch(@metric_style)[:prefix]
        integer(v, at, 0, max).tap { |m| hint(at, max) unless m }
      end

      def hint(at, max)
        @errors[-1] += " (the most #{@metric_style} metrics carry is #{max})" if @errors.last&.start_with?("#{at}:")
      end

      def flag(v, at)
        return v if [true, false].include?(v)

        error(at, "is true or false") && nil
      end

      def unknown(h, keys, at)
        (h.keys - keys).each { |k| error(at, "unknown key #{k}; one of #{keys.join(', ')}") }
      end

      def error(at, message)
        @errors << "#{at}: #{message}"
        nil
      end

      def stringify(v)
        case v
        when Hash then v.to_h { |k, x| [k.to_s, stringify(x)] }
        when Array then v.map { stringify(_1) }
        else v
        end
      end
    end
  end
end
