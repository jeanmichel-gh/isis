# frozen_string_literal: true

module ISIS
  # A whole IS-IS system from one configuration: a database, an originator
  # and a Decision Process per level, a circuit per interface (a LAN
  # circuit per level on a broadcast interface), and at both levels the
  # leak and the summary between them. The mechanisms are the library's
  # own objects, built here and nowhere else, so a script can still reach
  # each one and replace it.
  #
  # The configuration is a Hash, as a YAML file reads:
  #
  #   system_id: 1921.6800.1001     required
  #   hostname: r1                  TLV 137, RFC 5301
  #   areas: [49.0001]
  #   level: 1                      1, 2 or "1-2"
  #   metric_style: wide            wide, narrow or transition
  #   ipv6: false                   run IPv6 too (RFC 5308)
  #   ip_addresses: [...]           TLV 132 in the LSP; the interfaces'
  #                                 when not given
  #   ipv6_addresses: [...]         TLV 232 in the LSP
  #   prefixes: [{prefix:, metric:}]   and ipv6_prefixes, external_prefixes;
  #                                 with segment routing a prefix may add
  #                                 sid: (its index), no_php:, explicit_null:
  #   router_id: 10.255.0.1         TLV 242's Router ID; the first IPv4 /32
  #                                 among the prefixes when not given
  #   segment_routing:              SR-MPLS, RFC 8667 (SegmentRouting); off
  #     srgb: [{start: 16000, size: 8000}]   when absent
  #     srlb: {start: 15000, size: 1000}
  #     receive_policy: rfc          rfc, strict or lenient (Validation)
  #   affinity_map: {red: 1}        names for the interfaces' affinity, each a
  #                                 group, 0 to 1023 (RFC 7308)
  #   flex_algo: [{algorithm: 128, metric_type: delay, ...}]
  #                                 the algorithms this system takes part in
  #                                 (RFC 9350; FlexAlgoConfig has the keys);
  #                                 needs segment_routing. A prefix gives
  #                                 algorithm_sids: {128: 101}, an index
  #                                 per algorithm
  #   overload: false
  #   area_key: / hello_key:        HMAC-MD5 keys (RFC 5304)
  #   lsp_buffer_size: 1492
  #   minimum_lsp_interval: 5       RFC 1142's fixed hold on a change, 30 s
  #                                 when absent
  #   lsp_generation:               the backoff in its place
  #     {initial: 0, secondary: 1, maximum: 30}    (GenerationTimer::Backoff,
  #                                 docs/design/lsp-generation.md); not with
  #                                 minimum_lsp_interval
  #   forwarding: false             install routes through the host
  #   leak: [prefix, ...]           Level 2 routes leaked into Level 1
  #   summaries: [{prefix:, metric:}]
  #   redistribute: {kinds:, metric:, external:, interval:}
  #   interfaces:
  #     - name: eth1
  #       network: point-to-point   or broadcast
  #       ip_addresses: [10.0.12.1]
  #       metric: 10
  #       priority: 64              broadcast only
  #       hello_interval: 3
  #       hello_multiplier: 10
  #       adj_sid: true             false: no Adj-SID for its adjacencies
  #       bfd: false                true: BFD for its adjacencies, through
  #                                 bfdd4r, with TLV 148 (RFC 6213)
  #       bfd_tlv: true             true or false: what TLV 148 says,
  #                                 whatever BFD does; for negative tests
  #       ti_lfa: link              TI-LFA backups for the destinations behind
  #                                 this interface's neighbour, against the
  #                                 link failing (RFC 9855, docs/ti-lfa.md);
  #                                 node: against the neighbour failing, and
  #                                 the link's where no node backup exists;
  #                                 point-to-point and segment routing only
  #       affinity: [red]           the link's groups, names in affinity_map,
  #                                 sent for flex-algo in an ASLA sub-TLV
  #                                 (RFC 9479, docs/design/flex-algo.md)
  #       delay: 5000               the link's delay in µs, sent as min, max
  #                                 and average, in the same sub-TLV
  #       te_metric: 100            its TE default metric, the same way
  #       srlg: [10]                its SRLGs, in TLV 238; needs ip_addresses
  #
  # An interface key not listed here is refused, naming the key and the
  # interface, so a misspelt one (bdf: true) does not quietly do nothing.
  # INTERFACE_KEYS is this list, and router_test holds it to this comment.
  #
  # The host gives what is outside the protocol: +link(name)+ answers {
  # transport:, snpa:, link_local: } for an interface, +forwarding(level,
  # interfaces:)+ an adapter or nil, and +route_source+ what
  # redistribution reads, and +bfd_client+ what an interface with bfd: true
  # asks for sessions through, a BFD::Client. Router::Host is the Linux
  # one; a test gives a simulated one.
  class Router
    NETWORKS = %w[point-to-point broadcast].freeze

    # The keys an interface may give, as the class comment lists them.
    INTERFACE_KEYS = %i[name network ip_addresses metric priority hello_interval hello_multiplier
                        adj_sid bfd bfd_tlv ti_lfa affinity delay te_metric srlg].freeze

    # The highest affinity group: FRR 10.7.1's affinity-map takes bit
    # positions 0 to 1023, measured.
    MAX_AFFINITY = 1023
    # A delay (RFC 8570 section 4.1) and a TE default metric (RFC 5305
    # section 3.7) are 24 bits.
    MAX_24 = 0xff_ffff

    # What ti_lfa takes.
    TI_LFA = %w[link node].freeze

    # One configured interface: its transport and its circuits, one per
    # level on a broadcast interface, the same one for every level on a
    # point to point one.
    Interface = Struct.new(:name, :network, :transport, :circuits, keyword_init: true) do
      def broadcast? = network == "broadcast"
      def each_circuit(&block) = circuits.values.uniq.each(&block)
    end

    attr_reader :config, :system_id, :levels, :databases, :originators, :decisions, :interfaces, :segment_routing,
                :label_table, :flex_config, :flex_algos,
                :leak, :summary, :redistributions, :adapters, :log, :scheduler, :clock, :bfd

    def initialize(config, clock:, scheduler:, log:, host:)
      @config = self.class.normalize(config)
      @clock = clock
      @scheduler = scheduler
      @log = log
      @host = host
      @system_id = @config.fetch(:system_id) { raise ArgumentError, "a system_id is needed" }
      @levels = self.class.levels(@config.fetch(:level, 1))
      @started = false
      build
    end

    def both? = @levels.size == 2

    # The System ID as routers print it: 1921.6800.1001.
    def system_id_s = Pdu.dotted_octets(@system_id).unpack1("H*").scan(/.{4}/).join(".")

    # The configuration with symbol keys throughout and the interfaces as a
    # list, as JSON and YAML both read it.
    def self.normalize(config)
      config = symbolize(config)
      config[:interfaces] = Array(config[:interfaces]).map do |i|
        i = i.is_a?(Hash) ? i : { name: i.to_s }
        network = (i[:network] || "point-to-point").to_s
        raise ArgumentError, "interface #{i[:name]}: network is #{NETWORKS.join(' or ')}" unless NETWORKS.include?(network)

        name = i.fetch(:name) { raise ArgumentError, "an interface needs a name" }.to_s
        unknown = i.keys - INTERFACE_KEYS
        unless unknown.empty?
          raise ArgumentError, "interface #{name}: unknown #{unknown.size == 1 ? 'key' : 'keys'} " \
                               "#{unknown.join(', ')}; the keys are #{INTERFACE_KEYS.join(', ')}"
        end

        ti_lfa(i, name, network, config)
        link_attributes(i, name, config)
        i.merge(name: name, network: network)
      end
      flex = flex_config(config)
      %i[prefixes ipv6_prefixes].each do |key|
        next unless config[key]

        config[key] = Array(config[key]).map do |p|
          p.is_a?(Hash) && p.key?(:algorithm_sids) ? p.merge(algorithm_sids: flex.algorithm_sids(p)) : p
        end
      end
      config
    end

    # The flex_algo list, checked (FlexAlgoConfig).
    def self.flex_config(config)
      FlexAlgoConfig.new(config[:flex_algo], affinity_map: affinity_map(config),
                                             segment_routing: config[:segment_routing])
    end

    # Refuses a ti_lfa that cannot apply, naming why.
    def self.ti_lfa(interface, name, network, config)
      mode = interface[:ti_lfa]
      return if mode.nil? || mode == false

      unless TI_LFA.include?(mode.to_s)
        raise ArgumentError, "interface #{name}: ti_lfa is #{TI_LFA.join(' or ')}, not #{mode}"
      end
      raise ArgumentError, "interface #{name}: ti_lfa needs segment_routing" unless config[:segment_routing]
      raise ArgumentError, "interface #{name}: ti_lfa protects point-to-point interfaces" if network == "broadcast"
    end

    # Refuses link attributes that cannot be sent, naming why.
    def self.link_attributes(interface, name, config)
      unless interface[:affinity].nil?
        map = affinity_map(config)
        Array(interface[:affinity]).each do |color|
          next if map.key?(color.to_s)

          raise ArgumentError, "interface #{name}: affinity #{color} is not in affinity_map" \
                               "#{map.empty? ? '' : " (#{map.keys.join(', ')})"}"
        end
      end
      %i[delay te_metric].each do |key|
        v = interface[key]
        next if v.nil?
        next if v.is_a?(Integer) && v.between?(0, MAX_24)

        raise ArgumentError, "interface #{name}: #{key} is 0 to #{MAX_24}, not #{v.inspect}"
      end
      return if interface[:srlg].nil?

      Array(interface[:srlg]).each do |v|
        next if v.is_a?(Integer) && v.between?(0, 0xffff_ffff)

        raise ArgumentError, "interface #{name}: an SRLG is 0 to #{0xffff_ffff}, not #{v.inspect}"
      end
      return unless Array(interface[:ip_addresses]).empty?

      raise ArgumentError, "interface #{name}: srlg needs ip_addresses, which TLV 238 names the link by"
    end

    # affinity_map as names to groups, checked.
    def self.affinity_map(config)
      map = config[:affinity_map] || {}
      raise ArgumentError, "affinity_map is a map of names to groups" unless map.is_a?(Hash)

      map.to_h do |k, v|
        unless v.is_a?(Integer) && v.between?(0, MAX_AFFINITY)
          raise ArgumentError, "affinity_map: #{k} is a group from 0 to #{MAX_AFFINITY}, not #{v.inspect}"
        end

        [k.to_s, v]
      end
    end

    # The interfaces with ti_lfa, by name.
    def ti_lfa_interfaces
      ti_lfa_modes.keys
    end

    # Each interface with ti_lfa, and its mode, :link or :node.
    def ti_lfa_modes
      @config[:interfaces].select { _1[:ti_lfa] }.to_h { [_1[:name], _1[:ti_lfa].to_sym] }
    end

    def self.symbolize(value)
      case value
      # A key YAML reads as a number, as algorithm_sids' {128: 101}, stays
      # one.
      when Hash then value.to_h { |k, v| [k.is_a?(Integer) ? k : k.to_sym, symbolize(v)] }
      when Array then value.map { |v| symbolize(v) }
      else value
      end
    end

    # 1, 2 or "1-2" (also "1-2", [1, 2]).
    def self.levels(level)
      list = level.is_a?(Array) ? level.map { Integer(_1) } : level.to_s == "1-2" ? [1, 2] : [Integer(level)]
      raise ArgumentError, "level is 1, 2 or 1-2, not #{level.inspect}" unless [[1], [2], [1, 2]].include?(list.sort)

      list.sort
    end

    def start
      return self if @started

      @started = true
      @originators.each_value(&:start)
      @interfaces.each { |i| i.each_circuit(&:start) }
      @decisions.each_value(&:start)
      @redistributions.each(&:start)
      self
    end

    def stop
      return self unless @started

      @started = false
      @interfaces.each { |i| i.each_circuit(&:stop) }
      @originators.each_value(&:stop)
      @redistributions.each(&:stop)
      @decisions.each_value(&:stop)
      @adapters.each_value { |a| a.flush; a.close }
      @bfd&.close
      self
    end

    # One turn of the loop: run what is due, then read frames for at most
    # +wait+ seconds, shorter when a timer is due sooner. Each frame goes to
    # every circuit on its interface; each takes its own level's.
    def step(wait: 0.1)
      @scheduler.run_due
      due = @scheduler.next_due
      wait = (due - @clock.now).clamp(0.0, wait) if due
      slice = @interfaces.empty? ? 0 : wait / @interfaces.size
      @interfaces.each do |i|
        while (frame = i.transport.receive(timeout: slice))
          i.each_circuit { |c| c.receive_frame(frame) }
          slice = 0
        end
      end
      @scheduler.run_due
    end

    # The leak policy, a list of covering prefixes, none by default.
    def leak_prefixes=(list)
      @leak&.policy = self.class.leak_policy(list)
    end

    def summaries=(list)
      @summary&.summaries = list
    end

    # TI-LFA on interface +name+, changed while running (policy.ti_lfa):
    # "link", "node", or "off". Checked as the file's ti_lfa is. Each level
    # runs SPF again, so the backups are computed, installed or withdrawn
    # at once. Turned off, ignore_routes_with_linkdown stays as it was:
    # with no backup route it changes nothing.
    def set_ti_lfa(name, mode)
      iface = @config[:interfaces].find { _1[:name] == name.to_s }
      raise ArgumentError, "no interface #{name}; the interfaces are #{@config[:interfaces].map { _1[:name] }.join(', ')}" unless iface

      mode = mode.to_s
      raise ArgumentError, "mode is off, #{TI_LFA.join(' or ')}, not #{mode}" unless ["off", *TI_LFA].include?(mode)

      value = mode == "off" ? nil : mode
      self.class.ti_lfa({ ti_lfa: value }, iface[:name], iface[:network], @config)
      iface[:ti_lfa] = value
      @decisions.each_value do |d|
        d.ti_lfa = ti_lfa_modes
        d.changed("ti_lfa #{mode} on #{iface[:name]}")
      end
      link_down_routes if value
      { interface: iface[:name], mode: mode }
    end

    # Algorithm +algorithm+'s FAD changed while running (policy.flex_algo):
    # +changes+ any of advertise, priority, metric_type, exclude_any,
    # include_any, include_all and exclude_srlg, checked as the file's are.
    # Each level selects again, and the LSPs go out with the new FAD.
    def set_flex_algo(algorithm, changes)
      entry = @flex_config.change(algorithm, Router.symbolize(changes))
      why = "policy.flex_algo #{entry.algorithm}"
      @flex_algos.each_value { _1.update(why) }
      @originators.each_value { _1.changed(why) }
      entry.to_hash
    end

    def redistribute=(kinds)
      @redistributions.each { |r| r.kinds = kinds }
    end

    def self.leak_policy(list)
      list = Array(list)
      list.empty? ? Spf::Leak::NONE : Spf::Leak.prefixes(list)
    end

    # The interface named +name+.
    def interface(name) = @interfaces.find { |i| i.name == name }

    private

    def protocols = @config.fetch(:ipv6, false) ? %i[ipv4 ipv6] : %i[ipv4]

    def build
      @databases = {}
      @originators = {}
      @segment_routing = SegmentRouting.from_config(@config[:segment_routing], router_id: @config[:router_id],
                                                    prefixes: @config.fetch(:prefixes, []),
                                                    ipv6: protocols.include?(:ipv6), no_adj_sid: no_adj_sid)
      @flex_config = self.class.flex_config(@config)
      @flex_algos = {}
      @levels.each do |level|
        @databases[level] = Database.new(level: level, clock: @clock, scheduler: @scheduler, log: @log)
        unless @flex_config.empty?
          @flex_algos[level] = Spf::FlexAlgo.new(level: level, system_id: @system_id, database: @databases[level],
                                                 config: @flex_config, log: @log,
                                                 policy: @segment_routing.receive_policy)
        end
        @originators[level] = originator(level)
        @flex_algos[level]&.originator = @originators[level]
      end
      @bfd = @config[:interfaces].any? { _1[:bfd] } ? Bfd.new(client: @host.bfd_client, log: @log) : nil
      @interfaces = []
      p2p_index = 0
      lan_index = 0
      @config[:interfaces].each do |c|
        if c[:network] == "broadcast"
          @interfaces << lan_interface(c, lan_index += 1)
        else
          @interfaces << p2p_interface(c, p2p_index += 1)
        end
      end
      @adapters = {}
      if @config.fetch(:forwarding, false)
        names = both? ? lan_names : {}
        @levels.each do |l|
          adapter = @host.forwarding(l, interfaces: names)
          next unless adapter

          adapter.flush
          @adapters[l] = adapter
        end
      end
      @label_table = build_label_table
      link_down_routes
      @leak = both? ? Spf::Leak.new(originator: @originators[1], log: @log, policy: self.class.leak_policy(@config[:leak])) : nil
      @summary = both? ? Spf::Summary.new(originator: @originators[2], log: @log, summaries: @config.fetch(:summaries, [])) : nil
      @redistributions = build_redistributions
      @decisions = @levels.to_h { |l| [l, decision(l)] }
    end

    # The backoff's settings, the defaults filled in, or nil for the fixed
    # hold. A key it does not know, or minimum_lsp_interval beside it, is
    # refused.
    def lsp_generation
      g = @config[:lsp_generation] or return nil
      g = {} if g == true
      raise ArgumentError, "lsp_generation is a map of #{GenerationTimer::Backoff::DEFAULTS.keys.join(', ')}" unless g.is_a?(Hash)

      g = g.transform_keys(&:to_sym)
      unknown = g.keys - GenerationTimer::Backoff::DEFAULTS.keys
      raise ArgumentError, "lsp_generation: unknown #{unknown.size == 1 ? 'key' : 'keys'} #{unknown.join(', ')}" if unknown.any?
      raise ArgumentError, "lsp_generation and minimum_lsp_interval are two ways to time the same thing; give one" if @config.key?(:minimum_lsp_interval)

      GenerationTimer::Backoff::DEFAULTS.merge(g)
    end

    def originator(level)
      c = @config
      Originator.new(system_id: @system_id, database: @databases[level], scheduler: @scheduler, log: @log,
                     areas: c.fetch(:areas, ["49.0001"]), protocols: protocols, hostname: c[:hostname],
                     ip_addresses: c.fetch(:ip_addresses) { c[:interfaces].flat_map { Array(_1[:ip_addresses]) }.uniq },
                     ipv6_addresses: c.fetch(:ipv6_addresses, []), ipv6_prefixes: c.fetch(:ipv6_prefixes, []),
                     prefixes: c.fetch(:prefixes, []), external_prefixes: c.fetch(:external_prefixes, []),
                     metric_style: c.fetch(:metric_style, "wide").to_sym, area_key: c[:area_key],
                     minimum_interval: c.fetch(:minimum_lsp_interval, Originator::MINIMUM_LSP_GENERATION_INTERVAL),
                     lsp_generation: lsp_generation,
                     buffer_size: c.fetch(:lsp_buffer_size, Originator::LSP_BUFFER_SIZE),
                     is_type: both? ? 3 : nil, level1_database: level == 2 ? @databases[1] : nil,
                     overload: c.fetch(:overload, false), segment_routing: @segment_routing,
                     link_attributes: link_attributes, flex_algo: @flex_algos[level])
    end

    # Each interface's attributes for flex-algo, by circuit name, as the
    # Originator takes them: :affinity as groups, :delay, :te_metric and
    # :srlg. Interfaces without any are left out.
    def link_attributes
      map = self.class.affinity_map(@config)
      @config[:interfaces].each_with_object({}) do |c, h|
        a = {}
        a[:affinity] = Array(c[:affinity]).map { map.fetch(_1.to_s) }.uniq.sort unless c[:affinity].nil?
        a[:delay] = c[:delay] unless c[:delay].nil?
        a[:te_metric] = c[:te_metric] unless c[:te_metric].nil?
        a[:srlg] = Array(c[:srlg]).uniq unless c[:srlg].nil?
        next if a.empty?

        names = c[:network] == "broadcast" && both? ? @levels.map { |l| "#{c[:name]}-l#{l}" } : [c[:name]]
        names.each { h[_1] = a }
      end
    end

    # The settings an interface may give, and the circuit keyword each
    # becomes.
    def circuit_options(c)
      options = c.slice(:hello_interval, :hello_multiplier, :metric, :bfd_tlv)
      options.merge!(bfd: @bfd, bfd_interface: c[:name]) if c[:bfd]
      options
    end

    def p2p_interface(c, index)
      link = @host.link(c[:name])
      levels = @levels.to_h { |l| [l, { database: @databases[l], originator: @originators[l], area_key: @config[:area_key] }] }
      circuit = P2pCircuit.new(transport: link[:transport], scheduler: @scheduler, log: @log, name: c[:name],
                               system_id: @system_id, snpa: link[:snpa], levels: levels,
                               local_circuit_id: index, extended_circuit_id: index,
                               hello_key: @config[:hello_key], areas: @config.fetch(:areas, ["49.0001"]),
                               ip_addresses: Array(c[:ip_addresses]), protocols: protocols,
                               ipv6_addresses: protocols.include?(:ipv6) ? Array(link[:link_local]) : [],
                               **circuit_options(c))
      Interface.new(name: c[:name], network: c[:network], transport: link[:transport],
                    circuits: @levels.to_h { |l| [l, circuit] })
    end

    def lan_interface(c, index)
      link = @host.link(c[:name])
      circuits = @levels.to_h do |level|
        [level, LanCircuit.new(transport: link[:transport], scheduler: @scheduler, log: @log,
                               name: both? ? "#{c[:name]}-l#{level}" : c[:name], level: level,
                               circuit_type: both? ? :l1l2 : nil, local_circuit_id: index,
                               database: @databases[level], originator: @originators[level],
                               area_key: @config[:area_key], hello_key: @config[:hello_key],
                               system_id: @system_id, snpa: link[:snpa], areas: @config.fetch(:areas, ["49.0001"]),
                               ip_addresses: Array(c[:ip_addresses]), priority: c.fetch(:priority, LanCircuit::PRIORITY),
                               protocols: protocols,
                               ipv6_addresses: protocols.include?(:ipv6) ? Array(link[:link_local]) : [],
                               **circuit_options(c))]
      end
      Interface.new(name: c[:name], network: c[:network], transport: link[:transport], circuits: circuits)
    end

    # With ti_lfa on an interface and forwarding, the host passes over a
    # route whose link is down, so the kernel takes the backup by itself
    # when a link loses carrier (Host#ti_lfa). One that cannot is logged;
    # the backups are still installed, and taken when isisd converges.
    def link_down_routes
      names = ti_lfa_interfaces
      return if names.empty? || @adapters.empty? || !@host.respond_to?(:ti_lfa)

      why = @host.ti_lfa(names)
      @log.warn("TI-LFA: the kernel will not switch to a backup on carrier loss: #{why}") if why
    end

    # With segment routing and forwarding, one label table for both levels,
    # through the first level's adapter, once the host can take label
    # routes: MPLS input on every interface, and a platform label table
    # reaching the highest label in the SRGB and SRLB. A host that cannot is
    # logged and runs with IP routes only.
    def build_label_table
      return nil unless @segment_routing && !@adapters.empty?

      if @host.respond_to?(:mpls)
        names = @config[:interfaces].map { _1[:name] }
        why = @host.mpls(names, highest: @segment_routing.highest_label)
        if why
          @log.error("segment routing labels not installed: #{why}")
          return nil
        end
      end
      Forwarding::LabelTable.new(adapter: @adapters.values.first, log: @log)
    end

    # The circuits of the interfaces whose configuration says adj_sid:
    # false. A LAN circuit at both levels is named for its level.
    def no_adj_sid
      @config[:interfaces].select { _1[:adj_sid] == false }.flat_map do |c|
        c[:network] == "broadcast" && both? ? @levels.map { |l| "#{c[:name]}-l#{l}" } : [c[:name]]
      end
    end

    # A LAN circuit at both levels is named for its level; the kernel knows
    # only the interface.
    def lan_names
      @config[:interfaces].select { _1[:network] == "broadcast" }
                          .flat_map { |c| @levels.map { |l| ["#{c[:name]}-l#{l}", c[:name]] } }.to_h
    end

    def build_redistributions
      r = @config[:redistribute] or return []
      source = @host.route_source
      @levels.map do |l|
        Redistribution.new(originator: @originators[l], scheduler: @scheduler, log: @log, source: source,
                           kinds: Array(r[:kinds]).map(&:to_s), metric: r.fetch(:metric, 0),
                           external: r.fetch(:external, false), interval: r.fetch(:interval, 5))
      end
    end

    # A Decision Process per level, with each circuit's level as its first
    # hops. At both levels the Level 2 one sets the Level 1 originator's
    # AttachedFlag (RFC 1142 7.2.9.2).
    def decision(level)
      d = Spf::Decision.new(system_id: @system_id, database: @databases[level], scheduler: @scheduler, log: @log,
                            forwarding: @adapters[level],
                            attached_flag: both? && level == 2 ? @originators[1] : nil,
                            leak: level == 2 ? @leak : nil, summary: level == 1 ? @summary : nil,
                            segment_routing: @segment_routing)
      d.label_table = @label_table
      d.ti_lfa = ti_lfa_modes
      d.flex_algo = @flex_algos[level]
      @interfaces.each do |i|
        c = i.circuits.fetch(level)
        d.attach(i.broadcast? ? c : c.levels.fetch(level))
      end
      d
    end
  end
end
