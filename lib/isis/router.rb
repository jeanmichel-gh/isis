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
  #   overload: false
  #   area_key: / hello_key:        HMAC-MD5 keys (RFC 5304)
  #   lsp_buffer_size: 1492
  #   minimum_lsp_interval: 5
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
  #
  # The host gives what is outside the protocol: +link(name)+ answers {
  # transport:, snpa:, link_local: } for an interface, +forwarding(level,
  # interfaces:)+ an adapter or nil, and +route_source+ what
  # redistribution reads. Router::Host is the Linux one; a test gives a
  # simulated one.
  class Router
    NETWORKS = %w[point-to-point broadcast].freeze

    # One configured interface: its transport and its circuits, one per
    # level on a broadcast interface, the same one for every level on a
    # point to point one.
    Interface = Struct.new(:name, :network, :transport, :circuits, keyword_init: true) do
      def broadcast? = network == "broadcast"
      def each_circuit(&block) = circuits.values.uniq.each(&block)
    end

    attr_reader :config, :system_id, :levels, :databases, :originators, :decisions, :interfaces, :segment_routing,
                :leak, :summary, :redistributions, :adapters, :log, :scheduler, :clock

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

        i.merge(name: i.fetch(:name) { raise ArgumentError, "an interface needs a name" }.to_s, network: network)
      end
      config
    end

    def self.symbolize(value)
      case value
      when Hash then value.to_h { |k, v| [k.to_sym, symbolize(v)] }
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
      @levels.each do |level|
        @databases[level] = Database.new(level: level, clock: @clock, scheduler: @scheduler, log: @log)
        @originators[level] = originator(level)
      end
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
      @leak = both? ? Spf::Leak.new(originator: @originators[1], log: @log, policy: self.class.leak_policy(@config[:leak])) : nil
      @summary = both? ? Spf::Summary.new(originator: @originators[2], log: @log, summaries: @config.fetch(:summaries, [])) : nil
      @redistributions = build_redistributions
      @decisions = @levels.to_h { |l| [l, decision(l)] }
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
                     buffer_size: c.fetch(:lsp_buffer_size, Originator::LSP_BUFFER_SIZE),
                     is_type: both? ? 3 : nil, level1_database: level == 2 ? @databases[1] : nil,
                     overload: c.fetch(:overload, false), segment_routing: @segment_routing)
    end

    # The settings an interface may give, and the circuit keyword each
    # becomes.
    def circuit_options(c)
      c.slice(:hello_interval, :hello_multiplier, :metric)
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
      @interfaces.each do |i|
        c = i.circuits.fetch(level)
        d.attach(i.broadcast? ? c : c.levels.fetch(level))
      end
      d
    end
  end
end
