# frozen_string_literal: true

require "ipaddr"

module ISIS
  module Sim
    # Runs a Topology: the simulator's own system is an ordinary Router with
    # real circuits, and every simulated system is an ordinary Originator
    # writing into that Router's databases. Their LSPs are flooded on the
    # Router's circuits like any others, and the update process treats them
    # as this system's own: a newer copy is generated past (RFC 1142
    # 7.3.16.1), and a neighbour's purge of one still held is answered by
    # generating it again (7.3.16.4 c).
    #
    # A link between two systems is an entry in each one's IS reachability,
    # from a VirtualLink attached to its originator. The actions below
    # change the topology and generate the LSPs they touch again.
    #
    #   sim = ISIS::Sim::Simulator.new(topology, clock:, scheduler:, log:, host:)
    #   sim.start
    #   sim.link_down("r1c1--r1c2")
    class Simulator
      # A link seen from one end: what that end's originator puts in its IS
      # reachability, the far end's System ID with a zero pseudonode octet,
      # at the link's metric, while the link is up. It floods nothing: the
      # Flooder does.
      class VirtualLink
        attr_reader :link, :neighbor

        def initialize(link, neighbor_id)
          @link = link
          @neighbor = Pdu.dotted_octets(neighbor_id)
        end

        def is_neighbor
          [(@neighbor + "\x00".b).b, @link.metric] if @link.up?
        end

        def flood(_entry) = nil
      end

      # What floods a simulated system's LSPs: every circuit of the
      # database it writes into, as the database floods a purge (7.3.16.4).
      class Flooder
        def initialize(database)
          @database = database
        end

        def is_neighbor = nil

        def flood(entry)
          @database.circuits.each { |c| c.flood(entry) }
        end
      end

      # One simulated system's originators answering for it in a database's
      # generators, while the simulator generates it. Flushed, or with aging
      # off, it answers for nothing, so copies that arrive are taken as any
      # other system's.
      class Generator
        def initialize(simulator, originator)
          @simulator = simulator
          @originator = originator
        end

        def generates?(lsp_id) = @simulator.generating? && @originator.generates?(lsp_id)

        def receive_own(result, lsp) = @originator.receive_own(result, lsp)
      end

      # The actions, by the names routescope's sim: steps and the API use,
      # and the method each calls.
      ACTIONS = {
        "link.down" => :link_down, "link.up" => :link_up, "link.toggle" => :link_toggle,
        "link.flap" => :link_flap, "link.metric" => :link_metric,
        "router.overload" => :router_overload, "router.attached" => :router_attached,
        "prefixes.withdraw" => :prefixes_withdraw, "prefixes.advertise" => :prefixes_advertise,
        "refresh" => :refresh, "flush" => :flush, "restore" => :restore, "aging" => :aging=,
        "neighbor.stop" => :neighbor_stop, "neighbor.start" => :neighbor_start
      }.freeze

      attr_reader :topology, :router, :originators, :log

      # +originators+ is { system name => { level => Originator } }, the
      # simulator's own system included, whose originators are the
      # Router's.
      def initialize(topology, clock:, scheduler:, log:, host:)
        @topology = topology
        @clock = clock
        @scheduler = scheduler
        @log = log
        @router = Router.new(topology.router_config, clock: clock, scheduler: scheduler, log: log, host: host)
        @generating = false
        @aging = true
        @withdrawn = Hash.new { |h, k| h[k] = [] }
        @flaps = []
        @originators = { topology.simulator.name => @router.levels.to_h { |l| [l, @router.originators[l]] } }
        topology.systems.each { |s| @originators[s.name] = build_originators(s) }
        attach_links
      end

      def levels = @router.levels

      # Start the Router, then generate every simulated system.
      def start
        @router.start
        start_simulated("the simulator started")
        self
      end

      def stop
        @flaps.each(&:cancel)
        @flaps.clear
        each_simulated(&:stop)
        @router.stop
        self
      end

      def step(wait: 0.1) = @router.step(wait: wait)

      # Whether the simulated systems are generated now: not after a flush
      # or with aging off, until restore or aging on.
      def generating? = @generating

      def aging? = @aging

      # The link named +ref+ ("r1c1--r1c2", either way round, or its number),
      # or raises ArgumentError.
      def link(ref)
        @topology.link(ref) or raise ArgumentError, "no link #{ref}"
      end

      def system(name)
        s = @topology.system(name) or raise ArgumentError, "no system #{name}"
        s
      end

      def link_down(ref) = set_link(link(ref), :down)
      def link_up(ref) = set_link(link(ref), :up)

      def link_toggle(ref)
        l = link(ref)
        set_link(l, l.up? ? :down : :up)
      end

      # Down and up +count+ times, +interval+ seconds each way, on the
      # scheduler.
      def link_flap(ref, count: 3, interval: 5)
        l = link(ref)
        count = Integer(count)
        interval = Float(interval)
        raise ArgumentError, "a flap needs a count of 1 or more and an interval over 0" unless count.positive? && interval.positive?

        event(:link, "#{l.name} flapping #{count} times every #{interval} s")
        (0...(count * 2)).each do |i|
          @flaps << @scheduler.after(i * interval) { set_link(l, i.even? ? :down : :up) }
        end
        l
      end

      def link_metric(ref, metric)
        l = link(ref)
        max = Topology::LIMITS.fetch(@topology.metric_style)[:link]
        metric = Integer(metric)
        raise ArgumentError, "a #{@topology.metric_style} link metric is 0 to #{max}" unless metric.between?(0, max)

        l.metric = metric
        changed([l.from, l.to], "#{l.name} metric #{metric}")
        l
      end

      # The OL bit in +name+'s LSP Number 0 (RFC 1142 7.3.19.1).
      def router_overload(name, on)
        s = simulated(name)
        s.overload = on ? true : false
        @originators[s.name].each_value { |o| o.overload = s.overload }
        event(:router, "#{s.name} overload #{s.overload ? 'set' : 'cleared'}")
        s
      end

      # The default metric ATT bit in +name+'s Level 1 LSP Number 0 (7.2.9.2).
      def router_attached(name, on)
        s = simulated(name)
        s.attached = on ? true : false
        @originators[s.name][1]&.attached = s.attached
        event(:router, "#{s.name} attached #{s.attached ? 'set' : 'cleared'}")
        s
      end

      # Take the group whose first prefix is +group+ out of +name+'s LSPs, or
      # put it back.
      def prefixes_withdraw(name, group) = set_group(name, group, withdraw: true)
      def prefixes_advertise(name, group) = set_group(name, group, withdraw: false)

      # Generate every simulated LSP again, at the next sequence.
      def refresh
        raise ArgumentError, "nothing to refresh: the simulated systems are not generated now" unless @generating

        each_simulated { |o| o.refresh }
        event(:lsdb, "every simulated LSP generated again")
      end

      # Purge every simulated LSP (RFC 1142 7.3.16.4), and generate none
      # until restore.
      def flush
        @generating = false
        each_simulated do |o|
          o.stop
          o.numbers.each do |n|
            held = o.database[o.lsp_id(n)]
            next if held.nil? || held.placeholder? || held.purged?

            o.database.purge(held, "flushed by the simulator", retain: Database::MAX_AGE)
          end
        end
        event(:lsdb, "every simulated LSP purged")
      end

      # After a flush: generate every simulated system again, past its purge.
      def restore
        raise ArgumentError, "nothing to restore: the simulated systems are generated" if @generating

        start_simulated("restored after a flush")
      end

      # Off: no refreshes, so the simulated LSPs run out at the neighbours
      # within the topology's lsp_lifetime, and none is generated again. On:
      # every simulated system generated again at once.
      def aging=(on)
        on = on ? true : false
        return if on == @aging

        @aging = on
        if on
          start_simulated("aging back on")
        else
          @generating = false
          each_simulated(&:stop)
          event(:lsdb, "aging off: no refreshes, the simulated LSPs run out in #{@topology.lsp_lifetime} s")
        end
      end

      # Stop or start the hellos on one of the simulator's own interfaces,
      # or all of them, so its neighbours' adjacencies time out.
      def neighbor_stop(circuit: nil) = each_interface(circuit) { |c| c.stop }.tap { event(:neighbor, "hellos stopped on #{circuit || 'every interface'}") }
      def neighbor_start(circuit: nil) = each_interface(circuit) { |c| c.start }.tap { event(:neighbor, "hellos started on #{circuit || 'every interface'}") }

      # What the API's sim.state shows.
      def state
        { generating: @generating, aging: @aging, lsp_lifetime: @topology.lsp_lifetime,
          counts: @topology.counts, levels: levels,
          systems: @topology.all_systems.map { |s| system_state(s) },
          links: @topology.links.map { |l| link_state(l) },
          warnings: @topology.warnings }
      end

      # Nodes and links for a map: the simulator and every simulated system,
      # each link with its state and metric.
      def graph
        { nodes: @topology.all_systems.map do |s|
          { id: s.name, system_id: s.system_id, simulator: s.simulator?, grid: s.grid, levels: s.levels,
            overload: s.overload ? true : false, attached: s.attached ? true : false }
        end,
          links: @topology.links.map { |l| link_state(l) } }
      end

      private

      def build_originators(sys)
        (sys.levels & levels).to_h do |level|
          v4, v6 = sys.prefixes.partition { |p| IPAddr.new(p.prefix).ipv4? }
          lo = sys.loopback && IPAddr.new(sys.loopback)
          o = Originator.new(
            system_id: sys.system_id, database: @router.databases[level], scheduler: @scheduler, log: @log,
            areas: sys.areas, protocols: v6.empty? && sys.externals.none? { |p| p.prefix.include?(":") } ? %i[ipv4] : %i[ipv4 ipv6],
            hostname: sys.hostname,
            ip_addresses: lo&.ipv4? ? [lo.to_s] : [], ipv6_addresses: lo&.ipv6? ? [lo.to_s] : [],
            prefixes: v4.map(&:to_h), ipv6_prefixes: v6.map(&:to_h), external_prefixes: sys.externals.map(&:to_h),
            metric_style: @topology.metric_style, minimum_interval: 1,
            buffer_size: sys.lsp_buffer_size || Originator::LSP_BUFFER_SIZE,
            is_type: sys.levels == [1, 2] ? 3 : nil,
            level1_database: level == 2 && levels.include?(1) ? @router.databases[1] : nil,
            overload: sys.overload ? true : false, lifetime: @topology.lsp_lifetime,
            refresh_interval: refresh_interval
          )
          o.attached = true if level == 1 && sys.attached
          o.attach(Flooder.new(@router.databases[level]))
          @router.databases[level].add_generator(Generator.new(self, o))
          [level, o]
        end
      end

      # Refreshed before the lifetime runs out (7.3.16.3): the usual
      # interval, or three quarters of a shorter lifetime.
      def refresh_interval
        [Originator::MAXIMUM_LSP_GENERATION_INTERVAL, @topology.lsp_lifetime * 3 / 4].min.clamp(1, nil)
      end

      def attach_links
        @topology.links.each do |l|
          a = @topology.system(l.from)
          b = @topology.system(l.to)
          l.levels.each do |level|
            @originators.dig(a.name, level)&.attach(VirtualLink.new(l, b.system_id))
            @originators.dig(b.name, level)&.attach(VirtualLink.new(l, a.system_id)) unless l.one_way
          end
        end
      end

      def start_simulated(why)
        @generating = true
        @aging = true
        each_simulated(&:start)
        event(:lsdb, "#{@topology.systems.size} simulated systems generated: #{why}")
      end

      def each_simulated(&block)
        @topology.systems.each { |s| @originators[s.name].each_value(&block) }
      end

      def set_link(l, state)
        return l if l.state == state

        l.state = state
        changed([l.from, l.to], "#{l.name} #{state}")
        l
      end

      # Generate the LSPs of +names+ again, the simulator's own included.
      def changed(names, why)
        event(:link, why)
        names.each { |n| @originators[n].each_value { |o| o.changed("simulator: #{why}") } }
      end

      def simulated(name)
        s = system(name)
        raise ArgumentError, "#{name} is the simulator itself, not a simulated system" if s.simulator?

        s
      end

      def set_group(name, group, withdraw:)
        s = simulated(name)
        group = group.to_s
        all = s.prefixes + s.externals
        raise ArgumentError, "#{s.name} has no prefix group #{group}" unless all.any? { |p| p.group == group }

        list = @withdrawn[s.name]
        withdraw ? list << group : list.delete(group)
        list.uniq!
        keep = ->(ps) { ps.reject { |p| list.include?(p.group) } }
        @originators[s.name].each_value do |o|
          v4, v6 = keep.call(s.prefixes).partition { |p| IPAddr.new(p.prefix).ipv4? }
          o.prefixes = v4.map(&:to_h)
          o.ipv6_prefixes = v6.map(&:to_h)
          o.external_prefixes = keep.call(s.externals).map(&:to_h)
          o.changed("simulator: #{group} on #{s.name} #{withdraw ? 'withdrawn' : 'advertised'}")
        end
        event(:prefixes, "#{s.name}: #{group} #{withdraw ? 'withdrawn' : 'advertised'}")
        s
      end

      def each_interface(name, &block)
        list = name ? [@router.interface(name.to_s) || raise(ArgumentError, "no interface #{name}")] : @router.interfaces
        list.each { |i| i.each_circuit(&block) }
      end

      def system_state(s)
        lsps = @originators[s.name].transform_values { |o| o.numbers.size }
        { name: s.name, system_id: s.system_id, hostname: s.hostname, simulator: s.simulator?, levels: s.levels,
          overload: s.overload ? true : false, attached: s.attached ? true : false,
          prefixes: s.prefixes.size, externals: s.externals.size, withdrawn: @withdrawn[s.name].dup, lsps: lsps }
      end

      def link_state(l)
        { name: l.name, from: l.from, to: l.to, metric: l.metric, state: l.up? ? "up" : "down",
          one_way: l.one_way ? true : false, levels: l.levels }
      end

      def event(kind, text)
        @log.info("simulator: #{text}", kind: :simulator, action: kind)
      end
    end
  end
end
