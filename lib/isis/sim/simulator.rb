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

        # The link's name, which keys this end's Adj-SID.
        def name = @link.name

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
      # generators, while the simulator generates it. Flushed, with aging
      # off, or stale (the stale_lsp behaviour), it answers for nothing, so
      # copies that arrive are taken as any other system's, and its LSP
      # expires as theirs do.
      class Generator
        def initialize(simulator, originator, name)
          @simulator = simulator
          @originator = originator
          @name = name
        end

        def generates?(lsp_id)
          @simulator.generating? && !@simulator.stale?(@name) && @originator.generates?(lsp_id)
        end

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
        @faults = []
        @sent = []
        @behaviour = nil
        @stale = []
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
        @behaviour&.fetch(:timers)&.each(&:cancel)
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
        s = live(name)
        s.overload = on ? true : false
        @originators[s.name].each_value { |o| o.overload = s.overload }
        event(:router, "#{s.name} overload #{s.overload ? 'set' : 'cleared'}")
        s
      end

      # The default metric ATT bit in +name+'s Level 1 LSP Number 0 (7.2.9.2).
      def router_attached(name, on)
        s = live(name)
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
      # or all of them, so its neighbours' adjacencies time out. A circuit
      # already sending is not started again, which would run a second
      # hello timer beside the first.
      # A fault of the catalog (ISIS::Fault) in simulated system +name+'s
      # LSPs: the entry's Router Capability in place of the system's own,
      # and its reachability, a +prefix+ of its own with +index+, after the
      # system's. The system needs segment routing. Answers the entry, the
      # context it was built for, and its TLVs. +plan+ builds and injects
      # nothing.
      def fault(name, router:, prefix: nil, index: nil, plan: false)
        sys = live(router)
        sr = segment_routing(sys) or raise ArgumentError, "#{router} has no segment routing, so no SR fault applies"
        if @behaviour && @behaviour[:name] == :srgb_change && @behaviour[:params][:router].to_s == sys.name
          raise ArgumentError, "#{sys.name}'s SRGB is moved by srgb_change; stop it first"
        end
        n = @faults.size + 1
        first, size = sr.srgb.first
        ctx = { system_id: sys.system_id.to_s, loopback: prefix || "10.255.250.#{n % 250}/32",
                index: index || size - n, srgb: [first, size], router_id: sr.router_id.to_s,
                second: "10.255.251.#{n % 250}/32" }
        entry = Fault.entry(name.to_s.to_sym)
        tlvs = Fault.tlvs(entry[:name], **ctx)
        answer = { case: entry[:name], router: router, finding: entry[:finding], channel: entry[:channel],
                   expect: entry[:expect], rfc: entry[:rfc], context: ctx.except(:neighbors),
                   tlvs: tlvs.map { |t| { hash: t.to_hash, hex: t.to_shex } } }
        return answer.merge(plan: true) if plan

        @originators[sys.name].each_value { |o| o.inject(tlvs, "simulator: fault #{entry[:name]}") }
        @faults << answer.slice(:case, :router, :finding).merge(prefix: ctx[:loopback], index: ctx[:index],
                                                                 at: @scheduler.now.round(3))
        event(:fault, "fault #{entry[:name]} in #{router}'s LSPs (#{entry[:finding]})")
        answer
      end

      # Takes the injected TLVs out of +name+'s LSPs, or every system's.
      def fault_clear(name = nil)
        names = name ? [simulated(name).name] : @originators.keys
        names.each { |n| @originators[n].each_value { |o| o.inject([], "simulator: fault cleared") if o.injected&.any? } }
        event(:fault, "faults cleared in #{name || 'every system'}")
        { cleared: names }
      end

      attr_reader :faults, :sent

      # The behaviour running, { name:, params:, at: }, or nil.
      def behaviour = @behaviour&.slice(:name, :params, :at)

      # Whether simulated system +name+ is stale: the stale_lsp behaviour
      # holds its LSP as it was.
      def stale?(name) = @stale.include?(name)

      # Runs behaviour +name+ of the catalog (Fault::BEHAVIOURS) with
      # +params+, its defaults filling the rest. One at a time: another
      # is refused until behave_stop. flap ends on its own; stale_lsp and
      # srgb_change hold until behave_stop, which undoes what they did.
      # Answers the entry, the parameters it runs with, and what it
      # changed.
      def behave(name, **params)
        e = Fault.behaviour(name)
        raise ArgumentError, "behaviour #{@behaviour[:name]} runs; stop it first" if @behaviour

        unknown = params.keys - e[:params].keys
        raise ArgumentError, "#{e[:name]} takes #{e[:params].keys.join(', ')}, not #{unknown.join(', ')}" unless unknown.empty?

        p = e[:params].merge(params.compact)
        e[:required].each { |k| raise ArgumentError, "#{e[:name]} needs #{k}" if p[k].nil? }
        @behaviour = { name: e[:name], params: p, at: @scheduler.now.round(3), timers: [], undo: nil }
        begin
          done = send(:"behave_#{e[:name]}", p)
        rescue StandardError
          @behaviour = nil
          raise
        end
        event(:behaviour, "behaviour #{e[:name]} started (#{p.compact.map { |k, v| "#{k} #{v}" }.join(', ')})")
        { behaviour: e[:name], description: e[:description], expect: e[:expect], rfc: e[:rfc], params: p }
          .merge(done || {})
      end

      # Ends the behaviour running, undoing what it did: hellos sent again,
      # a stale system generated again, a moved SRGB put back.
      def behave_stop
        return { stopped: nil } unless @behaviour

        b = @behaviour
        @behaviour = nil
        b[:timers].each(&:cancel)
        b[:undo]&.call
        event(:behaviour, "behaviour #{b[:name]} stopped")
        { stopped: b[:name] }
      end

      # Hellos stopped on +circuit+, or every interface, then started,
      # count times; the behaviour ends with the last start.
      def behave_flap(p)
        count = Integer(p[:count])
        down = Float(p[:down])
        up = Float(p[:up])
        raise ArgumentError, "flap needs a count of 1 or more, and down and up over 0" unless count.positive? && down.positive? && up.positive?

        circuit = p[:circuit]&.to_s
        each_interface(circuit) { nil }
        count.times do |i|
          t = i * (down + up)
          @behaviour[:timers] << @scheduler.after(t) { neighbor_stop(circuit: circuit) }
          @behaviour[:timers] << @scheduler.after(t + down) do
            neighbor_start(circuit: circuit)
            finish(:flap) if i == count - 1
          end
        end
        @behaviour[:undo] = -> { neighbor_start(circuit: circuit) }
        { ends_in: ((count * down) + ((count - 1) * up)).round(3) }
      end

      # The far ends of +router+'s links report them down; its own
      # originators stop, so its LSP is neither refreshed nor generated
      # again, and its Generator answers for nothing.
      def behave_stale_lsp(p)
        s = live(p[:router])
        raise ArgumentError, "nothing to make stale: the simulated systems are not generated now" unless @generating

        links = @topology.links.select { |l| l.up? && [l.from, l.to].include?(s.name) }
        far = links.map { |l| l.from == s.name ? l.to : l.from }.uniq
        @originators[s.name].each_value(&:stop)
        @stale << s.name
        links.each { |l| l.state = :down }
        changed(far, "#{s.name} stale: #{links.map(&:name).join(', ')} down at the far ends")
        @behaviour[:undo] = lambda do
          @stale.delete(s.name)
          links.each { |l| l.state = :up }
          @originators[s.name].each_value(&:start) if @generating
          changed(far + [s.name], "#{s.name} generated again: #{links.map(&:name).join(', ')} up")
        end
        { links: links.map(&:name), lifetime: @topology.lsp_lifetime }
      end

      # +router+'s Router Capability, the simulator's own included, with
      # each SRGB block moved so the first starts at +start+.
      def behave_srgb_change(p)
        sys = system(p[:router])
        raise ArgumentError, "#{sys.name} is stale" if stale?(sys.name)

        os = @originators[sys.name].values
        sr = os.first.segment_routing or raise ArgumentError, "#{sys.name} has no segment routing"
        raise ArgumentError, "#{sys.name} has a fault injected; clear it first" if os.any? { |o| o.injected&.any? }

        first = sr.srgb.first.first
        start = p[:start].nil? ? first + Fault::SRGB_MOVE : Integer(p[:start])
        moved = SegmentRouting.new(router_id: sr.router_id.to_s, srgb: sr.srgb.map { |f, n| [f + start - first, n] },
                                   srlb: sr.srlb)
        os.each { |o| o.inject([moved.capability], "simulator: behaviour srgb_change") }
        @behaviour[:undo] = -> { os.each { |o| o.inject([], "simulator: srgb_change stopped") } }
        { srgb: { from: sr.srgb, to: moved.srgb } }
      end
      private :behave_flap, :behave_stale_lsp, :behave_srgb_change

      # Sends +octets+, any PDU or none, as they are, on +circuit+'s
      # circuits, or every interface's. Pdu.factory keeps what it cannot
      # read and writes the same octets back (docs/parse-policy.md).
      def send_pdu(octets, circuit: nil)
        pdu = Pdu.factory(Octets.new(octets.b))
        count = 0
        each_interface(circuit) do |c|
          c.transmit(pdu)
          count += 1
        end
        @sent << { octets: octets.bytesize, circuit: circuit, circuits: count, at: @scheduler.now.round(3) }
        event(:send, "sent #{octets.bytesize} octets on #{circuit || 'every interface'}")
        { sent: count, octets: octets.bytesize, pdu: pdu.class.name.split("::").last }
      end

      def neighbor_stop(circuit: nil) = each_interface(circuit) { |c| c.stop }.tap { event(:neighbor, "hellos stopped on #{circuit || 'every interface'}") }
      def neighbor_start(circuit: nil) = each_interface(circuit) { |c| c.start unless c.hellos? }.tap { event(:neighbor, "hellos started on #{circuit || 'every interface'}") }

      # What the API's sim.state shows.
      def state
        { generating: @generating, aging: @aging, lsp_lifetime: @topology.lsp_lifetime,
          counts: @topology.counts, levels: levels, metric_style: @topology.metric_style.to_s,
          metric_max: Sim::Topology::LIMITS.fetch(@topology.metric_style)[:link],
          interfaces: @router.interfaces.map { |i| { name: i.name, hellos: i.each_circuit.any?(&:hellos?) } },
          behaviour: behaviour, stale: @stale.dup,
          systems: @topology.all_systems.map { |s| system_state(s) },
          links: @topology.links.each_with_index.map { |l, i| link_state(l).merge(number: i + 1) },
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
        sr = segment_routing(sys)
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
            refresh_interval: refresh_interval, segment_routing: sr
          )
          o.attached = true if level == 1 && sys.attached
          o.attach(Flooder.new(@router.databases[level]))
          @router.databases[level].add_generator(Generator.new(self, o, sys.name))
          [level, o]
        end
      end

      # A simulated system's SegmentRouting, shared by its levels: with the
      # file's segment_routing, for a system with an IPv4 loopback, its
      # Router ID. Its own srgb, else the file's. Nil otherwise.
      def segment_routing(sys)
        sr = @topology.segment_routing or return nil
        lo = sys.loopback && IPAddr.new(sys.loopback)
        return nil unless lo&.ipv4?

        SegmentRouting.new(router_id: lo.to_s, srgb: sys.srgb || sr[:srgb], srlb: sr[:srlb])
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

      # Every simulated system's originators but a stale one's, whose LSP
      # stays as it was.
      def each_simulated(&block)
        @topology.systems.each { |s| @originators[s.name].each_value(&block) unless stale?(s.name) }
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
        names.each { |n| @originators[n].each_value { |o| o.changed("simulator: #{why}") } unless stale?(n) }
      end

      def simulated(name)
        s = system(name)
        raise ArgumentError, "#{name} is the simulator itself, not a simulated system" if s.simulator?

        s
      end

      # A simulated system that is not stale: what an action may change.
      def live(name)
        s = simulated(name)
        raise ArgumentError, "#{s.name} is stale (the stale_lsp behaviour); stop it first" if stale?(s.name)

        s
      end

      # A behaviour that ends on its own.
      def finish(name)
        return unless @behaviour && @behaviour[:name] == name

        @behaviour = nil
        event(:behaviour, "behaviour #{name} done")
      end

      def set_group(name, group, withdraw:)
        s = live(name)
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
          prefixes: s.prefixes.size, externals: s.externals.size, groups: (s.prefixes + s.externals).map(&:group).uniq,
          withdrawn: @withdrawn[s.name].dup, lsps: lsps }
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
