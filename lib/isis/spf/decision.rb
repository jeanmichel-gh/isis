# frozen_string_literal: true

module ISIS
  module Spf
    # The Decision Process for one level (RFC 1142 7.2): it runs the
    # calculation when its input changes and keeps the routes it found. It
    # computes routes and hands each change to +forwarding+, an adapter
    # (lib/isis/forwarding/), as a route operation: install, replace or
    # withdraw. With no adapter it installs nothing.
    #
    # Its input is clause 7.2.1's: the link state database, and "a signal
    # from the Update Process that a change to a link has occurred". So it
    # listens to the database, and each attached circuit tells it when an
    # adjacency goes Up or Down or the DIS changes. A change runs it after
    # +delay+ seconds on the scheduler, and changes inside that time share
    # one run. Zero, the default, still waits for the current callback to
    # finish, so the LSPs of one flood are counted once.
    #
    # At Level 1 it adds a default route, 0.0.0.0/0, toward the nearest
    # attached Level 2 system (RFC 1142 7.2.9.1; RFC 1195 section 1.3,
    # traffic outside the area "will be forwarded to the nearest level 2
    # router"), unless a prefix of that name is already as near. Not when
    # this system is attached itself: its own Level 1 LSP Number 0 sets
    # the bit, and its nearest Level 2 system is "Self" (7.2.9.2).
    #
    # At Level 2, with +attached_flag+, the Level 1 originator of a system
    # at both levels, it sets that originator's AttachedFlag after each
    # run: true when the routes reach at least one other area, false when
    # they reach none (RFC 1142 7.2.9.2). A change is logged at info. With
    # +leak+, an Spf::Leak, it hands the Level 2 routes to it after each
    # run, for the Level 1 LSP (RFC 5302 section 2). At Level 1, with
    # +summary+, an Spf::Summary, it hands it the Level 1 routes after each
    # run, for the Level 2 LSP (RFC 1195 section 3.2).
    #
    # Each step is a method a test can replace on one object: changed
    # decides when to run, and compute does the calculation.
    #
    # Logging: each route added, changed or removed at info, with the
    # reason that started the run, and each run at info as an event of
    # kind :spf, with up to REASONS_KEPT of its reasons, so a viewer
    # (routescope's Timeline) can see every run and what started it.
    class Decision
      REASONS_KEPT = 20
      attr_reader :system_id, :database, :circuits, :routes, :paths, :runs, :labels
      attr_accessor :max_path_splits, :max_path_metric, :delay, :forwarding, :attached_flag, :leak, :summary
      # A SegmentRouting, or nil: with one, each run also builds the label
      # table (Spf::Labels).
      attr_accessor :segment_routing
      # A Forwarding::LabelTable the label table is installed through, or nil.
      attr_accessor :label_table
      # The interfaces with ti_lfa, name => :link or :node: with any, and
      # segment routing, each run also computes TI-LFA's backups
      # (Spf::Backups).
      attr_accessor :ti_lfa
      # The last run's Spf::Backups, or nil.
      attr_reader :backups
      # This level's Spf::FlexAlgo, or nil: each run selects again, before
      # the routes, so a change of taking part regenerates the LSP.
      attr_accessor :flex_algo
      # With segment routing and a flex_algo, each algorithm this system
      # takes part in: its routes (prefix => Route), from its own
      # calculation, and its label table (Spf::Labels), installed beside
      # algorithm 0's. No IP route comes from them (docs/design/
      # flex-algo.md, "Calculation").
      attr_reader :flex_routes, :flex_labels
      # With ti_lfa too, each such algorithm's Spf::Backups, on its own
      # graph (docs/design/flex-algo.md, "TI-LFA per algorithm").
      attr_reader :flex_backups
      # This system's Srv6::Local, or nil: with one, the calculation reads
      # the locators of TLV 27, and each run builds the SRv6 table
      # (Spf::Srv6), kept as +srv6_table+.
      attr_accessor :srv6
      attr_reader :srv6_table

      def initialize(system_id:, database:, scheduler:, log:, max_path_splits: MAXIMUM_PATH_SPLITS,
                     max_path_metric: MAX_PATH_METRIC, delay: 0, forwarding: nil,
                     attached_flag: nil, leak: nil, summary: nil, segment_routing: nil)
        @system_id = system_id
        @database = database
        @scheduler = scheduler
        @log = log
        @max_path_splits = max_path_splits
        @max_path_metric = max_path_metric
        @delay = delay
        @forwarding = forwarding
        @attached_flag = attached_flag
        @leak = leak
        @summary = summary
        @segment_routing = segment_routing
        @labels = nil
        @ti_lfa = {}
        @backups = nil
        @flex_algo = nil
        @flex_routes = {}
        @flex_labels = {}
        @flex_backups = {}
        @srv6 = nil
        @srv6_table = nil
        @circuits = []
        @routes = {}
        @paths = {}
        @runs = 0
        @pending = nil
        @started = false
        @reasons = []
        database.listen(self)
      end

      def level
        @database.level
      end

      # A circuit whose adjacencies are the first hops. It answers
      # spf_adjacencies, [node ID, metric, Adjacency] for each adjacency Up,
      # and spf_broadcast, [pseudonode ID, metric, Adjacency to the DIS] or
      # nil; and it calls changed when either moves.
      def attach(circuit)
        @circuits << circuit unless @circuits.include?(circuit)
        circuit.decision = self if circuit.respond_to?(:decision=)
        self
      end

      def start
        @started = true
        changed("start")
        self
      end

      def stop
        @pending&.cancel
        @pending = nil
        @started = false
        self
      end

      # The database stored +entry+.
      def stored(entry)
        changed("LSP #{entry.lsp_id_s} #{entry.purged? ? 'purged' : "sequence #{format('0x%08x', entry.sequence)}"}")
      end

      # Something the calculation reads moved: run it after the delay.
      def changed(reason)
        return unless @started

        @reasons << reason
        @pending ||= @scheduler.after(@delay) do
          @pending = nil
          reasons = @reasons
          @reasons = []
          run(reasons)
        end
      end

      # Run now and keep the result. Returns the routes.
      def run(reasons = ["asked"])
        calc = compute
        @runs += 1
        before = @routes
        @paths = calc.paths
        @routes = calc.routes
        add_default(calc.attached) if level == 1 && !calc.self_attached?
        why = reasons.uniq.first(3).join("; ")
        why += "; and #{reasons.uniq.size - 3} more" if reasons.uniq.size > 3
        set_attached(calc.reaches_other_area?, why) if level == 2 && @attached_flag
        @flex_algo&.update(why)
        old_labels = @labels
        old_backups = @backups
        label(calc) if @segment_routing
        build_srv6(calc) if @srv6
        flex(why) if @segment_routing && @flex_algo
        # No interface protected any more: no backups, so the forwarding
        # withdraws the last run's.
        if @segment_routing && @ti_lfa.any?
          protect
        else
          @backups = nil
        end
        @leak.update(@routes) if level == 2 && @leak
        @summary.update(@routes) if level == 1 && @summary
        @log.info("Level #{level} SPF run #{@runs}: #{@paths.size} systems, #{@routes.size} prefixes, " \
                  "after #{why} (RFC 1142 7.2, Annex C.2)",
                  kind: :spf, level: level, run: @runs, systems: @paths.size, prefixes: @routes.size,
                  reasons: reasons.uniq.first(REASONS_KEPT), more: [reasons.uniq.size - REASONS_KEPT, 0].max)
        report(before, @routes, why)
        install(before, @routes, old_labels, old_backups)
        @label_table&.update(level, @labels, @flex_labels.values)
        @routes
      end

      # One calculation over the database and the circuits as they are now.
      def compute
        adjacencies = @circuits.flat_map(&:spf_adjacencies)
        broadcast = @circuits.filter_map(&:spf_broadcast)
        Calculation.new(database: @database, system_id: @system_id, adjacencies: adjacencies, broadcast: broadcast,
                        max_path_splits: @max_path_splits, max_path_metric: @max_path_metric,
                        srv6: @srv6 && Validation.policy(@srv6.receive_policy)).run
      end

      # Algorithm +algorithm+'s calculation, with +definition+ its winning
      # FAD.
      def compute_flex(algorithm, definition)
        adjacencies = @circuits.flat_map(&:spf_adjacencies)
        broadcast = @circuits.filter_map(&:spf_broadcast)
        Calculation.new(database: @database, system_id: @system_id, adjacencies: adjacencies, broadcast: broadcast,
                        max_path_splits: @max_path_splits, max_path_metric: @max_path_metric,
                        algorithm: algorithm, definition: definition, policy: receive_policy).run
      end

      private

      DEFAULT = "0.0.0.0/0"

      def receive_policy
        (@segment_routing.receive_policy if @segment_routing.respond_to?(:receive_policy)) || :rfc
      end

      # Each algorithm this system takes part in: its routes and its label
      # table, in algorithm order, each table's indexes checked against
      # those before it, algorithm 0's first. A route of an algorithm that
      # changed is logged at info, as kind :flex_algo_route; a new label
      # problem at warn, as for algorithm 0.
      def flex(why)
        before = @flex_routes
        old_labels = @flex_labels
        old_backups = @flex_backups
        @flex_routes = {}
        @flex_labels = {}
        @flex_backups = {}
        taken = (@labels&.indexes || {}).transform_values { [_1, 0] }
        @flex_algo.participating.each do |k|
          calc = compute_flex(k, @flex_algo.statuses[k].winner)
          @flex_routes[k] = calc.routes
          table = Labels.new(own: @segment_routing, database: @database, paths: calc.paths, algorithm: k)
                        .build(calc.routes, [], taken: taken)
          @flex_labels[k] = table
          table.indexes.each { |i, p| taken[i] ||= [p, k] }
          named = table.findings.to_h { [_1.to_s, _1.name] }
          (table.problems - (old_labels[k]&.problems || [])).each do |p|
            text = named[p] ? "#{named[p]}: #{p}" : p
            @log.warn("Level #{level} algorithm #{k} segment routing: #{text}", kind: :sr, level: level, algorithm: k)
          end
          report_flex(k, before[k] || {}, calc.routes, why)
          protect_flex(k, calc.routes, table, old_backups[k]) if @ti_lfa.any?
        end
        # An algorithm no longer taken part in: each of its routes goes.
        (before.keys - @flex_routes.keys).each { report_flex(_1, before[_1], {}, why) }
      end

      # Algorithm +algorithm+'s backups, logged as algorithm 0's are, with
      # the algorithm, when what they protect changes.
      def protect_flex(algorithm, routes, table, old)
        backups = Backups.new(database: @database, system_id: @system_id, routes: routes, labels: table,
                              adjacencies: @circuits.flat_map(&:spf_adjacencies), interfaces: @ti_lfa,
                              clock: @scheduler, algorithm: algorithm,
                              definition: @flex_algo.statuses[algorithm].winner, policy: receive_policy).compute
        @flex_backups[algorithm] = backups
        text = summary_text(backups)
        return if text == summary_text(old)

        @log.info("Level #{level} algorithm #{algorithm} TI-LFA: #{text}, #{backups.trees} trees (RFC 9855 section 8)",
                  kind: :ti_lfa, level: level, algorithm: algorithm, trees: backups.trees)
      end

      def report_flex(algorithm, before, after, why)
        (before.keys | after.keys).sort.each do |prefix|
          old = before[prefix]
          new = after[prefix]
          next if old && new && old.metric == new.metric && old.adjacencies == new.adjacencies

          change = new.nil? ? :removed : (old ? :changed : :added)
          text = new.nil? ? "#{prefix} removed" : "#{new} #{change}"
          @log.info("Level #{level} algorithm #{algorithm} route #{text}, after #{why} (RFC 9350 section 13)",
                    kind: :flex_algo_route, level: level, algorithm: algorithm, prefix: prefix, change: change)
        end
      end

      # The label table for this run's routes. A problem is logged once,
      # when it first appears, at warn: it is a label not installed. A
      # finding is logged by its name.
      def label(calc)
        before = @labels&.problems || []
        adjacencies = @circuits.flat_map(&:spf_adjacencies).map { |_, _, a| a }
        @labels = Labels.new(own: @segment_routing, database: @database, paths: calc.paths).build(@routes, adjacencies)
        named = @labels.findings.to_h { [_1.to_s, _1.name] }
        (@labels.problems - before).each do |p|
          text = named[p] ? "#{named[p]}: #{p}" : p
          @log.warn("Level #{level} segment routing: #{text}", kind: :sr, level: level)
        end
      end

      # The SRv6 table for this run (Spf::Srv6). Each finding is logged once,
      # when it first appears, at warn with its clause; each locator learned
      # or withdrawn at info; both as events of kind :srv6.
      def build_srv6(calc)
        before = @srv6_table
        adjacencies = @circuits.flat_map(&:spf_adjacencies).map { |_, _, a| a }
        @srv6_table = Srv6.new(local: @srv6, database: @database, paths: calc.paths, routes: @routes,
                               adjacencies: adjacencies).build
        (@srv6_table.findings - (before&.findings || [])).each do |f|
          @log.warn("Level #{level} SRv6: #{f.name}: #{f}", kind: :srv6, level: level, finding: f.name)
        end
        old = locator_set(before)
        new = locator_set(@srv6_table)
        (new - old).each do |id, prefix, algorithm|
          @log.info("Level #{level} SRv6 locator #{prefix} algorithm #{algorithm} of #{id} learned (RFC 9352 section 7.1)",
                    kind: :srv6, level: level, system_id: id, locator: prefix, algorithm: algorithm, change: :added)
        end
        (old - new).each do |id, prefix, algorithm|
          @log.info("Level #{level} SRv6 locator #{prefix} algorithm #{algorithm} of #{id} withdrawn",
                    kind: :srv6, level: level, system_id: id, locator: prefix, algorithm: algorithm, change: :removed)
        end
      end

      # The locators of other systems in +table+, as [System ID, prefix,
      # algorithm].
      def locator_set(table)
        return [] unless table

        mine = Pdu.dotted_octets(@system_id)
        table.nodes.flat_map do |node, n|
          next [] if node.byteslice(0, 6) == mine

          id = SystemId.from_bytes(node.byteslice(0, 6)).to_s
          n.locators.map { [id, _1.prefix, _1.algorithm] }
        end
      end

      # TI-LFA's backups for this run's routes. A reason a destination is
      # left unprotected is logged once, when it first appears.
      def protect
        before = summary_text(@backups)
        @backups = Backups.new(database: @database, system_id: @system_id, routes: @routes, labels: @labels,
                               adjacencies: @circuits.flat_map(&:spf_adjacencies), interfaces: @ti_lfa,
                               clock: @scheduler).compute
        text = summary_text(@backups)
        return if text == before

        @log.info("Level #{level} TI-LFA: #{text}, #{@backups.trees} trees (RFC 9855)",
                  kind: :ti_lfa, level: level, trees: @backups.trees)
      end

      def summary_text(backups)
        return nil unless backups

        backups.summaries.map do |s|
          left = s.unprotected.map { |k, v| "#{v} #{k}" }
          "#{s.interface} (#{s.mode}) #{s.protected} protected, #{s.ecmp} by ECMP" \
            "#{s.fallback.positive? ? ", #{s.fallback} by the link" : ''}" \
            "#{left.empty? ? '' : ", unprotected #{left.join(', ')}"}"
        end.join("; ")
      end

      def add_default(attached)
        return if attached.nil?

        held = @routes[DEFAULT]
        return if held && held.metric <= attached.distance

        @routes[DEFAULT] = Route.new(DEFAULT, attached.distance, attached.adjacencies)
      end

      def set_attached(reach, why)
        return if @attached_flag.attached == reach

        @log.info("Level 2 routes #{reach ? 'reach' : 'reach no'} other area, AttachedFlag " \
                  "#{reach ? 'set' : 'cleared'} in the Level 1 LSP, after #{why} (RFC 1142 7.2.9.2)",
                  kind: :attached, attached: reach)
        @attached_flag.attached = reach
      end

      # Each route operation, in prefix order, to the adapter.
      # The IP routes, each next hop with the label it pushes when there is
      # a label table.
      # The routes, then TI-LFA's backups beside them, through the adapter.
      def install(before, after, old_labels = nil, old_backups = nil)
        return unless @forwarding

        labels = [old_labels&.out_labels, @labels&.out_labels]
        Forwarding.operations(before, after, level: level, labels: labels).each { |op| @forwarding.apply(op) }
        Forwarding.backup_operations(old_backups&.routes, @backups&.routes, level: level).each { |op| @forwarding.apply(op) }
      end

      def report(before, after, why)
        (before.keys | after.keys).sort.each do |prefix|
          old = before[prefix]
          new = after[prefix]
          next if old && new && old.metric == new.metric && old.adjacencies == new.adjacencies

          if new.nil?
            @log.info("Level #{level} route #{prefix} removed, after #{why}", kind: :route, level: level,
                                                                              prefix: prefix, change: :removed)
          else
            change = old ? :changed : :added
            @log.info("Level #{level} route #{new} #{change}, after #{why}", kind: :route, level: level,
                                                                             prefix: prefix, change: change)
          end
        end
      end
    end
  end
end
