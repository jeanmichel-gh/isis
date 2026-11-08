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
      attr_reader :system_id, :database, :circuits, :routes, :paths, :runs
      attr_accessor :max_path_splits, :max_path_metric, :delay, :forwarding, :attached_flag, :leak, :summary

      def initialize(system_id:, database:, scheduler:, log:, max_path_splits: MAXIMUM_PATH_SPLITS,
                     max_path_metric: MAX_PATH_METRIC, delay: 0, forwarding: nil,
                     attached_flag: nil, leak: nil, summary: nil)
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
        @leak.update(@routes) if level == 2 && @leak
        @summary.update(@routes) if level == 1 && @summary
        @log.info("Level #{level} SPF run #{@runs}: #{@paths.size} systems, #{@routes.size} prefixes, " \
                  "after #{why} (RFC 1142 7.2, Annex C.2)",
                  kind: :spf, level: level, run: @runs, systems: @paths.size, prefixes: @routes.size,
                  reasons: reasons.uniq.first(REASONS_KEPT), more: [reasons.uniq.size - REASONS_KEPT, 0].max)
        report(before, @routes, why)
        install(before, @routes)
        @routes
      end

      # One calculation over the database and the circuits as they are now.
      def compute
        adjacencies = @circuits.flat_map(&:spf_adjacencies)
        broadcast = @circuits.filter_map(&:spf_broadcast)
        Calculation.new(database: @database, system_id: @system_id, adjacencies: adjacencies, broadcast: broadcast,
                        max_path_splits: @max_path_splits, max_path_metric: @max_path_metric).run
      end

      private

      DEFAULT = "0.0.0.0/0"

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
      def install(before, after)
        return unless @forwarding

        Forwarding.operations(before, after, level: level).each { |op| @forwarding.apply(op) }
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
