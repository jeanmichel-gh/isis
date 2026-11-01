# frozen_string_literal: true

module ISIS
  module Spf
    # The Decision Process for one level (RFC 1142 7.2): it runs the
    # calculation when its input changes and keeps the routes it found. It
    # computes routes and installs none; route installation is a later
    # mechanism.
    #
    # Its input is clause 7.2.1's: the link state database, and "a signal
    # from the Update Process that a change to a link has occurred". So it
    # listens to the database, and each attached circuit tells it when an
    # adjacency goes Up or Down or the DIS changes. A change runs it after
    # +delay+ seconds on the scheduler, and changes inside that time share
    # one run. Zero, the default, still waits for the current callback to
    # finish, so the LSPs of one flood are counted once.
    #
    # Each step is a method a test can replace on one object: changed
    # decides when to run, and compute does the calculation.
    #
    # Logging: each route added, changed or removed at info, with the
    # reason that started the run, and each run at debug.
    class Decision
      attr_reader :system_id, :database, :circuits, :routes, :paths, :runs
      attr_accessor :max_path_splits, :max_path_metric, :delay

      def initialize(system_id:, database:, scheduler:, log:, max_path_splits: MAXIMUM_PATH_SPLITS,
                     max_path_metric: MAX_PATH_METRIC, delay: 0)
        @system_id = system_id
        @database = database
        @scheduler = scheduler
        @log = log
        @max_path_splits = max_path_splits
        @max_path_metric = max_path_metric
        @delay = delay
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
        why = reasons.uniq.first(3).join("; ")
        why += "; and #{reasons.uniq.size - 3} more" if reasons.uniq.size > 3
        @log.debug("Level #{level} SPF run #{@runs}: #{@paths.size} systems, #{@routes.size} prefixes, " \
                   "after #{why} (RFC 1142 7.2, Annex C.2)")
        report(before, @routes, why)
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
