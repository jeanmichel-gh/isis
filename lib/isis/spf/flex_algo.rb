# frozen_string_literal: true

module ISIS
  module Spf
    # Flex-algo selection and participation for one level (RFC 9350
    # section 5.3; docs/design/flex-algo.md, "Selection"):
    #
    # 1. Every FAD of the level: each system's, from its LSPs with LSP
    #    Number 0 present, merged by section 6 (Spf::Definitions); this
    #    system's own from its configuration, as it advertises them.
    # 2. For each configured algorithm, the winner: "the numerically
    #    greatest priority value", then "the numerically greatest
    #    System-ID".
    # 3. This system takes part when the winner is one it can run. With no
    #    FAD, or one it cannot run, it "MUST stop participating".
    #
    # An algorithm not configured is not looked at: a router "not
    # configured to participate ... MUST ignore FAD sub-TLV advertisements"
    # for it. No Level 1 copy of the Level 2 winner (decision 5).
    #
    # The Decision Process runs #update after each SPF run. A change of
    # winner, of support or of taking part is an event of kind :flex_algo,
    # at info; a change of taking part regenerates this system's LSP, whose
    # SR-Algorithm and Prefix-SIDs follow #participating.
    class FlexAlgo
      # What this system sees of one configured algorithm.
      Status = Struct.new(:algorithm, :winner, :origin, :participating, :candidates, keyword_init: true) do
        def supported? = winner&.supported? || false

        # Why this system does not take part, or nil.
        def reason
          return nil if participating
          return "no FAD" unless winner

          "the winning FAD: #{winner.unsupported}"
        end

        def to_hash
          h = { algorithm: algorithm, participating: participating }
          if winner
            h[:winner] = winner.to_hash.except(:algorithm, :unsupported).merge(origin: origin)
            h[:supported] = supported?
          end
          h[:reason] = reason if reason
          h[:candidates] = candidates
          h
        end
      end

      # This system's own LSP stands for it as its configuration says.
      Own = Struct.new(:tlvs)

      attr_reader :level, :statuses, :findings
      # The Originator of this level, told when taking part changes.
      attr_accessor :originator

      def initialize(level:, system_id:, database:, config:, log:, policy: :rfc)
        @level = level
        @system_id = Pdu.dotted_octets(system_id).b
        @database = database
        @config = config
        @log = log
        @policy = policy
        @statuses = {}
        @findings = []
        update(nil)
      end

      # The configured algorithms this system takes part in, in order.
      def participating
        @statuses.values.select(&:participating).map(&:algorithm).sort
      end

      def participating?(algorithm) = @statuses[algorithm]&.participating || false

      # The FAD sub-TLVs this system advertises, from its configuration.
      def fads = @config.fads

      # Select again from the database as it is. Logs each change, and
      # tells the originator when taking part changed. Returns whether it
      # did.
      def update(why = "SPF run")
        before = @statuses
        definitions, @findings = read
        @statuses = @config.algorithms.to_h { |a| [a, status(a, definitions)] }
        changed = before.values.select(&:participating).map(&:algorithm) != participating
        report(before, why) if why
        @originator&.changed("flex-algo: taking part in #{participating.empty? ? 'none' : participating.join(', ')}") if changed && why
        changed
      end

      def to_hash
        { level: @level, participating: participating, algorithms: @statuses.values.map(&:to_hash),
          findings: @findings.map(&:to_hash) }
      end

      private

      # Each system's Definitions, System ID => Spf::Definitions, and the
      # findings on all of them.
      def read
        nodes = @database.entries.reject { _1.placeholder? || _1.purged? }
                         .select { _1.lsp_id.getbyte(6).zero? }
                         .group_by { _1.lsp_id.b[0, 6] }
        found = {}
        findings = []
        nodes.each do |id, entries|
          next if id == @system_id
          next unless entries.any? { _1.lsp_id.getbyte(7).zero? }

          d = Definitions.new(entries.sort_by { _1.lsp_id.getbyte(7) }.map(&:lsp), policy: @policy,
                              subject: SystemId.from_bytes(id).to_s)
          found[id] = d
          findings.concat(d.findings)
        end
        own = [Own.new([Tlv::RouterCapability.new(router_id: "0.0.0.0", subtlvs: @config.fads)])]
        found[@system_id] = Definitions.new(own, policy: @policy, subject: SystemId.from_bytes(@system_id).to_s)
        [found, findings]
      end

      def status(algorithm, definitions)
        offers = definitions.filter_map { |id, d| [id, d[algorithm]] if d[algorithm] }
        # The winner first: the greatest priority, then the greatest
        # System ID, compared as octets.
        ranked = offers.sort_by { |id, d| [d.priority, id] }.reverse
        win_id, winner = ranked.first
        candidates = ranked.map { |id, d| { origin: SystemId.from_bytes(id).to_s, priority: d.priority } }
        Status.new(algorithm: algorithm, winner: winner, origin: win_id && SystemId.from_bytes(win_id).to_s,
                   participating: winner&.supported? || false, candidates: candidates)
      end

      def report(before, why)
        @statuses.each_value do |s|
          b = before[s.algorithm]
          next if b && [b.origin, b.winner&.to_hash, b.participating] == [s.origin, s.winner&.to_hash, s.participating]

          text = if s.participating
                   "taking part, the FAD of #{s.origin} (priority #{s.winner.priority}, metric #{s.winner.metric_name})"
                 else
                   "not taking part: #{s.reason}"
                 end
          @log.info("Level #{@level} flex-algo #{s.algorithm}: #{text}, after #{why} (RFC 9350 section 5.3)",
                    kind: :flex_algo, level: @level, algorithm: s.algorithm, participating: s.participating,
                    origin: s.origin)
        end
      end
    end
  end
end
