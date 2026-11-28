# frozen_string_literal: true

require "ipaddr"

module ISIS
  module Spf
    # What one level's LSPs say about SRv6 (RFC 9352), read after each SPF
    # run beside Spf::Labels (docs/design/srv6.md, "Calculation"): each
    # reachable system's SRv6 Capabilities, its locators and End SIDs from
    # TLV 27, and its End.X and LAN End.X SIDs from TLV 22; and this
    # system's own SIDs, each End.X with the adjacency it is for. It
    # computes and installs nothing, and changes neither the routes nor
    # the database.
    #
    # The SRv6 rules of ISIS::Validation run here, each finding acted on
    # under the receive policy (+policy+, srv6's receive_policy, :rfc by
    # default). Srv6.read reads one system, and the calculation uses it
    # too, for the locator routes (Calculation, srv6:), so a locator the
    # rules ignore is not routed from TLV 27.
    #
    # Other systems' SIDs are only kept, for the view and for TI-LFA:
    # section 5, "SRv6 SIDs received from other nodes are not directly
    # routable and MUST NOT be installed in the forwarding plane".
    #
    # Only MTID 0 is read: TLV 27 for another topology is multi topology,
    # which isis4r does not run.
    class Srv6
      # One locator a system advertises: its prefix, algorithm, metric, D
      # bit (+up_down+) and Prefix Attribute Flags letters, the TLV 27
      # entry it came from, and its End SIDs that the rules let through.
      Locator = Struct.new(:prefix, :algorithm, :metric, :up_down, :flags, :entry, :end_sids, keyword_init: true) do
        # The entry with only the usable End SIDs, for propagating to the
        # other level (Srv6::Local.propagated).
        def usable_entry
          keep = end_sids.map(&:subtlv)
          h = entry.to_hash
          subs = entry.subtlvs.to_a
          h[:subtlvs] = Array(h[:subtlvs]).each_with_index.reject do |_, i|
            subs[i].is_a?(SubTlv::Srv6EndSid) && keep.none? { _1.equal?(subs[i]) }
          end.map(&:first)
          h
        end

        def to_hash
          { prefix: prefix, algorithm: algorithm, metric: metric, up_down: up_down ? true : false, flags: flags,
            end_sids: end_sids.map(&:to_hash) }
        end
      end

      # One SID: its value, behaviour codepoint, :end or :end_x, and for
      # End.X its algorithm, weight, flags and neighbour (the TLV 22
      # entry's node ID, or the LAN End.X's System ID, +lan+ true), and the
      # SID Structure as [block, node, function, argument] or nil.
      # +subtlv+ is the sub-TLV it came from.
      Sid = Struct.new(:sid, :behavior, :kind, :algorithm, :weight, :flags, :neighbor, :lan, :structure, :subtlv,
                       keyword_init: true) do
        def to_hash
          h = { sid: sid, behavior: Srv6.behavior_text(behavior) }
          if kind == :end_x
            h.merge!(algorithm: algorithm, weight: weight, flags: flags, neighbor: neighbor, lan: lan ? true : false)
          end
          h[:structure] = structure if structure
          h
        end
      end

      # One system as Srv6.read finds it: its SRv6 Capabilities (O flag),
      # or nil when it sends none; its SR-Algorithm list; its locators and
      # End.X SIDs; the findings; and +ignored+, true when a :strict policy
      # refused all of its SRv6 data.
      Node = Struct.new(:capabilities, :algorithms, :locators, :end_x_sids, :findings, :ignored, keyword_init: true) do
        def srv6? = !capabilities.nil?

        # Every usable SID, End first.
        def sids = locators.flat_map(&:end_sids) + end_x_sids
      end

      # One of this system's own SIDs in the table: +kind+ :end, :decap
      # (End.DT6) or :end_x, its locator's name, and for End.X the
      # Spf::Adjacency it leaves on.
      Own = Struct.new(:sid, :behavior, :kind, :locator, :adjacency, keyword_init: true)

      def self.behavior_text(number) = ISIS::Srv6.behavior_name(number).to_s

      # +lsps+ of one system, LSP Number 0 first: what it advertises of
      # SRv6, the rules run on it under +policy+. +subject+ names it in a
      # finding.
      def self.read(lsps, policy: :rfc, subject: "")
        Reader.new(lsps, Validation.policy(policy), subject).node
      end

      attr_reader :nodes, :findings, :problems, :own, :policy

      # +local+ is this system's Srv6::Local; +paths+ and +routes+ the SPF
      # run's; +adjacencies+ the circuits' Spf::Adjacency list.
      def initialize(local:, database:, paths:, routes:, adjacencies:, policy: nil)
        @local = local
        @database = database
        @paths = paths
        @routes = routes
        @adjacencies = adjacencies
        @policy = Validation.policy(policy || local&.receive_policy)
        @nodes = {}
        @findings = []
        @problems = []
        @own = []
      end

      def build
        @paths.each_key do |node|
          next unless node.getbyte(-1).zero?

          lsps = @database.entries.select { |e| e.lsp && !e.purged? && e.lsp_id.byteslice(0, 7) == node }
                          .sort_by { |e| e.lsp_id.getbyte(-1) }.map(&:lsp)
          next if lsps.empty?

          n = Srv6.read(lsps, policy: @policy, subject: SystemId.from_bytes(node.byteslice(0, 6)).to_s)
          n.findings.each { found(_1) }
          @nodes[node] = n unless n.locators.empty? && n.end_x_sids.empty? && !n.srv6?
        end
        longest_match
        own_sids
        self
      end

      # The node of +id+, a System ID and pseudonode octet, or nil.
      def node(id) = @nodes[id.b]

      private

      # Section 5's longest match, for each algorithm 0 locator's SIDs: a
      # route longer than the locator that covers a SID takes the SID's
      # traffic elsewhere. Inconclusive: the clause asks the operator.
      def longest_match
        v6 = @routes.keys.select { _1.include?(":") }.map { [_1, IPAddr.new(_1)] }
        @nodes.each do |node, n|
          subject = SystemId.from_bytes(node.byteslice(0, 6)).to_s
          n.locators.select { _1.algorithm.zero? }.each do |loc|
            sids = loc.end_sids + n.end_x_sids.select { |x| x.algorithm.zero? && IPAddr.new(loc.prefix).include?(IPAddr.new(x.sid)) }
            sids.each do |s|
              addr = IPAddr.new(s.sid)
              best = v6.select { |_, net| net.include?(addr) }.max_by { |_, net| net.prefix }
              next if best.nil? || best.first == loc.prefix || best.last.prefix <= IPAddr.new(loc.prefix).prefix

              found(Validation.finding(:locator_not_longest, subject,
                                       "SID #{s.sid} of locator #{loc.prefix}: #{best.first} is a longer match"))
            end
          end
        end
      end

      # This system's SIDs: End and End.DT6 per locator, and an End.X for
      # each adjacency Up that has one.
      def own_sids
        return unless @local

        up = @adjacencies.to_h { [[_1.circuit.to_s, _1.neighbor.b], _1] }
        @local.sids.each do |s|
          case s[:behavior]
          when "End" then @own << Own.new(sid: s[:sid], behavior: "End", kind: :end, locator: s[:locator])
          when "End.DT6" then @own << Own.new(sid: s[:sid], behavior: "End.DT6", kind: :decap, locator: s[:locator])
          else
            circuit, key = s[:adjacency]
            adj = up[[circuit.to_s, key.b]] or next
            @own << Own.new(sid: s[:sid], behavior: s[:behavior], kind: :end_x, locator: s[:locator], adjacency: adj)
          end
        end
      end

      def found(finding)
        return if @findings.include?(finding)

        @findings << finding
        @problems << finding.to_s unless @problems.include?(finding.to_s)
      end

      # Reads one system's LSPs, rule by rule.
      class Reader
        def initialize(lsps, policy, subject)
          @lsps = lsps
          @policy = policy
          @subject = subject
          @findings = []
        end

        def node
          tlvs = @lsps.flat_map { _1.tlvs.to_a }
          caps = tlvs.grep(Tlv::RouterCapability).flat_map { _1.subtlvs.to_a }
          capability = caps.grep(SubTlv::Srv6Capabilities).first
          algorithms = caps.grep(SubTlv::SrAlgorithm).first&.algorithms&.to_a || []
          locators = read_locators(tlvs.grep(Tlv::Srv6Locator).select { _1.mtid.zero? }, tlvs)
          end_x = read_end_x(tlvs.grep(Tlv::ExtendedIsReachability), locators)
          if @ignored
            locators = []
            end_x = []
          end
          Node.new(capabilities: capability && { o: capability.o? }, algorithms: algorithms, locators: locators,
                   end_x_sids: end_x, findings: @findings, ignored: @ignored ? true : false)
        end

        private

        # The policy's action on a new finding, which is kept; :ignore_node
        # marks the whole system ignored.
        def act(name, detail)
          f = Validation.finding(name, @subject, detail)
          @findings << f unless @findings.include?(f)
          action = Validation.action(f, @policy)
          @ignored = true if action == :ignore_node
          action
        end

        # Each TLV 27's entries, per locator, with the algorithm rule of
        # section 7.2 across TLVs; then each entry's own rules.
        def read_locators(tlv27, tlvs)
          entries = []
          tlv27.each do |tlv|
            bad = tlv.entries.reject(&:locator)
            if bad.any?
              action = nil
              bad.each { |e| action = act(:locator_size_invalid, "Loc-Size #{e.size}") }
              if action == :ignore_tlv
                @refused = true
                next
              end
            end
            tlv.entries.select(&:locator).each { entries << [tlv, _1] }
          end
          by_prefix = entries.group_by { |_, e| e.locator }
          reach = tlvs.grep(Tlv::Ipv6Reachability).flat_map(&:entries).select(&:prefix).group_by(&:prefix)
          by_prefix.filter_map do |prefix, list|
            algos = list.map { |_, e| e.algorithm }.uniq
            if algos.size > 1
              action = act(:locator_algorithm_conflict, "#{prefix} at algorithms #{algos.join(', ')}")
              if action == :ignore_tlvs
                @refused = true
                next
              end

              list = list.select { |_, e| e.algorithm == algos.first }
            end
            locator(prefix, list.map(&:last), reach[prefix])
          end
        end

        def locator(prefix, entries, reach)
          first = entries.first
          paf = entries.flat_map { _1.subtlvs_of(SubTlv::PrefixAttributeFlags) }.first
          flags = paf ? paf.flag_letters : []
          if flags.include?("N") && flags.include?("A")
            case act(:anycast_and_node, "#{prefix}: N and A both set")
            when :ignore_n then flags -= %w[N]
            when :ignore_locator then return refuse
            end
          end
          fapm = entries.flat_map { _1.subtlvs_of(SubTlv::Fapm) }
          if fapm.any? && act(:fapm_in_locator, "#{prefix}: FAPM for algorithm #{fapm.map(&:algorithm).uniq.join(', ')}") ==
                          :ignore_locator
            return refuse
          end

          if paf && reach
            x = reach.first.external ? true : false
            if flags.include?("X") != x
              case act(:x_flag_mismatch, "#{prefix}: X #{flags.include?('X') ? 'set' : 'clear'} in TLV 27, " \
                                         "#{x ? 'set' : 'clear'} in TLV 236")
              when :prefer_reachability then flags = x ? (flags | %w[X]) : flags - %w[X]
              when :ignore_locator then return refuse
              end
            end
          end
          net = IPAddr.new(prefix)
          sids = entries.flat_map { _1.subtlvs_of(SubTlv::Srv6EndSid) }.filter_map do |s|
            next unless usable_sid?(s, :end)

            unless net.include?(IPAddr.new(s.sid))
              next if act(:end_sid_outside_locator, "End SID #{s.sid} is outside #{prefix}") != :use
            end
            sid(s, :end)
          end
          Locator.new(prefix: prefix, algorithm: first.algorithm, metric: first.metric, up_down: first.up_down?,
                      flags: SubTlv::PrefixAttributeFlags::FLAGS & flags, entry: first, end_sids: sids)
        end

        # A locator the rules refused: nil, and the End.X SIDs it would
        # have covered go with it.
        def refuse
          @refused = true
          nil
        end

        # TLV 22's End.X and LAN End.X SIDs, each under a locator of its
        # algorithm (section 8). With a locator refused by a rule, one no
        # usable locator covers is left out with no finding of its own:
        # the locator's finding says why.
        def read_end_x(tlv22, locators)
          tlv22.flat_map(&:entries).flat_map do |e|
            e.subtlvs.to_a.grep(SubTlv::Srv6EndXSid).filter_map do |s|
              next unless usable_sid?(s, :end_x)

              covered = locators.any? { |l| l.algorithm == s.algorithm && IPAddr.new(l.prefix).include?(IPAddr.new(s.sid)) }
              unless covered
                next if @refused
                next if act(:end_x_sid_no_locator, "End.X SID #{s.sid} at algorithm #{s.algorithm}: no locator covers it") != :use
              end
              lan = s.is_a?(SubTlv::Srv6LanEndXSid)
              sid(s, :end_x, neighbor: lan ? "#{s.neighbor_id}.00" : e.neighbor_s, lan: lan)
            end
          end
        end

        # A SID's own rules: its SID Structure (section 9) and its
        # behaviour (sections 7.2, 8.1 and 10). False when the policy has
        # it ignored.
        def usable_sid?(s, kind)
          return false if s.short

          structures = s.subtlvs.to_a.grep(SubTlv::Srv6SidStructure)
          what = "#{kind == :end ? 'End' : 'End.X'} SID #{s.sid}"
          if structures.size > 1 && act(:sid_structure_twice, "#{what}: #{structures.size} SID Structures") == :ignore_sid
            return false
          end
          too_long = structures.first&.total.to_i > 128
          return false if too_long && act(:sid_structure_too_long, "#{what}: the structure is #{structures.first.total} bits") == :ignore_sid

          where = ISIS::Srv6.advertised_in(s.behavior)
          if where.nil?
            act(:behavior_unknown, "#{what}: behaviour #{s.behavior_name}")
            return false
          end
          if where != kind
            return false if act(:behavior_not_allowed, "#{what}: behaviour #{s.behavior_name} goes in " \
                                                       "#{where == :end ? 'an End' : 'an End.X'} SID") != :use
          end
          !@ignored
        end

        def sid(s, kind, neighbor: nil, lan: false)
          st = s.structure
          h = { sid: s.sid, behavior: s.behavior, kind: kind, structure: st && [st.block, st.node, st.function, st.argument],
                subtlv: s }
          if kind == :end_x
            h.merge!(algorithm: s.algorithm, weight: s.weight, flags: s.flag_letters, neighbor: neighbor, lan: lan)
          end
          Sid.new(**h)
        end
      end
    end
  end
end
