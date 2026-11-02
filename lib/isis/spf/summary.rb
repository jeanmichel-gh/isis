# frozen_string_literal: true

require "ipaddr"

module ISIS
  module Spf
    # The Level 1 area's IP reachability in the Level 2 LSP of a system at
    # both levels, RFC 1195 section 3.2, "Hierarchical Abbreviation of IP
    # Reachability". After each run of the Level 1 Decision Process it
    # hands the Level 2 originator the area's prefixes:
    #
    # * "Any address obtained from a level 1 LSP which is not superceded by
    #   the manually configured information" goes as it is, at the Level 1
    #   route's metric, which is the clause's "sum of the metric value"
    #   and "the distance from the level 2 router to the appropriate level
    #   1 router", the minimum over the routers that announce it.
    # * Each configured summary, { prefix:, metric: }, goes in place of the
    #   addresses it covers, "if they correspond to at least one address
    #   which is reachable in the area", at its configured metric; "metric
    #   values are not considered when determining if a given configured
    #   address supercedes" one. With no metric configured, a summary goes
    #   at the lowest metric among the routes it covers, which is this
    #   library's choice and not the clause's.
    #
    # Left out: a route with the up/down bit, since RFC 5302 section 4 has
    # "L1L2 routers MUST NOT advertise L2->L1 inter-area routes back into
    # L2"; a route this system advertises itself, which its Level 2 LSP
    # carries already as its own prefixes, though it counts toward
    # activating a summary; and the default route the Level 1 Decision
    # Process adds toward the nearest attached system. A route of the
    # external metric type stays external, which the originator puts in
    # TLV 130 (RFC 5302 section 2.2: those learned from TLV 130 "should be
    # advertised into L2 in TLV 130").
    #
    # Setting new summaries chooses again at once from the last routes, so
    # a change withdraws the prefixes it supersedes, or brings them back,
    # without waiting for a run.
    #
    # Logging: each prefix announced into Level 2 or withdrawn at info, as
    # an event of kind :summary.
    class Summary
      attr_reader :summaries, :announced

      def initialize(originator:, log:, summaries: [])
        @originator = originator
        @log = log
        @summaries = summaries
        @routes = {}
        @announced = []
      end

      # The Level 1 Decision Process ran and found +routes+.
      def update(routes)
        @routes = routes
        choose
      end

      def summaries=(list)
        @summaries = list
        choose
      end

      private

      def choose
        area = @routes.values.reject { |r| r.up_down || r.prefix == Decision::DEFAULT }
        nets = @summaries.map { |s| [s, IPAddr.new(s.fetch(:prefix))] }
        covered = Hash.new { |h, k| h[k] = [] }
        uncovered = []
        area.each do |route|
          net = IPAddr.new(route.prefix)
          summary = nets.find { |_, n| n.prefix <= net.prefix && n.include?(IPAddr.new(net.to_s)) }&.first
          summary ? covered[summary] << route : uncovered << route
        end
        chosen = uncovered.reject(&:local?).map do |r|
          { prefix: r.prefix, metric: r.metric, external: r.external ? true : nil }.compact
        end
        covered.each do |summary, routes|
          chosen << { prefix: summary.fetch(:prefix), metric: summary.fetch(:metric) { routes.map(&:metric).min } }
        end
        chosen.sort_by! { |p| p[:prefix] }
        return if chosen == @announced

        report(@announced, chosen)
        @announced = chosen
        @originator.area_prefixes = chosen
      end

      def report(before, after)
        old = before.to_h { |p| [p[:prefix], p] }
        new = after.to_h { |p| [p[:prefix], p] }
        (new.keys - old.keys).each do |prefix|
          @log.info("Level 1 prefix #{prefix} at #{new[prefix][:metric]} announced into Level 2 " \
                    "(RFC 1195 section 3.2)", kind: :summary, prefix: prefix, change: :added)
        end
        (new.keys & old.keys).reject { |p| new[p] == old[p] }.each do |prefix|
          @log.info("Level 1 prefix #{prefix} announced into Level 2 now at #{new[prefix][:metric]}",
                    kind: :summary, prefix: prefix, change: :changed)
        end
        (old.keys - new.keys).each do |prefix|
          @log.info("Level 1 prefix #{prefix} no longer announced into Level 2", kind: :summary, prefix: prefix,
                                                                                  change: :removed)
        end
      end
    end
  end
end
