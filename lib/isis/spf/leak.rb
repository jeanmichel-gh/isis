# frozen_string_literal: true

require "ipaddr"

module ISIS
  module Spf
    # Route leaking from Level 2 into Level 1 at a system at both levels,
    # RFC 5302's "L2->L1 inter-area routes". After each run of the Level 2
    # Decision Process it chooses the Level 2 routes +policy+ allows and
    # hands them to the Level 1 originator, which advertises them with the
    # up/down bit set.
    #
    # RFC 5302 section 4 recommends against doing so by default: "it is
    # RECOMMENDED that L2 routes not be advertised into L1 by default", so
    # the default policy allows nothing. +policy+ answers, for a Route,
    # whether to leak it; Leak.prefixes builds one from a list of covering
    # prefixes. Setting a new policy chooses again from the last routes, so
    # a change withdraws what it no longer allows without waiting for a
    # run.
    #
    # A route this system advertises itself is never leaked, whatever the
    # policy: it has no Level 2 next hop. Section 4's other rule, "L1L2
    # routers MUST NOT advertise L2->L1 inter-area routes back into L2",
    # asks nothing here, since this system advertises no Level 1 routes
    # into Level 2 at all.
    #
    # Logging: each prefix leaked or no longer leaked at info, as an event
    # of kind :leak.
    class Leak
      NONE = ->(_route) { false }

      attr_reader :policy, :leaked

      def initialize(originator:, log:, policy: NONE)
        @originator = originator
        @log = log
        @policy = policy
        @routes = {}
        @leaked = []
      end

      # A policy that leaks a route whose prefix lies within one of
      # +list+, "203.0.113.0/24" or "2001:db8::/32": at least as long, and
      # its address inside. The address is tested bare, since whether
      # IPAddr#include? compares a masked argument's whole range depends
      # on the ipaddr version; and include? is false across families.
      def self.prefixes(list)
        nets = list.map { |p| IPAddr.new(p) }
        lambda do |route|
          net = IPAddr.new(route.prefix)
          addr = IPAddr.new(net.to_s)
          nets.any? { |n| n.prefix <= net.prefix && n.include?(addr) }
        end
      end

      # The Level 2 Decision Process ran and found +routes+.
      def update(routes)
        @routes = routes
        choose
      end

      def policy=(policy)
        @policy = policy
        choose
      end

      private

      def choose
        chosen = @routes.values.reject(&:local?).select { |r| @policy.call(r) }.sort_by(&:prefix).map do |r|
          { prefix: r.prefix, metric: r.metric, external: r.external ? true : nil, sid: r.sid&.to_hash }.compact
        end
        return if chosen == @leaked

        before = @leaked.to_h { |p| [p[:prefix], p] }
        after = chosen.to_h { |p| [p[:prefix], p] }
        (after.keys - before.keys).each do |prefix|
          @log.info("Level 2 route #{prefix} at #{after[prefix][:metric]} leaked into Level 1, up/down set " \
                    "(RFC 5302 section 2)", kind: :leak, prefix: prefix, change: :added)
        end
        (after.keys & before.keys).reject { |p| after[p] == before[p] }.each do |prefix|
          @log.info("Level 2 route #{prefix} leaked into Level 1 now at #{after[prefix][:metric]}",
                    kind: :leak, prefix: prefix, change: :changed)
        end
        (before.keys - after.keys).each do |prefix|
          @log.info("Level 2 route #{prefix} no longer leaked into Level 1", kind: :leak, prefix: prefix,
                                                                             change: :removed)
        end
        @leaked = chosen
        @originator.leaked_prefixes = chosen
      end
    end
  end
end
