# frozen_string_literal: true

require "ipaddr"

module ISIS
  # Redistribution: routes from outside IS-IS made this system's external
  # prefixes, which the originator sends in TLV 130 or 135, and TLV 236 for
  # IPv6 (Originator, external_prefixes).
  #
  # +source+ answers #routes with the host's routes, each a hash with
  # :prefix, :table, :protocol, :scope and :type, as
  # Forwarding::Netlink#routes reads them from the Linux kernel. +kinds+
  # says which are taken, by the protocol the kernel records:
  #
  #   :connected  a link's own subnet, which the kernel adds itself,
  #               RTPROT_KERNEL; not an IPv6 link-local fe80::/10 one
  #   :static     a route someone configured, RTPROT_BOOT, what `ip route
  #               add` gives, or RTPROT_STATIC
  #
  # Scope is not read: the kernel gives an IPv4 subnet link scope and an
  # IPv6 one universe scope, and a configured route can have either.
  # Each from the main table, unicast or blackhole, at +metric+, of the
  # external metric type when +external+. Nothing is taken by default.
  # It reads the source at start and every +interval+ seconds on the
  # scheduler, and at once when +kinds+ changes, so a route removed from
  # the host, or a kind no longer taken, is withdrawn by the next LSP. A
  # route this system installed itself, RTPROT_ISIS, is of neither kind,
  # so it is never taken.
  #
  # Logging: each prefix taken or let go at info, as an event of kind
  # :redistribution.
  class Redistribution
    MAIN = 254
    UNICAST = 1
    BLACKHOLE = 6
    LINK_LOCAL = IPAddr.new("fe80::/10")
    KINDS = {
      connected: lambda do |r|
        r[:protocol] == Forwarding::Netlink::RTPROT_KERNEL && !(r[:family] == :ipv6 && LINK_LOCAL.include?(IPAddr.new(r[:prefix].split("/").first)))
      end,
      static: ->(r) { [Forwarding::Netlink::RTPROT_BOOT, Forwarding::Netlink::RTPROT_STATIC].include?(r[:protocol]) }
    }.freeze

    attr_reader :kinds, :taken, :interval

    def initialize(originator:, scheduler:, log:, source:, kinds: [], metric: 0, external: false, interval: 5)
      @originator = originator
      @scheduler = scheduler
      @log = log
      @source = source
      @kinds = kinds.map(&:to_sym)
      @metric = metric
      @external = external
      @interval = interval
      @taken = []
      @timer = nil
    end

    def start
      refresh
      @timer = @scheduler.after(@interval) { tick }
      self
    end

    def stop
      @timer&.cancel
      @timer = nil
      self
    end

    def kinds=(list)
      @kinds = list.map(&:to_sym)
      refresh
    end

    # Read the source and hand the originator what it takes, if that moved.
    def refresh
      unknown = @kinds - KINDS.keys
      raise ArgumentError, "no redistribution of #{unknown.join(', ')}" unless unknown.empty?

      rows = @kinds.empty? ? [] : @source.routes
      chosen = rows.select { |r| take?(r) }.map { |r| r[:prefix] }.uniq.sort.map do |prefix|
        { prefix: prefix, metric: @metric, external: @external || nil }.compact
      end
      return if chosen == @taken

      report(@taken.map { |p| p[:prefix] }, chosen.map { |p| p[:prefix] })
      @taken = chosen
      @originator.external_prefixes = chosen
    end

    private

    def tick
      @timer = @scheduler.after(@interval) { tick }
      refresh
    end

    def take?(route)
      route[:table] == MAIN && [UNICAST, BLACKHOLE].include?(route[:type]) &&
        @kinds.any? { |k| KINDS.fetch(k).call(route) }
    end

    def report(before, after)
      (after - before).each do |prefix|
        @log.info("#{prefix} redistributed at #{@metric}", kind: :redistribution, prefix: prefix, change: :added)
      end
      (before - after).each do |prefix|
        @log.info("#{prefix} no longer redistributed", kind: :redistribution, prefix: prefix, change: :removed)
      end
    end
  end
end
