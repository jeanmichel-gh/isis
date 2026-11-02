# frozen_string_literal: true

require_relative "../../test_helper"

# Redistribution against a stand-in source of host routes and a stand-in
# originator. The rows are what Forwarding::Netlink#routes answers: main
# table 254, local table 255; type unicast 1, local 2, blackhole 6,
# unreachable 7; protocol 2 kernel, 3 boot, 4 static, 187 IS-IS; scope 0
# universe, 253 link.
class TestRedistribution < Minitest::Test
  Source = Struct.new(:rows, :reads) do
    def routes
      self.reads += 1
      rows
    end
  end

  Originator = Struct.new(:external_prefixes, :sets) do
    def external_prefixes=(list)
      self.sets += 1
      self[:external_prefixes] = list
    end
  end

  def row(prefix, protocol, scope: 0, table: 254, type: 1)
    { family: prefix.include?(":") ? :ipv6 : :ipv4, prefix: prefix, table: table, protocol: protocol,
      scope: scope, type: type }
  end

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @log = ISIS::Runtime::Log.new(clock: @clock)
    @source = Source.new([row("10.0.12.0/24", 2, scope: 253), row("198.18.7.0/24", 3), row("198.18.8.0/24", 4),
                          row("198.18.9.0/24", 4, type: 6), row("2001:db8:7::/64", 3),
                          row("198.51.100.3/32", 187), row("198.18.10.0/24", 3, table: 100),
                          row("10.0.12.1/32", 2, scope: 254, table: 255, type: 2),
                          row("198.18.12.0/24", 3, scope: 253), row("198.18.13.0/24", 3, type: 7),
                          row("2001:db8:12::/64", 2), row("fe80::/64", 2)], 0)
    @orig = Originator.new([], 0)
  end

  def redistribution(**opts)
    ISIS::Redistribution.new(originator: @orig, scheduler: @scheduler, log: @log, source: @source, interval: 5,
                             **opts)
  end

  def prefixes = @orig.external_prefixes.map { |p| p[:prefix] }

  # Nothing by default, and the source is not even read.
  def test_nothing_by_default
    redistribution.start
    assert_empty @orig.external_prefixes
    assert_equal 0, @source.reads
  end

  # Static: what `ip route add` gives, protocol boot, and protocol static,
  # unicast or blackhole, at either scope, IPv4 or IPv6; not IS-IS's own,
  # not another table's, not unreachable, not connected.
  def test_static
    redistribution(kinds: [:static], metric: 5).start
    assert_equal ["198.18.12.0/24", "198.18.7.0/24", "198.18.8.0/24", "198.18.9.0/24", "2001:db8:7::/64"], prefixes
    assert_equal [5], @orig.external_prefixes.map { |p| p[:metric] }.uniq
  end

  # Connected: the kernel's route of a subnet, IPv4 at link scope and IPv6
  # at universe; not its local table host routes, not IPv6 link-local.
  def test_connected
    redistribution(kinds: ["connected"]).start
    assert_equal ["10.0.12.0/24", "2001:db8:12::/64"], prefixes
  end

  def test_the_external_metric_type
    redistribution(kinds: [:connected], external: true).start
    assert_equal({ prefix: "10.0.12.0/24", metric: 0, external: true }, @orig.external_prefixes.first)
  end

  # Read again every interval: a route removed from the host goes, one
  # added comes; the same rows again hand the originator nothing.
  def test_read_again_every_interval
    redistribution(kinds: [:static]).start
    @source.rows = @source.rows.reject { |r| r[:prefix] == "198.18.7.0/24" } + [row("198.18.11.0/24", 4)]
    @scheduler.advance(4)
    assert_includes prefixes, "198.18.7.0/24"
    @scheduler.advance(1)
    assert_equal ["198.18.11.0/24", "198.18.12.0/24", "198.18.8.0/24", "198.18.9.0/24", "2001:db8:7::/64"], prefixes
    sets = @orig.sets
    @scheduler.advance(5)
    assert_equal sets, @orig.sets
    # And again: each read schedules the next.
    @source.rows = @source.rows.reject { |r| r[:prefix] == "198.18.11.0/24" }
    @scheduler.advance(5)
    refute_includes prefixes, "198.18.11.0/24"
  end

  # A change of kinds reads at once, and what is no longer taken goes.
  # Each change is logged.
  def test_a_kinds_change_withdraws_at_once
    r = redistribution(kinds: [:connected])
    r.start
    r.kinds = []
    assert_empty @orig.external_prefixes
    changes = @log.events.select { |e| e.kind == :redistribution }.map { |e| [e.data[:prefix], e.data[:change]] }
    assert_equal [["10.0.12.0/24", :added], ["2001:db8:12::/64", :added], ["10.0.12.0/24", :removed],
                  ["2001:db8:12::/64", :removed]], changes
  end

  def test_stop_reads_no_more
    r = redistribution(kinds: [:static])
    r.start
    r.stop
    reads = @source.reads
    @scheduler.advance(20)
    assert_equal reads, @source.reads
  end

  def test_an_unknown_kind_raises
    assert_raises(ArgumentError) { redistribution(kinds: [:ospf]).start }
  end
end
