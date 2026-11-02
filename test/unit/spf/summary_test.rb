# frozen_string_literal: true

require_relative "../../test_helper"

# Spf::Summary, RFC 1195 section 3.2, against a stand-in Level 2
# originator that keeps what it is handed.
class TestSpfSummary < Minitest::Test
  Originator = Struct.new(:area_prefixes, :sets) do
    def area_prefixes=(list)
      self.sets += 1
      self[:area_prefixes] = list
    end
  end

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @log = ISIS::Runtime::Log.new(clock: @clock)
    @orig = Originator.new([], 0)
    adj = ISIS::Spf::Adjacency.new(circuit: "eth-b", neighbor: "\x00\x00\x00\x00\x00\x0b".b, circuit_id: 1,
                                   address: "10.0.0.11")
    route = ->(prefix, metric, *flags) { ISIS::Spf::Route.new(prefix, metric, [adj], *flags) }
    @routes = {
      "198.51.100.1/32" => route.call("198.51.100.1/32", 20),
      "198.51.100.2/32" => route.call("198.51.100.2/32", 15),
      "198.18.5.0/24" => route.call("198.18.5.0/24", 30, true),
      "203.0.113.0/24" => route.call("203.0.113.0/24", 40, nil, true),
      "0.0.0.0/0" => route.call("0.0.0.0/0", 10),
      "2001:db8:1::/64" => route.call("2001:db8:1::/64", 25),
      "192.0.2.1/32" => ISIS::Spf::Route.new("192.0.2.1/32", 5, [])
    }
  end

  def summary(list = [])
    ISIS::Spf::Summary.new(originator: @orig, log: @log, summaries: list)
  end

  def prefixes = @orig.area_prefixes.map { |p| p[:prefix] }

  # With no summaries, each Level 1 route goes at its own metric, the
  # external one marked; not the up/down one (RFC 5302 section 4), not
  # this system's own, and not the default route toward an attached system.
  def test_the_area_as_it_is
    summary.update(@routes)
    assert_equal [{ prefix: "198.18.5.0/24", metric: 30, external: true },
                  { prefix: "198.51.100.1/32", metric: 20 }, { prefix: "198.51.100.2/32", metric: 15 },
                  { prefix: "2001:db8:1::/64", metric: 25 }], @orig.area_prefixes
  end

  # A summary goes in place of what it covers, at its configured metric,
  # whatever theirs (section 3.2: "metric values are not considered").
  def test_a_summary_replaces_what_it_covers
    summary([{ prefix: "198.51.100.0/24", metric: 50 }]).update(@routes)
    assert_equal ["198.18.5.0/24", "198.51.100.0/24", "2001:db8:1::/64"], prefixes
    assert_equal 50, @orig.area_prefixes.find { |p| p[:prefix] == "198.51.100.0/24" }[:metric]
  end

  # With no metric configured, the lowest of those it covers, our choice.
  def test_a_summary_without_a_metric_takes_the_lowest
    summary([{ prefix: "198.51.100.0/24" }]).update(@routes)
    assert_equal 15, @orig.area_prefixes.find { |p| p[:prefix] == "198.51.100.0/24" }[:metric]
  end

  # Announced only "if they correspond to at least one address which is
  # reachable in the area". This system's own prefix counts toward that,
  # though it is not announced itself; an up/down route does not.
  def test_a_summary_needs_a_reachable_address
    summary([{ prefix: "192.0.2.0/24", metric: 5 }, { prefix: "203.0.113.0/23", metric: 5 },
             { prefix: "10.99.0.0/16", metric: 5 }]).update(@routes)
    assert_includes prefixes, "192.0.2.0/24"
    refute_includes prefixes, "203.0.113.0/23"
    refute_includes prefixes, "10.99.0.0/16"
  end

  # A summary longer than a route does not cover it.
  def test_a_longer_summary_covers_nothing_shorter
    summary([{ prefix: "198.18.5.0/25", metric: 5 }]).update(@routes)
    assert_includes prefixes, "198.18.5.0/24"
    refute_includes prefixes, "198.18.5.0/25"
  end

  # New summaries choose again from the last routes at once: the /24 goes
  # and its two /32s come back. Each change is logged.
  def test_a_summary_change_withdraws_and_restores
    s = summary([{ prefix: "198.51.100.0/24", metric: 50 }])
    s.update(@routes)
    s.summaries = []
    assert_includes prefixes, "198.51.100.1/32"
    refute_includes prefixes, "198.51.100.0/24"
    removed = @log.events.select { |e| e.kind == :summary && e.data[:change] == :removed }.map { |e| e.data[:prefix] }
    assert_equal ["198.51.100.0/24"], removed
  end

  # The same routes again hand the originator nothing.
  def test_only_a_change_reaches_the_originator
    s = summary
    s.update(@routes)
    s.update(@routes)
    assert_equal 1, @orig.sets
  end
end
