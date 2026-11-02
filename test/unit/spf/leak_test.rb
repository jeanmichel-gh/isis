# frozen_string_literal: true

require_relative "../../test_helper"

# Spf::Leak, against a stand-in Level 1 originator that keeps what it is
# handed.
class TestSpfLeak < Minitest::Test
  Originator = Struct.new(:leaked_prefixes, :sets) do
    def leaked_prefixes=(list)
      self.sets = (sets || 0) + 1
      self[:leaked_prefixes] = list
    end
  end

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @log = ISIS::Runtime::Log.new(clock: @clock)
    @orig = Originator.new([], 0)
    adj = ISIS::Spf::Adjacency.new(circuit: "eth-b", neighbor: "\x00\x00\x00\x00\x00\x0b".b, circuit_id: 1,
                                   address: "10.0.0.11")
    @routes = {
      "198.51.100.3/32" => ISIS::Spf::Route.new("198.51.100.3/32", 20, [adj]),
      "203.0.113.0/24" => ISIS::Spf::Route.new("203.0.113.0/24", 30, [adj], true),
      "2001:db8:3::/64" => ISIS::Spf::Route.new("2001:db8:3::/64", 25, [adj]),
      "192.0.2.1/32" => ISIS::Spf::Route.new("192.0.2.1/32", 5, [])
    }
  end

  def leak(policy = ISIS::Spf::Leak::NONE)
    ISIS::Spf::Leak.new(originator: @orig, log: @log, policy: policy)
  end

  # RFC 5302 section 4: "it is RECOMMENDED that L2 routes not be advertised
  # into L1 by default".
  def test_nothing_is_leaked_by_default
    l = leak
    l.update(@routes)
    assert_empty @orig.leaked_prefixes
    assert_equal 0, @orig.sets
  end

  # A covering prefix leaks what lies within it, of its family; the
  # external flag goes with the route.
  def test_a_prefix_policy_leaks_what_it_covers
    leak(ISIS::Spf::Leak.prefixes(%w[198.51.100.0/24 203.0.113.0/24 2001:db8::/32])).update(@routes)
    assert_equal [{ prefix: "198.51.100.3/32", metric: 20 }, { prefix: "2001:db8:3::/64", metric: 25 },
                  { prefix: "203.0.113.0/24", metric: 30, external: true }], @orig.leaked_prefixes
  end

  # A covering prefix longer than the route's does not cover it, and an
  # IPv4 one covers no IPv6 route.
  def test_coverage_needs_family_and_length
    policy = ISIS::Spf::Leak.prefixes(%w[203.0.113.0/25 0.0.0.0/0])
    assert policy.call(@routes["198.51.100.3/32"])
    refute ISIS::Spf::Leak.prefixes(%w[203.0.113.0/25]).call(@routes["203.0.113.0/24"])
    refute ISIS::Spf::Leak.prefixes(%w[0.0.0.0/0]).call(@routes["2001:db8:3::/64"])
  end

  # A route this system advertises itself is not leaked, whatever the
  # policy.
  def test_a_local_route_is_not_leaked
    leak(->(_r) { true }).update(@routes)
    refute_includes @orig.leaked_prefixes.map { |p| p[:prefix] }, "192.0.2.1/32"
  end

  # A new policy chooses again from the last routes at once, and what it
  # no longer allows is withdrawn. Each change is logged.
  def test_a_policy_change_withdraws
    l = leak(ISIS::Spf::Leak.prefixes(%w[198.51.100.0/24]))
    l.update(@routes)
    l.policy = ISIS::Spf::Leak::NONE
    assert_empty @orig.leaked_prefixes
    changes = @log.events.select { |e| e.kind == :leak }.map { |e| [e.data[:prefix], e.data[:change]] }
    assert_equal [["198.51.100.3/32", :added], ["198.51.100.3/32", :removed]], changes
  end

  # The same routes again hand the originator nothing; a new metric does,
  # and is logged as a change.
  def test_only_a_change_reaches_the_originator
    l = leak(ISIS::Spf::Leak.prefixes(%w[198.51.100.0/24]))
    l.update(@routes)
    l.update(@routes)
    assert_equal 1, @orig.sets
    @routes["198.51.100.3/32"] = ISIS::Spf::Route.new("198.51.100.3/32", 40, @routes["198.51.100.3/32"].adjacencies)
    l.update(@routes)
    assert_equal [{ prefix: "198.51.100.3/32", metric: 40 }], @orig.leaked_prefixes
    assert_equal :changed, @log.events.last.data[:change]
  end
end
