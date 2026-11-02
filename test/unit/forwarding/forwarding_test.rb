# frozen_string_literal: true

require_relative "../../test_helper"

# Forwarding.operations turns two route tables into route operations.
class TestForwardingOperations < Minitest::Test
  def adjacency(address)
    ISIS::Spf::Adjacency.new(circuit: "eth0", neighbor: "\x00\x00\x00\x00\x00\x02".b, circuit_id: 1,
                             address: address)
  end

  def route(prefix, metric, *addresses)
    ISIS::Spf::Route.new(prefix, metric, addresses.map { |a| adjacency(a) })
  end

  def kinds(before, after)
    ISIS::Forwarding.operations(before, after, level: 2).map { |o| [o.kind, o.route.prefix, o.level] }
  end

  def test_a_new_route_is_an_install
    assert_equal [[:install, "192.0.2.2/32", 2]], kinds({}, { "192.0.2.2/32" => route("192.0.2.2/32", 11, "10.0.0.2") })
  end

  def test_a_gone_route_is_a_withdrawal
    assert_equal [[:withdraw, "192.0.2.2/32", 2]], kinds({ "192.0.2.2/32" => route("192.0.2.2/32", 11, "10.0.0.2") }, {})
  end

  def test_a_new_metric_or_next_hop_is_a_replace
    old = { "p" => route("192.0.2.2/32", 11, "10.0.0.2") }
    assert_equal [[:replace, "192.0.2.2/32", 2]], kinds(old, { "p" => route("192.0.2.2/32", 12, "10.0.0.2") })
    assert_equal [[:replace, "192.0.2.2/32", 2]], kinds(old, { "p" => route("192.0.2.2/32", 11, "10.0.0.3") })
  end

  def test_the_same_route_is_nothing
    assert_empty kinds({ "p" => route("192.0.2.2/32", 11, "10.0.0.2") }, { "p" => route("192.0.2.2/32", 11, "10.0.0.2") })
  end

  # A route this system advertises itself has no next hop and is no
  # forwarding entry, so it counts as absent either way.
  def test_a_local_route_counts_as_absent
    assert_empty kinds({}, { "p" => route("192.0.2.1/32", 1) })
    assert_equal [[:withdraw, "192.0.2.2/32", 2]],
                 kinds({ "p" => route("192.0.2.2/32", 11, "10.0.0.2") }, { "p" => route("192.0.2.2/32", 1) })
    assert_equal [[:install, "192.0.2.2/32", 2]],
                 kinds({ "p" => route("192.0.2.2/32", 1) }, { "p" => route("192.0.2.2/32", 11, "10.0.0.2") })
  end

  def test_operations_come_in_prefix_order
    after = { "b" => route("b", 1, "10.0.0.2"), "a" => route("a", 1, "10.0.0.2") }
    assert_equal %w[a b], ISIS::Forwarding.operations({}, after).map { |o| o.route.prefix }
  end
end
