# frozen_string_literal: true

require_relative "../../test_helper"

class TestAdjacencyTiming < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new(100)
    @adj = ISIS::Adjacency.new(system_id: ISIS::SystemId.new("0000.0000.0002"),
                               snpa: Datalink::MAC.new("00:00:00:00:00:02"),
                               state: :init, holding_time: 10, clock: @clock)
  end

  def test_last_seen_comes_from_the_clock
    assert_equal 100.0, @adj.last_seen
  end

  def test_not_expired_at_the_holding_time
    @clock.advance(10)
    refute @adj.expired?
  end

  def test_expired_past_the_holding_time
    @clock.advance(10.5)
    assert @adj.expired?
  end

  def test_touch_restarts_the_holding_time
    @clock.advance(8)
    @adj.touch
    @clock.advance(8)
    refute @adj.expired?
  end
end
