# frozen_string_literal: true

require_relative "../../test_helper"

class TestManualClock < Minitest::Test
  def test_starts_where_told
    assert_equal 0.0, ISIS::Runtime::ManualClock.new.now
    assert_equal 5.0, ISIS::Runtime::ManualClock.new(5).now
  end

  def test_advance_moves_forward
    clock = ISIS::Runtime::ManualClock.new
    clock.advance(1.5)
    clock.advance(2)
    assert_equal 3.5, clock.now
  end

  def test_cannot_go_back
    clock = ISIS::Runtime::ManualClock.new(10)
    assert_raises(ArgumentError) { clock.advance(-1) }
    assert_raises(ArgumentError) { clock.set(9) }
    assert_equal 10.0, clock.now
  end

  def test_set_to_same_or_later
    clock = ISIS::Runtime::ManualClock.new(10)
    clock.set(10)
    clock.set(12)
    assert_equal 12.0, clock.now
  end
end

class TestMonotonicClock < Minitest::Test
  def test_never_goes_back
    clock = ISIS::Runtime::MonotonicClock.new
    readings = Array.new(100) { clock.now }
    assert_equal readings.sort, readings
    assert_kind_of Float, readings.first
  end
end
