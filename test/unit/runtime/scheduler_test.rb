# frozen_string_literal: true

require_relative "../../test_helper"

class TestScheduler < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @sched = ISIS::Runtime::Scheduler.new(@clock)
    @log = []
  end

  def test_nothing_runs_before_due
    @sched.after(5) { @log << :a }
    assert_equal 0, @sched.run_due
    assert_empty @log
  end

  def test_runs_in_due_order_and_sees_its_own_time
    @sched.after(3) { @log << [:c, @clock.now] }
    @sched.after(1) { @log << [:a, @clock.now] }
    @sched.after(2) { @log << [:b, @clock.now] }
    assert_equal 3, @sched.run_until(10)
    assert_equal [[:a, 1.0], [:b, 2.0], [:c, 3.0]], @log
    assert_equal 10.0, @clock.now
  end

  def test_same_due_time_runs_in_scheduling_order
    @sched.at(4) { @log << :first }
    @sched.at(4) { @log << :second }
    @sched.run_until(4)
    assert_equal %i[first second], @log
  end

  def test_cancelled_timer_does_not_run
    timer = @sched.after(1) { @log << :a }
    timer.cancel
    @sched.run_until(2)
    assert_empty @log
    assert_equal 0, @sched.pending_count
  end

  def test_callback_can_reschedule_inside_the_window
    tick = lambda do
      @log << @clock.now
      @sched.after(1, &tick) if @log.size < 5
    end
    @sched.after(1, &tick)
    @sched.run_until(3.5)
    assert_equal [1.0, 2.0, 3.0], @log
    assert_equal 4.0, @sched.next_due
  end

  def test_run_due_uses_the_clock_as_it_stands
    @sched.at(1) { @log << :a }
    @sched.at(2) { @log << :b }
    @clock.set(1.5)
    assert_equal 1, @sched.run_due
    assert_equal [:a], @log
    assert_equal 1.5, @clock.now, "run_due never moves the clock"
  end

  def test_advance_is_relative
    @clock.set(10)
    @sched.after(2) { @log << @clock.now }
    @sched.advance(5)
    assert_equal [12.0], @log
    assert_equal 15.0, @clock.now
  end

  def test_refuses_negative_delay_and_missing_block
    assert_raises(ArgumentError) { @sched.after(-1) { nil } }
    assert_raises(ArgumentError) { @sched.after(1) }
  end
end
