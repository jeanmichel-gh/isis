# frozen_string_literal: true

require_relative "../../test_helper"

# The two GenerationTimers on their own, with times as plain numbers:
# RFC 1142's fixed hold (7.3.21, per LSP 7.3.4) and the backoff of
# docs/design/lsp-generation.md.
class TestGenerationTimer < Minitest::Test
  Fixed = ISIS::GenerationTimer::Fixed
  Backoff = ISIS::GenerationTimer::Backoff

  def test_fixed_waits_the_minimum_from_any_generation
    t = Fixed.new(30)
    assert_equal 0, t.wait(0, now: 100)
    t.generated(0, now: 100, event: false)
    assert_equal 28, t.wait(0, now: 102)
    t.generated(0, now: 500, event: false)
    assert_equal 30, t.wait(0, now: 500)
    assert_operator t.wait(0, now: 530), :<=, 0
  end

  def test_fixed_holds_each_lsp_number_on_its_own
    t = Fixed.new(30)
    t.generated(0, now: 10)
    assert_equal 0, t.wait(1, now: 12)
    assert_equal 28, t.wait(0, now: 12)
  end

  def test_backoff_first_change_after_quiet_waits_initial
    assert_equal 0, Backoff.new.wait(0, now: 5, since: 5)
    t = Backoff.new(initial: 0.05)
    assert_in_delta 0.05, t.wait(0, now: 5, since: 5)
    # Asked again when that wait is over, it is over: the round started at 5.
    assert_in_delta 0, t.wait(0, now: 5.05, since: 5)
  end

  # 1, 2, 4, 8, 16 then 30, the maximum, and back to the start after more
  # than 30 s with no change.
  def test_backoff_doubles_up_to_the_maximum_then_resets
    t = Backoff.new
    now = 0
    t.generated(0, now: now)
    # Each change comes 0.1 s after the last LSP, and waits the rest of
    # the interval.
    gaps = 6.times.map do
      last = now
      now += 0.1 + t.wait(0, now: now + 0.1)
      t.generated(0, now: now)
      (now - last).round(6)
    end
    assert_equal [1, 2, 4, 8, 16, 30], gaps
    assert_in_delta 30, t.interval(0)
    assert_equal 0, t.wait(0, now: now + 30.5, since: now + 30.5)
    t.generated(0, now: now + 30.5)
    assert_equal 1, t.interval(0)
  end

  def test_backoff_ignores_the_start_and_refreshes
    t = Backoff.new
    t.generated(0, now: 0, event: false)
    assert_equal 0, t.wait(0, now: 2, since: 2)
    t.generated(0, now: 2)
    t.generated(0, now: 2.5, event: false)
    assert_in_delta 0.5, t.wait(0, now: 2.5, since: 2.5)
  end

  def test_backoff_holds_each_lsp_number_on_its_own
    t = Backoff.new
    t.generated(0, now: 10)
    assert_equal 0, t.wait(1, now: 10.5, since: 10.5)
    assert_in_delta 0.5, t.wait(0, now: 10.5, since: 10.5)
  end

  def test_backoff_refuses_bad_settings
    assert_raises(ArgumentError) { Backoff.new(initial: -1) }
    assert_raises(ArgumentError) { Backoff.new(secondary: "1") }
    assert_raises(ArgumentError) { Backoff.new(secondary: 40, maximum: 30) }
  end

  def test_build
    assert_instance_of Fixed, ISIS::GenerationTimer.build(minimum: 30)
    b = ISIS::GenerationTimer.build(minimum: 30, backoff: { initial: 0, secondary: 2, maximum: 10 })
    assert_equal [0, 2, 10], [b.initial, b.secondary, b.maximum]
  end
end
