# frozen_string_literal: true

module ISIS
  module Runtime
    # Protocol time. Every holding time, lifetime and interval in isis4r is
    # measured against one of these, never against the system clock
    # directly, so a test can run protocol time without real waiting.
    #
    # A clock answers #now: seconds as a Float, monotonic, with an origin
    # that means nothing. Only differences between two readings are
    # meaningful. Wall clock time is for logs and never comes from here.

    # The real clock: the operating system's monotonic clock.
    #
    # This file is the one place in lib/isis/ allowed to read the system
    # clock. The source scan in test/unit/runtime/time_guard_test.rb holds
    # it to that.
    class MonotonicClock
      def now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end

    # A clock that moves only when told to. Tests and simulations use it,
    # usually through Scheduler#run_until, which advances it timer by timer.
    class ManualClock
      def initialize(start = 0.0)
        @now = Float(start)
      end

      def now
        @now
      end

      # Move forward by +seconds+. A monotonic clock cannot go back, so a
      # negative step is refused rather than applied.
      def advance(seconds)
        seconds = Float(seconds)
        raise ArgumentError, "a monotonic clock cannot go back (#{seconds})" if seconds.negative?

        @now += seconds
      end

      # Move to an absolute reading, which must not be earlier than now.
      def set(time)
        time = Float(time)
        raise ArgumentError, "a monotonic clock cannot go back (#{time} < #{@now})" if time < @now

        @now = time
      end
    end
  end
end
