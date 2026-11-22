# frozen_string_literal: true

module ISIS
  # How long a change to this system's own LSP waits before it is
  # generated again, per LSP Number. Originator asks it; a test can
  # replace it on one Originator (CLAUDE.md, "Autonomous operation and
  # testing controls"). docs/design/lsp-generation.md is the design.
  #
  # Two kinds, each answering the same two calls:
  #
  # * wait(number, now:, since:): seconds before a change to LSP Number
  #   +number+ may go out. +since+ is when the first change of this round
  #   arrived. Zero or less is now.
  # * generated(number, now:, event:): LSP Number +number+ went out.
  #   +event+ is true for a change (RFC 1142 7.3.6), false for the start,
  #   a refresh (7.3.5) or a newer copy of our own (7.3.16).
  module GenerationTimer
    # RFC 1142's hold: "A source Intermediate system shall wait at least
    # this long before re-generating one of its own Link State PDUs"
    # (7.3.21), which applies "to each LSP individually" (7.3.4). Every
    # generation counts, the start and refreshes too, as FRR 10.7.1 does.
    class Fixed
      attr_reader :minimum

      def initialize(minimum)
        @minimum = minimum
        @last = {}
      end

      def wait(number, now:, since: nil)
        last = @last[number] or return 0
        last + @minimum - now
      end

      def generated(number, now:, event: true)
        @last[number] = now
      end

      def to_h = { mode: "fixed", minimum: @minimum }
    end

    # A backoff, the shape RFC 9681 section 3 describes; RFC 1142 has
    # none, and the doubling is our choice. The first change after a quiet
    # time waits +initial+. The next waits +secondary+ from the last one,
    # and each after that twice the one before, up to +maximum+. More
    # than +maximum+ with no change is quiet again. Only changes count: a
    # refresh or the start opens no wait.
    class Backoff
      DEFAULTS = { initial: 0, secondary: 1, maximum: 30 }.freeze

      attr_reader :initial, :secondary, :maximum

      def initialize(initial: DEFAULTS[:initial], secondary: DEFAULTS[:secondary], maximum: DEFAULTS[:maximum])
        [[:initial, initial], [:secondary, secondary], [:maximum, maximum]].each do |name, v|
          raise ArgumentError, "lsp_generation: #{name} is a number of seconds, not #{v.inspect}" unless v.is_a?(Numeric) && v >= 0
        end
        raise ArgumentError, "lsp_generation: secondary is above maximum" if secondary > maximum

        @initial = initial
        @secondary = secondary
        @maximum = maximum
        @last = {}
        @interval = {}
      end

      def wait(number, now:, since: now)
        return since + @initial - now if quiet?(number, now)

        @last[number] + @interval[number] - now
      end

      def generated(number, now:, event: true)
        return unless event

        @interval[number] = quiet?(number, now) ? @secondary : [@interval[number] * 2, @maximum].min
        @last[number] = now
      end

      # The wait the next change would get, for a viewer.
      def interval(number) = @interval[number]

      def to_h = { mode: "backoff", initial: @initial, secondary: @secondary, maximum: @maximum }

      private

      def quiet?(number, now)
        @last[number].nil? || now - @last[number] > @maximum
      end
    end

    # The timer a configuration asks for: lsp_generation, a map of
    # initial, secondary and maximum, turns the backoff on; otherwise the
    # fixed hold of +minimum+ seconds.
    def self.build(minimum:, backoff: nil)
      backoff ? Backoff.new(**backoff) : Fixed.new(minimum)
    end
  end
end
