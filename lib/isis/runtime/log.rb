# frozen_string_literal: true

module ISIS
  module Runtime
    # Where every mechanism reports what it did and why. CLAUDE.md, "Logging
    # and events", after ospfv2's design.
    #
    # Three outputs, each optional:
    #
    # * the logger, a callable ->(level, message), gets every line;
    # * the event list keeps every line above debug, bounded, with its kind,
    #   circuit and data, so a test or a viewer can read what happened
    #   without parsing text, and listeners hear each event as it is kept;
    # * the tracer, a callable ->(direction, circuit, pdu, peer), gets each
    #   PDU sent or received.
    #
    # With none installed, nothing is written and nothing breaks. Logging is
    # observation: nothing here may change what the protocol does.
    class Log
      LEVELS = %i[debug info warn error].freeze
      MAX_EVENTS = 1000

      Event = Struct.new(:time, :level, :circuit, :kind, :message, :data) do
        def to_s
          [time.utc.strftime("%FT%T.%LZ"), level.to_s.ljust(5), circuit, message].compact.join(" ")
        end
      end

      attr_reader :events
      attr_accessor :logger, :tracer

      # +clock+ gives the wall time on events, so a simulated run keeps
      # simulated times.
      def initialize(clock:, logger: nil, tracer: nil, max_events: MAX_EVENTS)
        @clock = clock
        @logger = logger
        @tracer = tracer
        @max_events = max_events
        @events = []
        @listeners = []
      end

      # Log +message+ at +level+. Above debug it is also kept as an event of
      # +kind+, with +circuit+ and +data+.
      def log(level, message, circuit: nil, kind: :log, **data)
        raise ArgumentError, "no log level #{level.inspect}" unless LEVELS.include?(level)

        @logger&.call(level, circuit ? "#{circuit} #{message}" : message)
        return nil if level == :debug

        event = Event.new(@clock.wall, level, circuit, kind, message, data)
        @events << event
        @events.shift(@events.size - @max_events) if @events.size > @max_events
        @listeners.each { |l| l.call(event) }
        event
      end

      LEVELS.each do |level|
        define_method(level) { |message, **opts| log(level, message, **opts) }
      end

      # Hand one PDU to the tracer. +direction+ is :sent or :received.
      def trace(direction, circuit, pdu, peer = nil)
        @tracer&.call(direction, circuit, pdu, peer)
      end

      # Call the block with each event as it is kept.
      def on_event(&block)
        @listeners << block
        block
      end

      # A logger for an executable: "TIME LEVEL message" lines on +io+, wall
      # time from +clock+, debug lines only when +debug+ is true.
      def self.writer(io, clock:, debug: false)
        lambda do |level, message|
          next if level == :debug && !debug

          io.puts "#{clock.wall.utc.strftime('%FT%T.%LZ')} #{level.to_s.ljust(5)} #{message}"
        end
      end

      # A tracer for an executable: one line per PDU with its to_s, and with
      # +debug+ its hex as well, which is what makes a trace line usable as
      # a test fixture.
      def self.trace_writer(io, clock:, debug: false)
        lambda do |direction, circuit, pdu, peer|
          arrow = direction == :sent ? ">" : "<"
          line = "#{clock.wall.utc.strftime('%FT%T.%LZ')} #{circuit} #{arrow} #{pdu}"
          line += " #{peer}" if peer
          io.puts line
          io.puts "  #{pdu.to_shex}" if debug
        end
      end
    end
  end
end
