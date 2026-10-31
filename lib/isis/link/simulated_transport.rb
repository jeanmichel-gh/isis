# frozen_string_literal: true

module ISIS
  module Link
    # An in-memory link for tests and simulations. Frames go out as octets
    # and come back parsed, exactly as on a real wire, but nothing blocks
    # and nothing waits: #receive answers at once, with a frame or nil.
    #
    # A wire behaves like a hub. A frame sent by one transport is delivered
    # to every other transport attached to the same wire, and not echoed
    # back to its sender.
    class SimulatedWire
      def initialize
        @transports = []
      end

      def attach(transport)
        @transports << transport unless @transports.include?(transport)
        self
      end

      def detach(transport)
        @transports.delete(transport)
        self
      end

      def deliver(from, bytes)
        @transports.each { |t| t.enqueue(bytes) unless t.equal?(from) }
      end
    end

    # One end of a SimulatedWire. Same interface as SocketTransport:
    # #send a Datalink::Frame, #receive one back or nil.
    class SimulatedTransport
      attr_reader :wire

      def initialize(wire)
        @wire = wire
        @queue = []
        wire.attach(self)
      end

      def send(frame)
        @wire.deliver(self, frame.encode.b)
        frame
      end

      # The next frame that arrived, or nil when none is waiting. The
      # timeout is accepted for interface compatibility and ignored: a
      # simulated link never waits in real time.
      def receive(timeout: nil)
        bytes = @queue.shift
        bytes && Datalink::Frame.parse(bytes)
      end

      # Number of frames waiting to be received.
      def pending
        @queue.size
      end

      def close
        @wire.detach(self)
        @queue.clear
      end

      # Called by the wire. Not part of the transport interface.
      def enqueue(bytes)
        @queue << bytes
      end
    end
  end
end
