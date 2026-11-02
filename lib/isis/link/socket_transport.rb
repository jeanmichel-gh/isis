# frozen_string_literal: true

module ISIS
  module Link
    # A real link: an open Datalink::Socket, on any backend datalink-socket
    # provides (a raw interface, BPF, or its loopback wire).
    #
    # This is the edge where blocking is allowed. #receive may wait up to
    # +timeout+ seconds for a frame, because that is what a socket does.
    # Protocol code above it never waits itself.
    #
    # An interface that goes down is a link that carries nothing, not a
    # failure of the program: the system calls fail with ENETDOWN or
    # ENXIO, and both directions then answer as a silent link would. A
    # frame sent is lost and receive answers nil, so the adjacency goes
    # down when its holding timer expires, as for any silent neighbour.
    # +errors+ counts what was absorbed, by Errno class name.
    class SocketTransport
      # What a link that is down, or gone, answers.
      LINK_DOWN = [Errno::ENETDOWN, Errno::ENXIO, Errno::ENODEV].freeze

      attr_reader :socket, :errors

      def initialize(socket)
        @socket = socket
        @errors = Hash.new(0)
      end

      # The frame, or nil when the link is down and it was lost.
      def send(frame)
        @socket.send(frame)
        frame
      rescue *LINK_DOWN => e
        @errors[e.class.name] += 1
        nil
      end

      # The next frame, or nil if none arrived within +timeout+ seconds or
      # the link is down. With no timeout, the socket's own recv_timeout
      # applies. A link that is down answers at once, so a caller that polls
      # waits for its own timer, not for the socket.
      def receive(timeout: nil)
        @socket.recv_timeout = timeout unless timeout.nil?
        @socket.recv.frame
      rescue Datalink::TimeoutError
        nil
      rescue *LINK_DOWN => e
        @errors[e.class.name] += 1
        nil
      end

      def close
        @socket.close
      end
    end
  end
end
