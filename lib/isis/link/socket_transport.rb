# frozen_string_literal: true

module ISIS
  module Link
    # A real link: an open Datalink::Socket, on any backend datalink-socket
    # provides (a raw interface, BPF, or its loopback wire).
    #
    # This is the edge where blocking is allowed. #receive may wait up to
    # +timeout+ seconds for a frame, because that is what a socket does.
    # Protocol code above it never waits itself.
    class SocketTransport
      attr_reader :socket

      def initialize(socket)
        @socket = socket
      end

      def send(frame)
        @socket.send(frame)
        frame
      end

      # The next frame, or nil if none arrived within +timeout+ seconds.
      # With no timeout, the socket's own recv_timeout applies.
      def receive(timeout: nil)
        @socket.recv_timeout = timeout unless timeout.nil?
        @socket.recv.frame
      rescue Datalink::TimeoutError
        nil
      end

      def close
        @socket.close
      end
    end
  end
end
