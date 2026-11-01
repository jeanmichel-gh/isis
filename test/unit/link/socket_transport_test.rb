# frozen_string_literal: true

require_relative "../../test_helper"

# The real transport over datalink-socket's loopback backend, which needs
# no privileges. This is the one test file that may wait in real time, and
# only for the short receive timeout below.
class TestSocketTransport < Minitest::Test
  def setup
    wire = Datalink::Backends::Loopback::Wire.new
    @a = ISIS::Link::SocketTransport.new(socket(wire))
    @b = ISIS::Link::SocketTransport.new(socket(wire))
  end

  def teardown
    @a.close
    @b.close
  end

  def socket(wire)
    Datalink::Socket.new("t", backend: :loopback, wire: wire, recv_timeout: 0.05).open
  end

  def test_send_and_receive_a_frame
    sent = Datalink::Frame.ieee_802_3(dst: "01:80:c2:00:00:14", src: "00:00:00:00:00:01",
                                      payload: "\xFE\xFE\x03\x83".b)
    @a.send(sent)
    got = @b.receive(timeout: 0.05)
    assert_equal sent.encode.unpack1("H*"), got.encode.unpack1("H*")
  end

  def test_receive_answers_nil_on_timeout
    assert_nil @b.receive(timeout: 0.01)
  end

  # An interface that goes down: the system calls fail with ENETDOWN, and
  # the transport answers as a silent link, counting what it absorbed.
  def test_a_link_that_is_down_is_silent
    down = Object.new
    down.define_singleton_method(:recv_timeout=) { |_| nil }
    down.define_singleton_method(:recv) { raise Errno::ENETDOWN }
    down.define_singleton_method(:send) { |_| raise Errno::ENETDOWN }
    t = ISIS::Link::SocketTransport.new(down)
    assert_nil t.receive(timeout: 0.01)
    assert_nil t.send("frame")
    assert_equal({ "Errno::ENETDOWN" => 2 }, t.errors)
  end
end
