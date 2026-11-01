# frozen_string_literal: true

require_relative "../../test_helper"

class TestSimulatedTransport < Minitest::Test
  def setup
    @wire = ISIS::Link::SimulatedWire.new
    @a = ISIS::Link::SimulatedTransport.new(@wire)
    @b = ISIS::Link::SimulatedTransport.new(@wire)
  end

  def frame(n)
    Datalink::Frame.ieee_802_3(dst: "01:80:c2:00:00:14", src: "00:00:00:00:00:01",
                               payload: "\xFE\xFE\x03".b + [n].pack("C"))
  end

  def test_delivers_octets_to_the_other_end
    sent = frame(1)
    @a.send(sent)
    got = @b.receive
    assert_equal sent.encode.unpack1("H*"), got.encode.unpack1("H*")
  end

  def test_does_not_echo_to_the_sender
    @a.send(frame(1))
    assert_nil @a.receive
  end

  def test_empty_receive_answers_nil_at_once
    assert_nil @b.receive(timeout: 60)
  end

  def test_order_is_kept
    3.times { |i| @a.send(frame(i)) }
    assert_equal [0, 1, 2], Array.new(3) { @b.receive.payload.getbyte(3) }
  end

  def test_hub_delivers_to_every_other_end
    c = ISIS::Link::SimulatedTransport.new(@wire)
    @a.send(frame(7))
    assert_equal 1, @b.pending
    assert_equal 1, c.pending
    assert_equal 0, @a.pending
  end

  def test_closed_end_receives_nothing
    @b.close
    @a.send(frame(1))
    assert_nil @b.receive
  end
end
