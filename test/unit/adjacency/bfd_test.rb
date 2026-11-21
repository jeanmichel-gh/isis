# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/fake_bfd"

# The Bfd mechanism between the circuits and bfdd4r: who wants which
# session, and who hears what, with a FakeBfd in place of BFD::Client.
class TestBfd < Minitest::Test
  # A circuit as Bfd sees one: a name, and what it is told.
  class Holder
    attr_reader :name, :told, :running

    def initialize(name)
      @name = name
      @told = []
      @running = 0
    end

    def bfd_changed(event) = @told << event
    def bfd_running_changed = @running += 1
  end

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock))
    @fake = FakeBfd.new
    @bfd = ISIS::Bfd.new(client: @fake, log: @log)
    @l1 = Holder.new("eth1-l1")
    @l2 = Holder.new("eth1-l2")
    [@l1, @l2].each { |h| @bfd.attach(h) }
  end

  def test_running_is_the_clients_connected
    assert @bfd.running?
    @fake.lose
    refute @bfd.running?
  end

  # A LAN at both levels: two circuits want one session, which is asked
  # for once and let go when the last lets go.
  def test_a_session_two_circuits_want
    @bfd.want(@l1, interface: "eth1", peer: "10.0.0.2", local: "10.0.0.1")
    @bfd.want(@l2, interface: "eth1", peer: "10.0.0.2", local: "10.0.0.1")
    assert_equal [[:want, "eth1", "10.0.0.2", "10.0.0.1"]], @fake.calls
    @bfd.drop(@l1, interface: "eth1", peer: "10.0.0.2")
    assert @fake.wanted?(interface: "eth1", peer: "10.0.0.2")
    @bfd.drop(@l2, interface: "eth1", peer: "10.0.0.2")
    refute @fake.wanted?(interface: "eth1", peer: "10.0.0.2")
  end

  # A session's change goes to the circuits that want it, and is logged at
  # info as an event of kind :bfd.
  def test_state_goes_to_its_holders
    @bfd.want(@l1, interface: "eth1", peer: "10.0.0.2", local: "10.0.0.1")
    @fake.tell("eth1", "10.0.0.2", :up)
    @bfd.poll(@clock.now)
    assert_equal [:up], @l1.told.map(&:state)
    assert_empty @l2.told
    assert_equal :up, @bfd.state(interface: "eth1", peer: "10.0.0.2")
    event = @log.events.find { |e| e.kind == :bfd }
    assert_equal :up, event.data[:to]
  end

  # bfdd4r going or coming tells every circuit, and is logged.
  def test_lost_and_connected_tell_every_circuit
    @fake.lose
    @bfd.poll(@clock.now)
    @fake.connect
    @bfd.poll(@clock.now)
    assert_equal 2, @l1.running
    assert_equal 2, @l2.running
    assert_equal %i[warn info], @log.events.select { |e| e.kind == :bfd }.map(&:level)
  end

  # Closing lets go of every session (BFD::Client#close(release: true)).
  def test_close_releases
    @bfd.close
    assert_includes @fake.calls, [:close, true]
  end
end

# FakeBfd stands in for bfd4r's BFD::Client in every BFD test here, so
# it must answer what the real one answers: the same methods, the same
# event fields, and failure? only for Up gone Down.
class TestFakeBfdIsBfdClient < Minitest::Test
  require "bfd/client"
  require_relative "../../support/fake_bfd"

  def test_same_methods
    %i[want drop wanted? state connected? poll close].each do |m|
      assert BFD::Client.method_defined?(m), "BFD::Client has no #{m}"
      assert FakeBfd.method_defined?(m), "FakeBfd has no #{m}"
    end
    assert_equal BFD::Client.instance_method(:want).parameters.map(&:last),
                 FakeBfd.instance_method(:want).parameters.map(&:last).map { _1 == :_timers ? :timers : _1 }
  end

  def test_same_events
    assert_equal BFD::Client::Event.members, FakeBfd::Event.members
    [[:up, :down, true], [:up, :admin_down, false], [:init, :down, false], [nil, :up, false]].each do |from, to, failure|
      real = BFD::Client::Event.new(type: :state, from: from, state: to)
      fake = FakeBfd::Event.new(type: :state, from: from, state: to)
      assert_equal failure, real.failure?, "#{from} -> #{to}"
      assert_equal real.failure?, fake.failure?
      assert_equal real.up?, fake.up?
    end
  end

  # The real client, with no bfdd4r on its socket: not connected, :lost
  # once, which is what the circuits take as BFD not running.
  def test_real_client_without_bfdd4r
    client = BFD::Client.new("isisd", socket: "@isis4r-test-no-bfdd4r-#{Process.pid}")
    events = client.poll(0.0)
    refute client.connected?
    assert_equal [:lost], events.map(&:type)
    assert_empty client.poll(0.5)
  end
end
