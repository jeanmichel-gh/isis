# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"
require "tmpdir"

# The API over a real Unix socket in a temporary directory, polled by hand
# as the daemon's loop polls it, against a Router on a simulated wire.
class TestDaemonApi < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @log = ISIS::Runtime::Log.new(clock: @clock)
    wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    @router = ISIS::Router.new({ system_id: "0000.0000.000a", hostname: "a", level: "1-2", area_key: "secret",
                                 interfaces: [{ name: "x" }] },
                               clock: @clock, scheduler: @scheduler, log: @log,
                               host: SimHost.new(wires, { "x" => "00:00:00:00:00:0a" }))
    @dir = Dir.mktmpdir
    @api = ISIS::Daemon::Api.new(@router, path: File.join(@dir, "run", "isisd.sock"), keepalive: 15).start
  end

  def teardown
    @api.stop
    FileUtils.remove_entry(@dir)
  end

  def connect = UNIXSocket.new(@api.path)

  # Poll until a whole line has arrived on +socket+.
  def line(socket)
    20.times do
      @api.poll
      return JSON.parse(socket.gets) if socket.wait_readable(0.01)
    end
    flunk "no answer"
  end

  def ask(socket, method, params = {})
    socket.write(JSON.generate(id: 7, method: method, params: params) + "\n")
    line(socket)
  end

  def test_socket_is_0660
    assert_equal 0o660, File.stat(@api.path).mode & 0o777
  end

  def test_a_request_and_its_answer
    s = connect
    r = ask(s, "show.overview")
    assert_equal 7, r["id"]
    assert_equal "0000.0000.000a", r.dig("result", "system_id")
    assert_equal "a", r.dig("result", "hostname")
  end

  def test_two_requests_on_one_connection
    s = connect
    assert_equal [1, 2], ask(s, "show.overview").dig("result", "levels")
    assert_equal [], ask(s, "show.adjacencies")["result"]
  end

  def test_unknown_method
    assert_equal "unknown method show.foo", ask(connect, "show.foo")["error"]
  end

  def test_not_json
    s = connect
    s.write("{nope\n")
    assert_match(/\Anot JSON/, line(s)["error"])
  end

  def test_configuration_masks_keys
    assert_equal "********", ask(connect, "show.configuration").dig("result", "area_key")
  end

  def test_api_info_lists_every_method
    info = ask(connect, "api.info")["result"]
    assert_equal (ISIS::Daemon::Api::METHODS.keys + ISIS::Daemon::Api::STREAM_METHODS).sort, info["methods"]
    assert_equal ISIS::VERSION, info["version"]
  end

  def test_policy_leak_and_overload
    assert_equal ["10.0.0.0/8"], ask(connect, "policy.leak", "prefixes" => ["10.0.0.0/8"]).dig("result", "leak")
    refute_same ISIS::Spf::Leak::NONE, @router.leak.policy
    ask(connect, "policy.leak", "prefixes" => [])
    assert_same ISIS::Spf::Leak::NONE, @router.leak.policy
    ask(connect, "policy.overload", "on" => true)
    assert(@router.originators.values.all?(&:overload))
  end

  def test_policy_summaries
    ask(connect, "policy.summaries", "summaries" => [{ "prefix" => "10.0.0.0/8", "metric" => 5 }])
    assert_equal [{ prefix: "10.0.0.0/8", metric: 5 }], @router.summary.summaries
  end

  # Events after the subscription arrive as they are logged; those before
  # it only when asked for with since.
  def test_events_subscribe
    @log.info("before", kind: :test)
    s = connect
    r = ask(s, "events.subscribe")
    assert_equal({ "seq" => 1, "replayed" => 0 }, r["result"])
    @log.info("after", kind: :test)
    e = line(s)["event"]
    assert_equal [2, "after", "test"], e.values_at("seq", "message", "kind")
  end

  def test_events_replay_since
    @log.info("one", kind: :test)
    @log.info("two", kind: :test)
    s = connect
    assert_equal 1, ask(s, "events.subscribe", "since" => 1).dig("result", "replayed")
    assert_equal "two", line(s).dig("event", "message")
  end

  def test_keepalive_on_a_quiet_stream
    s = connect
    ask(s, "events.subscribe")
    @clock.advance(16)
    assert_equal 0, line(s)["keepalive"]
  end

  def test_unsubscribe
    s = connect
    ask(s, "events.subscribe")
    assert_equal({ "unsubscribed" => true }, ask(s, "events.unsubscribe")["result"])
    @log.info("unseen", kind: :test)
    assert_equal "0000.0000.000a", ask(s, "show.overview").dig("result", "system_id")
  end

  def test_a_closed_client_is_dropped
    connect.close
    3.times { @api.poll }
    assert_equal "0000.0000.000a", ask(connect, "show.overview").dig("result", "system_id")
  end

  def test_a_second_daemon_on_the_socket_is_refused
    assert_raises(ISIS::Daemon::Api::InUse) { ISIS::Daemon::Api.new(@router, path: @api.path).start }
  end

  def test_a_stale_socket_is_replaced
    @api.stop
    UNIXServer.new(@api.path) # a socket file nobody answers on: closed at once below
                .close
    @api = ISIS::Daemon::Api.new(@router, path: @api.path).start
    assert_equal "a", ask(connect, "show.overview").dig("result", "hostname")
  end
end
