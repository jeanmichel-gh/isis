# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/sim_host"
require "tmpdir"
require "open3"
require "rbconfig"

# isisd's daemon on a simulated host: its configuration file, its loop,
# and isis-cli asking it over the socket.
class TestDaemon < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)

  def setup
    @dir = Dir.mktmpdir
    @clock = ISIS::Runtime::ManualClock.new
    @log = ISIS::Runtime::Log.new(clock: @clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def write_config(text)
    path = File.join(@dir, "isisd.yml")
    File.write(path, text)
    path
  end

  CONFIG = <<~YAML
    system_id: 0000.0000.000a
    hostname: a
    level: 1-2
    areas: [49.0001]
    prefixes:
      - { prefix: 192.0.2.10/32, metric: 1 }
    interfaces:
      - name: eth1
        network: broadcast
        priority: 100
      - eth2
  YAML

  def test_load_config
    config = ISIS::Daemon.load_config(write_config(CONFIG))
    assert_equal "0000.0000.000a", config[:system_id]
    assert_equal "1-2", config[:level]
    assert_equal [{ prefix: "192.0.2.10/32", metric: 1 }], config[:prefixes]
    assert_equal [{ name: "eth1", network: "broadcast", priority: 100 }, { name: "eth2", network: "point-to-point" }],
                 config[:interfaces]
  end

  # YAML reads 49.0010 as the number 49.001; the area is what was written.
  def test_areas_as_written
    config = ISIS::Daemon.load_config(write_config("system_id: 0000.0000.000a\nareas: [49.0010, '49.0002']\n"))
    assert_equal %w[49.0010 49.0002], config[:areas]
    assert_equal ["49.0003"], ISIS::Daemon.load_config(write_config("areas: 49.0003\n"))[:areas]
  end

  def test_a_config_that_is_not_a_mapping
    assert_raises(ArgumentError) { ISIS::Daemon.load_config(write_config("- a\n- b\n")) }
  end

  def daemon(socket: File.join(@dir, "isisd.sock"))
    host = SimHost.new(@wires, { "eth1" => "00:00:00:00:00:0a", "eth2" => "00:00:00:00:00:1a" })
    ISIS::Daemon.new(ISIS::Daemon.load_config(write_config(CONFIG)), log: @log, clock: @clock, host: host,
                                                                     socket: socket)
  end

  def test_start_step_and_shutdown
    d = daemon.start
    assert_includes @log.events.map(&:message),
                    "isisd #{ISIS::VERSION} started as 0000.0000.000a (a), level 1-2, on eth1, eth2"
    assert File.socket?(d.api.path)
    d.step(wait: 0)
    assert_equal [1, 2], d.router.databases.keys
    d.shutdown
    refute File.exist?(d.api.path)
  end

  def test_without_a_socket
    d = daemon(socket: nil).start
    d.step(wait: 0)
    assert_nil d.api
    d.shutdown
  end

  # isis-cli in its own process, the daemon stepping in a thread here.
  def test_isis_cli
    d = daemon.start
    stop = false
    t = Thread.new { d.step(wait: 0) until stop }
    out, err, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "exe/isis-cli"), "-s", d.api.path,
                                      "show", "interfaces")
    assert status.success?, err
    lines = out.lines.map(&:split)
    assert_equal %w[name network level metric], lines.first.first(4)
    assert_equal [%w[eth1 broadcast 1], %w[eth1 broadcast 2], %w[eth2 point-to-point 1], %w[eth2 point-to-point 2]],
                 lines.drop(1).map { _1.first(3) }
    out, = Open3.capture3(RbConfig.ruby, File.join(ROOT, "exe/isis-cli"), "-s", d.api.path, "--json",
                          "show", "overview")
    assert_equal "a", JSON.parse(out)["hostname"]
    _, err, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "exe/isis-cli"), "-s", d.api.path, "show", "nothing")
    refute status.success?
    assert_includes err, "unknown method show.nothing"
  ensure
    stop = true
    t&.join
    d&.shutdown
  end

  def test_isis_cli_without_a_daemon
    _, err, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "exe/isis-cli"), "-s", File.join(@dir, "none"),
                                    "show", "overview")
    refute status.success?
    assert_includes err, "cannot reach isisd"
  end
end
