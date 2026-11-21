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

  # bfd: true: the daemon reads BFD's events at start, before the first
  # hellos, and on each step, as it reads the API.
  def test_bfd_is_polled_at_start_and_on_each_step
    require_relative "../support/fake_bfd"
    host = SimHost.new(@wires, { "eth1" => "00:00:00:00:00:0a" })
    host.bfd_client = fake = FakeBfd.new
    config = ISIS::Router.normalize({ system_id: "0000.0000.000a", interfaces: [{ name: "eth1", bfd: true }] })
    d = ISIS::Daemon.new(config, log: @log, clock: @clock, host: host, socket: nil).start
    assert_equal 1, fake.polls
    d.step(wait: 0)
    d.step(wait: 0)
    assert_equal 3, fake.polls
    d.shutdown
    assert_includes fake.calls, [:close, true]
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

  SIM = <<~YAML
    simulator:
      system_id: 0000.0000.0009
      hostname: s1
      interfaces: [eth1]
    grid: { rows: 1, columns: 2, loopbacks: 10.200.0.0/24 }
    routers:
      - { name: lost, system_id: 0000.0000.0100 }
    links:
      - { from: s1, to: r1c1 }
  YAML

  def sim_daemon
    path = File.join(@dir, "sim.yml")
    File.write(path, SIM)
    ISIS::Daemon.new(nil, topology: ISIS::Sim::Topology.load(path), log: @log, clock: @clock,
                          host: SimHost.new(@wires, { "eth1" => "00:00:00:00:00:09" }), socket: File.join(@dir, "sim.sock"))
  end

  # isis4r-sim: the simulator's Router, the sim.* methods, and the
  # topology's warnings in the log.
  def test_a_simulator
    d = sim_daemon.start
    messages = @log.events.map(&:message)
    assert_includes messages, "isis4r-sim #{ISIS::VERSION} started as 0000.0000.0009 (s1), level 1, on eth1, simulating 3 systems"
    assert_includes messages, "simulator: 1 system no link joins to s1: lost"
    assert_same d.simulator.router, d.router
    assert d.simulator.generating?
    assert_equal 4, d.router.databases[1].entries.count { !_1.placeholder? }, "s1, r1c1, r1c2 and lost"
    assert_includes d.api.method_names, "sim.flush"
    d.shutdown
    assert_includes @log.events.map(&:message), "isis4r-sim stopping"
  end

  # isis-cli sim ACTION KEY=VALUE, values as JSON where they read as JSON.
  def test_isis_cli_sim
    d = sim_daemon.start
    stop = false
    t = Thread.new { d.step(wait: 0) until stop }
    cli = ->(*args) { Open3.capture3(RbConfig.ruby, File.join(ROOT, "exe/isis-cli"), "-s", d.api.path, *args) }
    out, err, status = cli.call("--json", "sim", "link.metric", "link=s1--r1c1", "metric=25")
    assert status.success?, err
    assert_equal "link.metric", JSON.parse(out)["action"]
    assert_equal 25, d.simulator.link("s1--r1c1").metric
    _, err, status = cli.call("sim", "link.down", "s1--r1c1")
    refute status.success?
    assert_includes err, "a sim parameter is KEY=VALUE"
  ensure
    stop = true
    t&.join
    d&.shutdown
  end

  # isis-cli show topology LEVEL prints show.topology's answer, as JSON.
  def test_isis_cli_show_topology
    d = sim_daemon.start
    stop = false
    t = Thread.new { d.step(wait: 0) until stop }
    out, err, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "exe/isis-cli"), "-s", d.api.path,
                                      "show", "topology", "1")
    assert status.success?, err
    answer = JSON.parse(out)
    assert_equal 1, answer["level"]
    assert_equal %w[lost r1c1 r1c2 s1], answer["nodes"].map { _1["hostname"] }.sort
    r1c1 = answer["nodes"].find { _1["hostname"] == "r1c1" }
    assert_includes r1c1["neighbors"].map { _1["id"] }, "0000.0000.0009.00", "r1c1 lists s1"
    _, err, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "exe/isis-cli"), "-s", d.api.path, "show", "topology")
    refute status.success?
    assert_includes err, "show.topology needs level"
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
