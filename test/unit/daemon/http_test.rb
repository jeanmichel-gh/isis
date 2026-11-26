# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"
require "net/http"
require "tmpdir"

# isis4r-sim's HTTP API (Daemon::Http): each path through #answer, then a
# real request over TCP on 127.0.0.1, with the daemon's loop turning as
# isis4r-sim's does. The simulator is a small SR grid on a simulated wire.
class TestDaemonHttp < Minitest::Test
  HEADER = { "X-ISIS4R" => "routescope" }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    @log = ISIS::Runtime::Log.new(clock: @clock)
    @dir = Dir.mktmpdir("isis-http")
    topo = ISIS::Sim::Topology.from_hash(
      { "simulator" => { "system_id" => "0000.0000.0009", "hostname" => "s1", "areas" => ["49.0001"], "level" => 1,
                         "interfaces" => [{ "name" => "a", "ip_addresses" => ["10.0.14.2"] }] },
        "segment_routing" => {},
        "grid" => { "rows" => 1, "columns" => 2, "metric" => 10, "loopbacks" => "10.200.0.0/24", "sids" => 101 },
        "links" => [{ "from" => "s1", "to" => "r1c1" }] }
    )
    topo.router_config[:segment_routing] = {}
    topo.router_config[:router_id] = "10.0.14.2"
    @daemon = ISIS::Daemon.new(nil, topology: topo, log: @log, clock: @clock, scheduler: @scheduler,
                                    host: SimHost.new(@wires, { "a" => "00:00:00:00:00:09" }),
                                    socket: File.join(@dir, "sim.sock"), http: "127.0.0.1:0")
    @daemon.start
    @http = @daemon.http
  end

  def teardown
    @daemon.shutdown
    FileUtils.rm_rf(@dir)
  end

  def get(path) = @http.answer("GET", path, {}, "")

  def post(path, body = {}, headers = { "x-isis4r" => "routescope" })
    @http.answer("POST", path, headers, JSON.generate(body))
  end

  def test_status
    status, body = get("/api/status")
    assert_equal 200, status
    assert_equal [ISIS::VERSION, "0000.0000.0009", 2, 0], body.values_at(:version, :system_id, :systems, :faults)
  end

  def test_a_post_needs_the_header
    assert_equal 403, post("/api/link.down", { "link" => 1 }, {}).first
    assert_equal 403, post("/api/link.down", { "link" => 1 }, { "x-isis4r" => "other" }).first
    assert_equal 200, post("/api/link.down", { "link" => 1 }, { "x-isis4r" => " RoutesCope " }).first
  end

  def test_refusals
    assert_equal 404, get("/api/nothing").first
    assert_equal 404, post("/api/nothing").first
    assert_equal 405, @http.answer("PUT", "/api/status", {}, "").first
    status, body = post("/api/link.down", { "link" => 1, "bogus" => 2 })
    assert_equal [400, "/api/link.down takes link, not bogus"], [status, body[:error]]
    assert_equal 400, @http.answer("POST", "/api/fault", { "x-isis4r" => "routescope" }, "{").first
    status, body = post("/api/fault", { "case" => "nope", "router" => "r1c2" })
    assert_equal 400, status
    assert_match(/unknown fault :nope/, body[:error])
  end

  def test_a_fault_then_cleared
    status, body = post("/api/fault", { "case" => "srgb_overlap", "router" => "r1c2" })
    assert_equal 200, status
    assert_equal [:srgb_overlap, :srgb_overlap, :ignore_srgb], body.values_at(:case, :finding, :expect)
    assert_equal 1, get("/api/sent").last[:faults].size
    assert_equal 200, post("/api/fault.clear", { "router" => "r1c2" }).first
  end

  # A flex-algo entry (step 7): a FAD in a Router Capability with S set,
  # in r1c2's LSPs.
  def test_a_flex_algo_fault
    status, body = post("/api/fault", { "case" => "fad_s_bit", "router" => "r1c2" })
    assert_equal 200, status, body
    assert_equal [:fad_s_bit, :fad_s_bit, :ignore_fad], body.values_at(:case, :finding, :expect)
    assert_equal 200, post("/api/fault.clear", { "router" => "r1c2" }).first
  end

  def test_a_plan_injects_nothing
    status, body = post("/api/plan", { "case" => "srgb_reserved", "router" => "r1c2" })
    assert_equal [200, true], [status, body[:plan]]
    assert_empty get("/api/sent").last[:faults]
  end

  def test_the_catalog
    body = get("/api/catalog").last
    assert_equal ISIS::Fault.names + ISIS::Fault.flex_algo_names, body[:faults].map { _1[:name] }
    assert_equal %w[link], body[:actions]["/api/link.down"]
    assert_equal ISIS::Fault.behaviour_names, body[:behaviours].map { _1[:name] }
  end

  # A behaviour started, seen in the status, refused while it runs,
  # stopped; each POST needs the header.
  def test_a_behaviour_then_stopped
    assert_equal 403, post("/api/behave", { "name" => "srgb_change", "router" => "r1c2" }, {}).first
    assert_equal 403, post("/api/behave.stop", {}, {}).first
    status, body = post("/api/behave", { "name" => "srgb_change", "router" => "r1c2", "start" => 200_000 })
    assert_equal 200, status, body
    assert_equal [:srgb_change, 200_000], [body[:behaviour], body[:srgb][:to][0][0]]
    assert_equal "srgb_change", get("/api/status").last[:behaviour].to_s
    status, body = post("/api/behave", { "name" => "flap" })
    assert_equal 400, status
    assert_match(/srgb_change runs/, body[:error])
    assert_equal [200, { stopped: :srgb_change }], post("/api/behave.stop")
    assert_nil get("/api/status").last[:behaviour]
    assert_equal 400, post("/api/behave", {}).first
    assert_equal 400, post("/api/behave", { "name" => "flap", "router" => "r1c2" }).first
  end

  def test_events
    post("/api/link.down", { "link" => 1 })
    body = get("/api/events?since=0").last
    assert(body[:events].any? { _1[:kind] == "simulator" })
    assert_empty get("/api/events?since=#{body[:seq]}").last[:events]
  end

  def test_send
    status, body = post("/api/send", { "octets" => ISIS::Fault.wire(:srgb_overlap).unpack1("H*") })
    assert_equal [200, "Lsp"], [status, body[:pdu]]
    assert_equal 400, post("/api/send", { "octets" => "xyz" }).first
  end

  # Over TCP, with the daemon's loop turning while the client waits.
  def test_over_tcp
    port = @http.port
    responses = []
    client = Thread.new do
      Net::HTTP.start("127.0.0.1", port) { |h| responses << h.get("/api/status") }
      Net::HTTP.start("127.0.0.1", port) { |h| responses << h.post("/api/link.down", '{"link":1}', HEADER) }
      Net::HTTP.start("127.0.0.1", port) { |h| responses << h.post("/api/link.up", '{"link":1}', {}) }
    end
    @daemon.step(wait: 0) while client.alive?
    client.join
    assert_equal %w[200 200 403], responses.map(&:code)
    assert_equal "application/json", responses.first["Content-Type"]
    assert_equal "0000.0000.0009", JSON.parse(responses.first.body)["system_id"]
  end
end
