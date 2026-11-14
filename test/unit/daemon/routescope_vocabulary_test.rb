# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../../support/sim_host"
require_relative "../../support/routescope_vocabulary"

# isisd's API against what routescope reads from it
# (test/support/routescope_vocabulary.rb): every method answers, and every
# key routescope reads is in the answer. A change here that removes or
# renames one fails this test, before routescope's panels break
# (routescope docs/design/api-contract.md, part 3).
#
# The state is real: a router with a neighbour, so adjacencies, LSPs,
# routes and the topology are not empty. An empty list cannot show its
# elements' keys, so one fails the test rather than passing it.
class TestRoutescopeVocabulary < Minitest::Test
  STREAMS = ISIS::Daemon::Api::STREAM_METHODS

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @wires = Hash.new { |h, k| h[k] = ISIS::Link::SimulatedWire.new }
    @log = ISIS::Runtime::Log.new(clock: @clock)
    @routers = []
  end

  def router(config, macs)
    r = ISIS::Router.new(config, clock: @clock, scheduler: @scheduler, log: @log, host: SimHost.new(@wires, macs))
    @routers << r
    r
  end

  def run_for(seconds, step: 0.5)
    (seconds / step).ceil.times do
      @scheduler.advance(step)
      @routers.each { |r| r.step(wait: 0) }
    end
  end

  def neighbour(interface, mac)
    router({ system_id: "0000.0000.000b", hostname: "b", minimum_lsp_interval: 1,
             interfaces: [{ name: interface, ip_addresses: ["10.0.12.2"], hello_interval: 1, hello_multiplier: 3 }],
             prefixes: [{ prefix: "192.0.2.11/32", metric: 1 }] }, { interface => mac })
  end

  # What routescope sends each method; the rest take nothing.
  PARAMS = {
    "show.topology" => { "level" => 1 },
    "policy.leak" => { "prefixes" => [] },
    "policy.summaries" => { "summaries" => [] },
    "policy.overload" => { "on" => false },
    "sim.link.down" => { "link" => "r1c1--r1c2" }, "sim.link.up" => { "link" => "r1c1--r1c2" },
    "sim.link.toggle" => { "link" => "r1c1--r1c2" }, "sim.link.metric" => { "link" => 1, "metric" => 40 },
    "sim.link.flap" => { "link" => "r1c1--r1c2", "count" => 1, "interval" => 1 },
    "sim.router.overload" => { "router" => "r1c1", "on" => true },
    "sim.router.attached" => { "router" => "r2c2", "on" => true },
    "sim.prefixes.withdraw" => { "router" => "r2c2", "prefix" => "30.0.0.0/24" },
    "sim.prefixes.advertise" => { "router" => "r2c2", "prefix" => "30.0.0.0/24" },
    "sim.neighbor.stop" => { "circuit" => "a" }, "sim.aging" => { "on" => true }
  }.freeze

  # Called last, in this order: a flushed database has nothing to refresh,
  # and only a flushed one has something to restore.
  LAST = %w[sim.flush sim.restore].freeze

  # Every Hash a path's last key is read from, and the key. "[]" opens an
  # array: each element is followed. Flunks an empty array or a missing
  # key on the way.
  def holders(value, path, where)
    parts = path.split(".")
    nodes = [value]
    parts.each_with_index do |part, i|
      key, list = part.end_with?("[]") ? [part.delete_suffix("[]"), true] : [part, false]
      last = i == parts.size - 1 && !list
      return [nodes, key] if last
      nodes = nodes.flat_map do |n|
        v = key.empty? ? n : fetch(n, key, "#{where} #{path}")
        next [v] unless list
        assert_kind_of Array, v, "#{where} #{path}: #{key.empty? ? 'the answer' : key} is not a list"
        v
      end
      refute_empty nodes, "#{where} #{path}: an empty list shows no keys; give the test some"
    end
    [nodes, nil]
  end

  def fetch(hash, key, where)
    assert_kind_of Hash, hash, "#{where}: not an object"
    assert hash.key?(key.to_sym) || hash.key?(key), "#{where}: no key #{key}"
    hash.key?(key.to_sym) ? hash[key.to_sym] : hash[key]
  end

  def check(api, vocabulary, where)
    names = api.method_names
    vocabulary.sort_by { |m, _| LAST.index(m) || -1 }.each do |method, paths|
      assert_includes names, method, "#{where} does not answer #{method}"
      next if STREAMS.include?(method) # a stream; listing it is answering it
      r = api.handle("id" => 1, "method" => method, "params" => PARAMS.fetch(method, {}))
      refute r[:error], "#{where} #{method}: #{r[:error]}"
      paths.each do |path|
        nodes, key = holders(r[:result], path, "#{where} #{method}")
        nodes.each { |n| fetch(n, key, "#{where} #{method} #{path}") } if key
      end
    end
  end

  def test_isisd_answers_what_routescope_reads
    a = router({ system_id: "0000.0000.000a", hostname: "a", minimum_lsp_interval: 1,
                 interfaces: [{ name: "ab", ip_addresses: ["10.0.12.1"], hello_interval: 1, hello_multiplier: 3 }],
                 prefixes: [{ prefix: "192.0.2.10/32", metric: 1 }] }, { "ab" => "00:00:00:00:00:0a" })
    neighbour("ab", "00:00:00:00:00:0b")
    @routers.each(&:start)
    run_for(10)
    api = ISIS::Daemon::Api.new(a, path: "/nonexistent")
    check(api, RoutescopeVocabulary::ISISD, "isisd")
  end

  def test_isis4r_sim_answers_what_routescope_reads
    topology = ISIS::Sim::Topology.from_hash({
      "simulator" => { "system_id" => "0000.0000.0009", "hostname" => "s1", "interfaces" => [{ "name" => "a", "hello_interval" => 1 }] },
      "grid" => { "rows" => 2, "columns" => 2, "loopbacks" => "10.200.0.0/24" },
      "routers" => [{ "name" => "r2c2", "prefixes" => [{ "prefix" => "30.0.0.0/24", "count" => 2 }] }],
      "links" => [{ "from" => "s1", "to" => "r1c1" }]
    })
    sim = ISIS::Sim::Simulator.new(topology, clock: @clock, scheduler: @scheduler, log: @log,
                                             host: SimHost.new(@wires, { "a" => "00:00:00:00:00:09" }))
    @routers << sim.router
    neighbour("a", "00:00:00:00:00:0b")
    sim.start
    @routers.last.start
    run_for(10)
    api = ISIS::Daemon::Api.new(sim.router, path: "/nonexistent", simulator: sim)
    check(api, RoutescopeVocabulary::ISIS4R_SIM, "isis4r-sim")
  end
end
