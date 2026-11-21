# frozen_string_literal: true

# Runs isis4r as an ISIS::Router on real interfaces, on the real clock,
# until it is told to stop: the first interface point to point or
# broadcast, any more point to point. FrrLab starts it inside a network
# namespace with `ip netns exec`, so it sees only that namespace's links.
#
#   ruby test/support/isis_runner.rb CONFIG.json STATE.json
#
# CONFIG gives the interface and the circuit's settings. STATE is written
# twice a second with the adjacency and the database, for the test to read. The log goes to
# standard output, at debug with a PDU trace, so a failing test can show
# exactly what happened on the wire.
$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../../datalink-socket/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../../bfd4r", __dir__)

require "json"
require "ipaddr"
require "isis4r"

config = JSON.parse(File.read(ARGV.fetch(0)), symbolize_names: true)
state_file = ARGV.fetch(1)
$stdout.sync = true

iface = config.fetch(:interface)
lan = config[:network] == "broadcast"
clock = ISIS::Runtime::MonotonicClock.new
scheduler = ISIS::Runtime::Scheduler.new(clock)
log = ISIS::Runtime::Log.new(clock: clock,
                             logger: ISIS::Runtime::Log.writer($stdout, clock: clock, debug: true),
                             tracer: ISIS::Runtime::Log.trace_writer($stdout, clock: clock, debug: true))

# The test's configuration as a Router's: the first interface from the
# top level keys, then :extra_interfaces, point to point each, { interface:,
# ip_addresses:, metric: }. TLV 132 in the LSP is the top level
# :ip_addresses alone, as it always was here.
hello = config.slice(:hello_interval, :hello_multiplier)
first = { name: iface, network: lan ? "broadcast" : "point-to-point",
          ip_addresses: config.fetch(:ip_addresses, []) }.merge(hello)
first[lan ? :priority : :metric] = lan ? config.fetch(:priority, 64) : config.fetch(:metric, 10)
extra_interfaces = config.fetch(:extra_interfaces, []).map do |x|
  { name: x.fetch(:interface), ip_addresses: x.fetch(:ip_addresses, []), metric: x.fetch(:metric, 10) }.merge(hello)
end
router_config = config.merge(interfaces: [first] + extra_interfaces, ip_addresses: config.fetch(:ip_addresses, []),
                             minimum_lsp_interval: config.fetch(:minimum_lsp_interval, 1))
router_config[:redistribute] = { interval: 1 }.merge(config[:redistribute]) if config[:redistribute]
host = ISIS::Router::Host.new(log: log)
router = ISIS::Router.new(router_config, clock: clock, scheduler: scheduler, log: log, host: host)
levels = router.levels
both = router.both?
databases = router.databases
decisions = router.decisions
circuits = router.interfaces.first.circuits
extras = router.interfaces.drop(1).map { |i| [i.circuits[levels.first], i.transport] }
leak = router.leak
summary = router.summary
redistributions = router.redistributions
leak_policy = ->(list) { ISIS::Router.leak_policy(list) }

circuit_state = lambda do |circuit, database, decision|
  state =
    if lan
      dis = circuit.dis
      { state: circuit.up_neighbors.empty? ? "down" : "up", lan_id: circuit.lan_id_s,
        dis: dis == :self ? "self" : dis&.system_id_s,
        neighbors: circuit.neighbors.values.map { |n| { system_id: n.system_id_s, state: n.state, priority: n.priority, lan_id: n.lan_id && n.lan_id_s } } }
    else
      n = circuit.neighbor
      { state: circuit.three_way_state,
        neighbor: n && { system_id: n.system_id_s, state: n.state, holding_time: n.holding_time, usage: n.usage } }
    end
  state[:database] = database.entries.map do |e|
    { lsp_id: e.lsp_id_s, sequence: e.sequence, checksum: e.checksum,
      lifetime: e.remaining_lifetime, srm: e.srm.size, ssn: e.ssn.size, is_type: e.lsp&.is_type }
  end
  state[:routes] = decision.routes.values.map do |r|
    { prefix: r.prefix, metric: r.metric,
      next_hops: r.adjacencies.map { |a| { address: a.next_hop(r.family), circuit: a.circuit } } }
  end
  state
end

# The first level's circuit at the top, and with both levels each one
# under "levels".
write_state = lambda do
  per_level = levels.to_h { |l| [l.to_s, circuit_state.call(circuits[l], databases[l], decisions[l])] }
  state = per_level[levels.first.to_s].dup
  state[:levels] = per_level if both
  state[:extra] = extras.map do |c, _|
    n = c.neighbor
    { interface: c.name, state: c.three_way_state, neighbor: n && { system_id: n.system_id_s, state: n.state } }
  end
  File.write("#{state_file}.tmp", JSON.generate(state))
  File.rename("#{state_file}.tmp", state_file)
end

stop = false
%w[TERM INT].each { |sig| Signal.trap(sig) { stop = true } }

router.start
# A test changes policy while isis4r runs by writing STATE.json.control,
# JSON with any of: leak, a new list of covering prefixes; summaries, a
# new list of { prefix:, metric: }; redistribute, a new list of kinds.
# Read when its modification time moves.
control_file = "#{state_file}.control"
control_seen = nil
apply_control = lambda do
  stamp = File.exist?(control_file) && File.mtime(control_file)
  return if !stamp || stamp == control_seen

  control_seen = stamp
  control = JSON.parse(File.read(control_file), symbolize_names: true)
  if control.key?(:leak) && leak
    log.info("control: leak #{control[:leak].inspect}")
    leak.policy = leak_policy.call(control[:leak])
  end
  if control.key?(:redistribute)
    log.info("control: redistribute #{control[:redistribute].inspect}")
    redistributions.each { |red| red.kinds = control[:redistribute] }
  end
  if control.key?(:summaries) && summary
    log.info("control: summaries #{control[:summaries].inspect}")
    summary.summaries = control[:summaries]
  end
end

next_state = clock.now
until stop
  apply_control.call
  router.step(wait: 0.1)
  if clock.now >= next_state
    write_state.call
    next_state = clock.now + 0.5
  end
end
router.stop
write_state.call
host.close
