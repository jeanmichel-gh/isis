# frozen_string_literal: true

# Runs one isis4r circuit, point to point or broadcast, on a real interface, on the real
# clock, until it is told to stop. FrrLab starts it inside a network
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

require "json"
require "isis4r"

config = JSON.parse(File.read(ARGV.fetch(0)), symbolize_names: true)
state_file = ARGV.fetch(1)
$stdout.sync = true

iface = config.fetch(:interface)
mac = File.read("/sys/class/net/#{iface}/address").strip
clock = ISIS::Runtime::MonotonicClock.new
scheduler = ISIS::Runtime::Scheduler.new(clock)
log = ISIS::Runtime::Log.new(clock: clock,
                             logger: ISIS::Runtime::Log.writer($stdout, clock: clock, debug: true),
                             tracer: ISIS::Runtime::Log.trace_writer($stdout, clock: clock, debug: true))
socket = Datalink::Socket.new(iface, recv_timeout: 0.1).open
# :level is 1, 2 or "1-2": a database and an originator per level, and on
# a LAN a circuit per level on the one interface. On a point to point link
# one circuit runs every level.
levels = config.fetch(:level, 1).to_s == "1-2" ? [1, 2] : [Integer(config.fetch(:level, 1))]
both = levels.size == 2
transport = ISIS::Link::SocketTransport.new(socket)
lan = config[:network] == "broadcast"
databases = {}
originators = {}
circuits = {}
levels.each do |level|
  database = databases[level] = ISIS::Database.new(level: level, clock: clock, scheduler: scheduler, log: log)
  originator = originators[level] =
    ISIS::Originator.new(system_id: config.fetch(:system_id), database: database, scheduler: scheduler,
                         log: log, areas: config.fetch(:areas),
                         ip_addresses: config.fetch(:ip_addresses, []),
                         prefixes: config.fetch(:prefixes, []),
                         metric_style: config.fetch(:metric_style, "wide").to_sym,
                         area_key: config[:area_key],
                         minimum_interval: config.fetch(:minimum_lsp_interval, 1), is_type: both ? 3 : nil,
                         buffer_size: config.fetch(:lsp_buffer_size, ISIS::Originator::LSP_BUFFER_SIZE),
                         level1_database: level == 2 ? databases[1] : nil)
  next unless lan

  circuits[level] =
      ISIS::LanCircuit.new(transport: transport, scheduler: scheduler, log: log,
                           name: both ? "#{iface}-l#{level}" : iface, level: level,
                           circuit_type: both ? :l1l2 : nil,
                           database: database, originator: originator, area_key: config[:area_key],
                           system_id: config.fetch(:system_id), snpa: mac, areas: config.fetch(:areas),
                           ip_addresses: config.fetch(:ip_addresses, []), priority: config.fetch(:priority, 64),
                           hello_interval: config.fetch(:hello_interval),
                           hello_multiplier: config.fetch(:hello_multiplier), hello_key: config[:hello_key])
end
unless lan
  p2p = ISIS::P2pCircuit.new(transport: transport, scheduler: scheduler, log: log,
                             levels: levels.to_h { |l| [l, { database: databases[l], originator: originators[l],
                                                              area_key: config[:area_key] }] },
                             hello_key: config[:hello_key],
                             name: iface, system_id: config.fetch(:system_id), snpa: mac,
                             areas: config.fetch(:areas), ip_addresses: config.fetch(:ip_addresses, []),
                             hello_interval: config.fetch(:hello_interval),
                             hello_multiplier: config.fetch(:hello_multiplier))
  levels.each { |l| circuits[l] = p2p }
end

# A Decision Process per level, with the circuit, or the point to point
# circuit's level, as its first hops.
decisions = levels.to_h do |l|
  decision = ISIS::Spf::Decision.new(system_id: config.fetch(:system_id), database: databases[l],
                                     scheduler: scheduler, log: log)
  decision.attach(lan ? circuits[l] : circuits[l].levels.fetch(l))
  [l, decision]
end

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
      next_hops: r.adjacencies.map { |a| { address: a.address, circuit: a.circuit } } }
  end
  state
end

# The first level's circuit at the top, and with both levels each one
# under "levels".
write_state = lambda do
  per_level = levels.to_h { |l| [l.to_s, circuit_state.call(circuits[l], databases[l], decisions[l])] }
  state = per_level[levels.first.to_s].dup
  state[:levels] = per_level if both
  File.write("#{state_file}.tmp", JSON.generate(state))
  File.rename("#{state_file}.tmp", state_file)
end

stop = false
%w[TERM INT].each { |sig| Signal.trap(sig) { stop = true } }

originators.each_value(&:start)
circuits.values.uniq.each(&:start)
decisions.each_value(&:start)
next_state = clock.now
until stop
  scheduler.run_due
  # Wait for a frame at most until the next timer is due. Each frame read
  # goes to every circuit on the interface; each takes its own level's.
  due = scheduler.next_due
  wait = due ? (due - clock.now).clamp(0.01, 0.1) : 0.1
  while (frame = transport.receive(timeout: wait))
    circuits.values.uniq.each { |c| c.receive_frame(frame) }
  end
  if clock.now >= next_state
    write_state.call
    next_state = clock.now + 0.5
  end
end
circuits.values.uniq.each(&:stop)
originators.each_value(&:stop)
write_state.call
socket.close
