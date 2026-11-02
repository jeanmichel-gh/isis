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
require "ipaddr"
require "isis4r"

config = JSON.parse(File.read(ARGV.fetch(0)), symbolize_names: true)
state_file = ARGV.fetch(1)
$stdout.sync = true

iface = config.fetch(:interface)
# With :ipv6, the system runs IPv6 too (RFC 5308): :ipv6 in TLV 129, each
# circuit's link-local address in its hellos' TLV 232, read from the
# kernel, and the configured :ipv6_addresses and :ipv6_prefixes in its LSP.
ipv6 = config.fetch(:ipv6, false)
protocols = ipv6 ? %i[ipv4 ipv6] : %i[ipv4]
link_local = lambda do |name|
  return [] unless ipv6

  File.foreach("/proc/net/if_inet6").filter_map do |line|
    hex, _, _, scope, _, dev = line.split
    IPAddr.new_ntoh([hex].pack("H*")).to_s if dev == name && scope == "20"
  end
end
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
                         ip_addresses: config.fetch(:ip_addresses, []), protocols: protocols,
                         ipv6_addresses: config.fetch(:ipv6_addresses, []),
                         ipv6_prefixes: config.fetch(:ipv6_prefixes, []),
                         prefixes: config.fetch(:prefixes, []),
                         external_prefixes: config.fetch(:external_prefixes, []),
                         metric_style: config.fetch(:metric_style, "wide").to_sym,
                         area_key: config[:area_key],
                         minimum_interval: config.fetch(:minimum_lsp_interval, 1), is_type: both ? 3 : nil,
                         buffer_size: config.fetch(:lsp_buffer_size, ISIS::Originator::LSP_BUFFER_SIZE),
                         level1_database: level == 2 ? databases[1] : nil,
                         overload: config.fetch(:overload, false))
  next unless lan

  circuits[level] =
      ISIS::LanCircuit.new(transport: transport, scheduler: scheduler, log: log,
                           name: both ? "#{iface}-l#{level}" : iface, level: level,
                           circuit_type: both ? :l1l2 : nil,
                           database: database, originator: originator, area_key: config[:area_key],
                           system_id: config.fetch(:system_id), snpa: mac, areas: config.fetch(:areas),
                           ip_addresses: config.fetch(:ip_addresses, []), priority: config.fetch(:priority, 64),
                           protocols: protocols, ipv6_addresses: link_local.call(iface),
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
                             protocols: protocols, ipv6_addresses: link_local.call(iface),
                             hello_interval: config.fetch(:hello_interval),
                             hello_multiplier: config.fetch(:hello_multiplier), metric: config.fetch(:metric, 10))
  levels.each { |l| circuits[l] = p2p }
end

# More point to point circuits, each on its own interface, sharing the
# databases and originators: { interface:, ip_addresses:, metric: }.
extras = config.fetch(:extra_interfaces, []).each_with_index.map do |x, i|
  name = x.fetch(:interface)
  xsocket = Datalink::Socket.new(name, recv_timeout: 0.01).open
  xtransport = ISIS::Link::SocketTransport.new(xsocket)
  circuit = ISIS::P2pCircuit.new(transport: xtransport, scheduler: scheduler, log: log,
                                 levels: levels.to_h { |l|
                                   [l, { database: databases[l], originator: originators[l],
                                         area_key: config[:area_key] }]
                                 },
                                 hello_key: config[:hello_key], name: name, system_id: config.fetch(:system_id),
                                 snpa: File.read("/sys/class/net/#{name}/address").strip,
                                 local_circuit_id: i + 2, extended_circuit_id: i + 2,
                                 areas: config.fetch(:areas), ip_addresses: x.fetch(:ip_addresses, []),
                                 protocols: protocols, ipv6_addresses: link_local.call(name),
                                 hello_interval: config.fetch(:hello_interval),
                                 hello_multiplier: config.fetch(:hello_multiplier), metric: x.fetch(:metric, 10))
  [circuit, xtransport]
end

# With :forwarding, a netlink adapter per level installs the routes in
# this namespace's kernel, Level 1 at priority 21 and Level 2 at 22, so a
# prefix both reach goes by Level 1 (RFC 1142 7.2.12). Each starts by
# flushing what an earlier run left, and flushes again on stop.
adapters = {}
if config.fetch(:forwarding, false)
  names = lan && both ? levels.to_h { |l| ["#{iface}-l#{l}", iface] } : {}
  levels.each do |l|
    adapters[l] = ISIS::Forwarding::Netlink.new(log: log, priority: 20 + l, interfaces: names)
    adapters[l].flush
  end
end

# At both levels, an Spf::Leak puts the Level 2 routes within :leak, a
# list of covering prefixes, in the Level 1 LSP (RFC 5302 section 2). The
# default leaks nothing.
leak_policy = ->(list) { list.empty? ? ISIS::Spf::Leak::NONE : ISIS::Spf::Leak.prefixes(list) }
leak = both ? ISIS::Spf::Leak.new(originator: originators[1], log: log, policy: leak_policy.call(config.fetch(:leak, []))) : nil

# At both levels, an Spf::Summary puts the Level 1 area's prefixes in the
# Level 2 LSP (RFC 1195 section 3.2), with :summaries, a list of { prefix:,
# metric: }, in place of what each covers.
summary = both ? ISIS::Spf::Summary.new(originator: originators[2], log: log, summaries: config.fetch(:summaries, [])) : nil

# With :redistribute, { kinds:, metric:, external:, interval: }, a
# Redistribution per level takes the kernel's connected or static routes
# as external prefixes, read through a netlink adapter of its own.
redistributions = []
if (r = config[:redistribute])
  source = ISIS::Forwarding::Netlink.new(log: log)
  redistributions = levels.map do |l|
    ISIS::Redistribution.new(originator: originators[l], scheduler: scheduler, log: log, source: source,
                             kinds: r.fetch(:kinds, []), metric: r.fetch(:metric, 0),
                             external: r.fetch(:external, false), interval: r.fetch(:interval, 1))
  end
end

# A Decision Process per level, with the circuit, or the point to point
# circuit's level, as its first hops. At both levels the Level 2 one sets
# the Level 1 originator's AttachedFlag (RFC 1142 7.2.9.2).
decisions = levels.to_h do |l|
  decision = ISIS::Spf::Decision.new(system_id: config.fetch(:system_id), database: databases[l],
                                     scheduler: scheduler, log: log, forwarding: adapters[l],
                                     attached_flag: both && l == 2 ? originators[1] : nil,
                                     leak: l == 2 ? leak : nil, summary: l == 1 ? summary : nil)
  decision.attach(lan ? circuits[l] : circuits[l].levels.fetch(l))
  extras.each { |c, _| decision.attach(c.levels.fetch(l)) }
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

originators.each_value(&:start)
circuits.values.uniq.each(&:start)
extras.each { |c, _| c.start }
decisions.each_value(&:start)
redistributions.each(&:start)
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
  scheduler.run_due
  # Wait for a frame at most until the next timer is due. Each frame read
  # goes to every circuit on the interface; each takes its own level's.
  due = scheduler.next_due
  wait = due ? (due - clock.now).clamp(0.01, 0.1) : 0.1
  while (frame = transport.receive(timeout: wait))
    circuits.values.uniq.each { |c| c.receive_frame(frame) }
  end
  extras.each do |c, t|
    while (frame = t.receive(timeout: 0.005))
      c.receive_frame(frame)
    end
  end
  if clock.now >= next_state
    write_state.call
    next_state = clock.now + 0.5
  end
end
circuits.values.uniq.each(&:stop)
extras.each { |c, _| c.stop }
originators.each_value(&:stop)
adapters.each_value { |a| a.flush; a.close }
write_state.call
socket.close
