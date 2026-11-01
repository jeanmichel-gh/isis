# frozen_string_literal: true

# Runs one isis4r point to point circuit on a real interface, on the real
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
circuit = ISIS::P2pCircuit.new(transport: ISIS::Link::SocketTransport.new(socket), scheduler: scheduler, log: log,
                               name: iface, system_id: config.fetch(:system_id), snpa: mac,
                               areas: config.fetch(:areas), ip_addresses: config.fetch(:ip_addresses, []),
                               hello_interval: config.fetch(:hello_interval),
                               hello_multiplier: config.fetch(:hello_multiplier))

write_state = lambda do
  n = circuit.neighbor
  state = { state: circuit.three_way_state,
            neighbor: n && { system_id: n.system_id_s, state: n.state, holding_time: n.holding_time },
            database: circuit.database.entries.map do |e|
              { lsp_id: e.lsp_id_s, sequence: e.sequence, checksum: e.checksum,
                lifetime: e.remaining_lifetime, srm: e.srm.size, ssn: e.ssn.size }
            end }
  File.write("#{state_file}.tmp", JSON.generate(state))
  File.rename("#{state_file}.tmp", state_file)
end

stop = false
%w[TERM INT].each { |sig| Signal.trap(sig) { stop = true } }

circuit.start
next_state = clock.now
until stop
  scheduler.run_due
  # Wait for a frame at most until the next timer is due.
  due = scheduler.next_due
  wait = due ? (due - clock.now).clamp(0.01, 0.1) : 0.1
  circuit.poll(timeout: wait)
  if clock.now >= next_state
    write_state.call
    next_state = clock.now + 0.5
  end
end
circuit.stop
write_state.call
socket.close
