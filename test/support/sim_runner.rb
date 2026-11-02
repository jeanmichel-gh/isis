# frozen_string_literal: true

# Runs the simulator on real interfaces, on the real clock, until told to
# stop. FrrLab starts it inside isis4r's namespace for the simulator's
# interop tests, in place of isis_runner.rb.
#
#   ruby test/support/sim_runner.rb SIM.yml
#
# The log goes to standard output, at debug with a PDU trace.
$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../../datalink-socket/lib", __dir__)

require "isis4r"

$stdout.sync = true
clock = ISIS::Runtime::MonotonicClock.new
scheduler = ISIS::Runtime::Scheduler.new(clock)
log = ISIS::Runtime::Log.new(clock: clock,
                             logger: ISIS::Runtime::Log.writer($stdout, clock: clock, debug: true),
                             tracer: ISIS::Runtime::Log.trace_writer($stdout, clock: clock, debug: true))
host = ISIS::Router::Host.new(log: log)
sim = ISIS::Sim::Simulator.new(ISIS::Sim::Topology.load(ARGV.fetch(0)), clock: clock, scheduler: scheduler,
                                                                        log: log, host: host)
stop = false
%w[TERM INT].each { |sig| Signal.trap(sig) { stop = true } }
sim.start
sim.step(wait: 0.1) until stop
sim.stop
host.close
