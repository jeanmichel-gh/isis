# frozen_string_literal: true

# A Router's host for tests: each interface name is a simulated wire,
# shared by every router that names it, and forwarding goes to a
# recorder.
class SimHost
  attr_reader :adapters

  def initialize(wires, macs)
    @wires = wires
    @macs = macs
    @adapters = {}
  end

  def link(name)
    { transport: ISIS::Link::SimulatedTransport.new(@wires[name]), snpa: @macs.fetch(name),
      link_local: ["fe80::#{@macs.fetch(name)[-2..]}"] }
  end

  def forwarding(level, interfaces:)
    @adapters[level] = SimAdapter.new(interfaces)
  end

  # The host's routes for redistribution: none unless a test sets them.
  attr_writer :routes

  def route_source = self

  def routes = @routes || []
end

# A Recorder that also answers what the router asks of an adapter.
class SimAdapter < ISIS::Forwarding::Recorder
  attr_reader :interfaces, :flushes

  def initialize(interfaces)
    super()
    @interfaces = interfaces
    @flushes = 0
  end

  def flush = @flushes += 1
  def close = nil
end

