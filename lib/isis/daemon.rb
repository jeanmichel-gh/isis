# frozen_string_literal: true

module ISIS
  # isisd: a Router from a configuration file, run on the real clock on a
  # Linux host, with the management API on a Unix socket. One thread: each
  # turn runs the protocol's due timers, reads frames, then answers the
  # API, so the API never sees a mechanism halfway through a change.
  #
  # isis4r-sim is the same with a simulator: given a topology in place of
  # a configuration, the Router is the simulator's, and the API also
  # answers the sim.* methods.
  class Daemon
    SOCKET = "/run/isis4r/isisd.sock"

    attr_reader :router, :api, :host, :log, :simulator

    # The configuration file, YAML (JSON is YAML too), with its areas
    # as written (ConfigFile).
    def self.load_config(path)
      Router.normalize(ConfigFile.load(path))
    end

    # +config+ is a Router configuration, or with +topology+ nil and
    # ignored: the simulator's own configuration is the topology's.
    def initialize(config, log:, clock:, scheduler: Runtime::Scheduler.new(clock), host: nil, socket: SOCKET,
                   group: nil, topology: nil)
      @log = log
      @clock = clock
      @host = host || Router::Host.new(log: log)
      if topology
        @simulator = Sim::Simulator.new(topology, clock: clock, scheduler: scheduler, log: log, host: @host)
        @router = @simulator.router
      else
        @router = Router.new(config, clock: clock, scheduler: scheduler, log: log, host: @host)
      end
      @api = socket && Api.new(@router, path: socket, group: group, simulator: @simulator)
      @stop = false
    end

    def name = @simulator ? "isis4r-sim" : "isisd"

    def start
      @api&.start
      @simulator ? @simulator.start : @router.start
      @log.info("#{name} #{VERSION} started as #{@router.system_id_s}" \
                "#{" (#{@router.config[:hostname]})" if @router.config[:hostname]}, " \
                "level #{@router.levels.join('-')}, on #{@router.interfaces.map(&:name).join(', ')}" \
                "#{", simulating #{@simulator.topology.systems.size} systems" if @simulator}", kind: :daemon)
      @simulator&.topology&.warnings&.each { |w| @log.warn("simulator: #{w}", kind: :daemon) }
      self
    end

    # Run until #stop is called, from a signal handler say.
    def run
      start
      step until @stop
      shutdown
    end

    def step(wait: 0.05)
      @router.step(wait: wait)
      @api&.poll
    end

    def stop
      @stop = true
    end

    def shutdown
      @log.info("#{name} stopping", kind: :daemon)
      @simulator ? @simulator.stop : @router.stop
      @api&.stop
      @host.close if @host.respond_to?(:close)
      self
    end
  end
end
