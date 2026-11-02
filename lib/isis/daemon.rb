# frozen_string_literal: true

module ISIS
  # isisd: a Router from a configuration file, run on the real clock on a
  # Linux host, with the management API on a Unix socket. One thread: each
  # turn runs the protocol's due timers, reads frames, then answers the
  # API, so the API never sees a mechanism halfway through a change.
  class Daemon
    SOCKET = "/run/isis4r/isisd.sock"

    attr_reader :router, :api, :host, :log

    # The configuration file, YAML (JSON is YAML too), with its areas
    # as written (ConfigFile).
    def self.load_config(path)
      Router.normalize(ConfigFile.load(path))
    end

    def initialize(config, log:, clock:, scheduler: Runtime::Scheduler.new(clock), host: nil, socket: SOCKET,
                   group: nil)
      @log = log
      @clock = clock
      @host = host || Router::Host.new(log: log)
      @router = Router.new(config, clock: clock, scheduler: scheduler, log: log, host: @host)
      @api = socket && Api.new(@router, path: socket, group: group)
      @stop = false
    end

    def start
      @api&.start
      @router.start
      @log.info("isisd #{VERSION} started as #{@router.system_id_s}" \
                "#{" (#{@router.config[:hostname]})" if @router.config[:hostname]}, " \
                "level #{@router.levels.join('-')}, on #{@router.interfaces.map(&:name).join(', ')}", kind: :daemon)
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
      @log.info("isisd stopping", kind: :daemon)
      @router.stop
      @api&.stop
      @host.close if @host.respond_to?(:close)
      self
    end
  end
end
