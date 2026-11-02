# frozen_string_literal: true

require "yaml"

module ISIS
  # isisd: a Router from a configuration file, run on the real clock on a
  # Linux host, with the management API on a Unix socket. One thread: each
  # turn runs the protocol's due timers, reads frames, then answers the
  # API, so the API never sees a mechanism halfway through a change.
  class Daemon
    SOCKET = "/run/isis4r/isisd.sock"

    attr_reader :router, :api, :host, :log

    # The configuration file, YAML (JSON is YAML too).
    #
    # An area address such as 49.0001 reads as a number in YAML, and
    # 49.0010 as 49.001, so the areas are taken as written, from the
    # document's own text, quoted or not.
    def self.load_config(path)
      text = File.read(path)
      config = YAML.safe_load(text, permitted_classes: [], aliases: false)
      raise ArgumentError, "#{path}: the configuration is a mapping" unless config.is_a?(Hash)

      areas = written_areas(YAML.parse(text))
      config["areas"] = areas if areas
      Router.normalize(config)
    end

    # The areas list's scalars as the file wrote them.
    def self.written_areas(document)
      root = document&.root
      return unless root.is_a?(Psych::Nodes::Mapping)

      root.children.each_slice(2) do |key, value|
        next unless key.respond_to?(:value) && key.value == "areas"

        items = value.is_a?(Psych::Nodes::Sequence) ? value.children : [value]
        return items.map { |n| n.respond_to?(:value) ? n.value : raise(ArgumentError, "an area is written as 49.0001") }
      end
      nil
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
