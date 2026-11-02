# frozen_string_literal: true

require "json"
require "socket"
require "fileutils"
require "etc"

module ISIS
  class Daemon
    # The management API: JSON lines over a Unix socket, the shape ospfd's
    # has, so routescope and a person at a shell reach both the same way.
    #
    #   -> {"id": 1, "method": "show.adjacencies", "params": {}}
    #   <- {"id": 1, "result": [...]}
    #   <- {"id": 1, "error": "unknown method show.foo"}
    #
    # events.subscribe turns the connection into a stream: after its reply,
    # one line per event, and a keepalive line when nothing happened for
    # KEEPALIVE seconds. events.unsubscribe ends the stream.
    #
    #   -> {"id": 2, "method": "events.subscribe", "params": {"since": 120}}
    #   <- {"id": 2, "result": {"seq": 131, "replayed": 11}}
    #   <- {"event": {"seq": 121, "time": "...", "level": "info", "kind": "adjacency", ...}}
    #   <- {"keepalive": 131}
    #
    # It runs in the router's own loop and thread: #poll accepts, reads and
    # writes whatever is ready and never waits, so a request is answered
    # between two turns of the protocol and never during one. The socket is
    # created mode 0660, so access is by file permission.
    class Api
      MAX_LINE = 1 << 20   # bytes in one request
      MAX_CLIENTS = 32     # connections served at once
      KEEPALIVE = 15       # seconds between keepalive lines on an event stream
      MAX_EVENTS = 1000    # events kept for a subscriber to replay
      VERSION = 1          # of this API: raised when a method changes in an incompatible way
      STREAM_METHODS = %w[events.subscribe events.unsubscribe].freeze

      # name => ->(api, params) { result }
      METHODS = {
        "show.overview" => ->(a, _) { a.views.overview },
        "show.interfaces" => ->(a, _) { a.views.interfaces },
        "show.adjacencies" => ->(a, _) { a.views.adjacencies },
        "show.database" => ->(a, p) { a.views.database(level: p["level"]) },
        "show.routes" => ->(a, p) { a.views.routes(level: p["level"]) },
        "show.hostnames" => ->(a, _) { a.views.hostnames },
        "show.log" => ->(a, p) { a.views.log((p["count"] || 100).to_i.clamp(1, 1000)) },
        "show.configuration" => ->(a, _) { a.configuration },
        # Policy, as the runner's control file sets it in the interop tests.
        "policy.leak" => lambda do |a, p|
          a.router.leak_prefixes = Array(p["prefixes"])
          { leak: Array(p["prefixes"]) }
        end,
        "policy.summaries" => lambda do |a, p|
          list = Array(p["summaries"]).map { |s| Router.symbolize(s) }
          a.router.summaries = list
          { summaries: list }
        end,
        "policy.redistribute" => lambda do |a, p|
          a.router.redistribute = Array(p["kinds"])
          { redistribute: Array(p["kinds"]) }
        end,
        "policy.overload" => lambda do |a, p|
          on = p["on"] == true
          a.router.originators.each_value { |o| o.overload = on }
          { overload: on }
        end,
        "api.info" => lambda do |a, _|
          { version: ISIS::VERSION, api: VERSION, methods: (METHODS.keys + STREAM_METHODS).sort, event_seq: a.seq }
        end
      }.freeze

      # Keys whose values the API never shows.
      SECRETS = %i[area_key hello_key].freeze

      Client = Struct.new(:io, :input, :output, :subscribed, :last_write)

      attr_reader :path, :router, :views, :seq

      def initialize(router, path:, group: nil, keepalive: KEEPALIVE)
        @router = router
        @views = Views.new(router)
        @path = path
        @group = group
        @keepalive = keepalive
        @clients = []
        @events = []
        @seq = 0
        router.log.on_event { |e| record(e) }
      end

      # Raised when another isisd already answers on the socket path.
      class InUse < StandardError; end

      def start
        FileUtils.mkdir_p(File.dirname(@path))
        if File.socket?(@path)
          raise InUse, "another isisd is running on #{@path}" if live?
          File.delete(@path) # left by a daemon that died
        end
        gid = @group && Etc.getgrnam(@group).gid
        old = File.umask(0o117) # born 0660: no window where umask leaves it open
        begin
          @server = UNIXServer.new(@path)
        ensure
          File.umask(old)
        end
        File.chown(nil, gid, @path) if gid
        self
      end

      def stop
        @clients.each { |c| c.io.close unless c.io.closed? }
        @clients.clear
        @server&.close
        @server = nil
        File.delete(@path) if File.socket?(@path)
        self
      end

      # One request Hash in, one response Hash out. Used by #poll and
      # directly by tests.
      def handle(req)
        id = req["id"]
        name = req["method"].to_s
        fn = METHODS[name] or return { id: id, error: "unknown method #{name}" }
        params = req["params"].is_a?(Hash) ? req["params"] : {}
        { id: id, result: fn.call(self, params) }
      rescue ArgumentError, KeyError => e
        { id: id, error: e.message }
      rescue StandardError => e
        @router.log.error("api #{name}: #{e.class}: #{e.message}", kind: :api)
        { id: id, error: "internal error: #{e.class}" }
      end

      # Accept, read, answer and write what is ready, without waiting.
      def poll
        return unless @server

        accept
        @clients.each { |c| read(c) }
        keepalives
        @clients.each { |c| flush(c) }
        @clients.reject! { |c| c.io.closed? }
      end

      # The configuration as loaded, keys masked.
      def configuration
        mask = ->(h) { h.to_h { |k, v| [k, SECRETS.include?(k) && v ? "********" : v] } }
        mask.call(@router.config)
      end

      private

      def record(event)
        @seq += 1
        line = { seq: @seq }.merge(Views.event(event))
        @events << line
        @events.shift(@events.size - MAX_EVENTS) if @events.size > MAX_EVENTS
        @clients.each { |c| write(c, event: line) if c.subscribed }
      end

      def live?
        UNIXSocket.new(@path).close
        true
      rescue SystemCallError
        false
      end

      def accept
        loop do
          io = @server.accept_nonblock(exception: false)
          break if io == :wait_readable

          if @clients.size >= MAX_CLIENTS
            io.close
            next
          end
          @clients << Client.new(io, +"", +"", false, @router.clock.now)
        end
      end

      def read(client)
        data = client.io.read_nonblock(65_536, exception: false)
        return if data == :wait_readable
        return client.io.close if data.nil?

        client.input << data
        while (i = client.input.index("\n"))
          line = client.input.slice!(0, i + 1)
          request(client, line)
        end
        if client.input.bytesize > MAX_LINE
          write(client, error: "request over #{MAX_LINE} bytes")
          flush(client)
          client.io.close
        end
      rescue SystemCallError, IOError
        client.io.close unless client.io.closed?
      end

      def request(client, line)
        req = JSON.parse(line)
        return write(client, error: "a request is a JSON object") unless req.is_a?(Hash)

        case req["method"]
        when "events.subscribe" then subscribe(client, req)
        when "events.unsubscribe"
          client.subscribed = false
          write(client, id: req["id"], result: { unsubscribed: true })
        else write(client, handle(req))
        end
      rescue JSON::ParserError => e
        write(client, error: "not JSON: #{e.message[0, 100]}")
      end

      def subscribe(client, req)
        since = req.dig("params", "since")
        replay = since ? @events.select { _1[:seq] > Integer(since) } : []
        write(client, id: req["id"], result: { seq: @seq, replayed: replay.size })
        replay.each { |e| write(client, event: e) }
        client.subscribed = true
      end

      def keepalives
        now = @router.clock.now
        @clients.each do |c|
          write(c, keepalive: @seq) if c.subscribed && now - c.last_write >= @keepalive
        end
      end

      def write(client, message)
        client.output << JSON.generate(message) << "\n"
        client.last_write = @router.clock.now
      end

      def flush(client)
        return if client.output.empty? || client.io.closed?

        n = client.io.write_nonblock(client.output, exception: false)
        client.output.slice!(0, n) if n.is_a?(Integer)
      rescue SystemCallError, IOError
        client.io.close unless client.io.closed?
      end
    end
  end
end
