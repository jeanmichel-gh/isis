# frozen_string_literal: true

require "json"
require "socket"
require "uri"

module ISIS
  class Daemon
    # isis4r-sim's HTTP API, as bgp4r-sim, vtep4r-sim and bfd4r-sim have
    # (routescope docs/design/protocol-conventions.md, part 4): HTTP/1.1 on
    # 127.0.0.1:8080 by default, hand-written over TCPServer, one request
    # per connection, JSON in and out. It sits beside the Unix socket's API
    # (Api), which stays as it is.
    #
    # A POST needs the header X-ISIS4R: routescope, compared in lower
    # case, which a page of another site cannot send; without it, 403. A
    # refused request is a 4xx with {"error": ...}.
    #
    # Like Api it runs in the daemon's own loop and thread: #poll accepts,
    # reads and writes what is ready and never waits, so a request is
    # answered between two turns of the protocol and never during one.
    class Http
      MAX_REQUEST = 1 << 20
      MAX_CLIENTS = 32
      HEADER = "x-isis4r"
      TOKEN = "routescope"

      # GET path => ->(http, query) { result }
      READS = {
        "/api/status" => ->(h, _) { h.status },
        "/api/state" => ->(h, _) { h.simulator.state },
        "/api/topology" => ->(h, _) { h.simulator.graph },
        "/api/sent" => ->(h, _) { { faults: h.simulator.faults, sent: h.simulator.sent } },
        "/api/catalog" => ->(h, _) { h.catalog },
        "/api/events" => ->(h, q) { h.api.events_since(q.fetch("since", "0")) }
      }.freeze

      # POST path => [parameters, ->(http, params) { result }]
      ACTIONS = {
        "/api/fault" => [%w[case router prefix index], ->(h, p) { h.fault(p, plan: false) }],
        "/api/plan" => [%w[case router prefix index], ->(h, p) { h.fault(p, plan: true) }],
        "/api/fault.clear" => [%w[router], ->(h, p) { h.simulator.fault_clear(p["router"]) }],
        "/api/behave" => [%w[name circuit count down up router start algorithm priority metric_type hold link delay],
                          ->(h, p) { h.behave(p) }],
        "/api/behave.stop" => [[], ->(h, _) { h.simulator.behave_stop }],
        "/api/send" => [%w[octets circuit], lambda do |h, p|
          hex = p.fetch("octets") { raise ArgumentError, "send needs octets, in hex" }.to_s
          raise ArgumentError, "octets is not hex" unless hex.match?(/\A(\h\h)+\z/)

          h.simulator.send_pdu([hex].pack("H*"), circuit: p["circuit"])
        end]
      }.merge(Api::SIM_PARAMS.to_h do |action, keys|
        ["/api/#{action}", [keys, ->(h, p) { Api.sim_action(h.simulator, action, p) }]]
      end).freeze

      Client = Struct.new(:io, :input, :output)

      attr_reader :simulator, :api, :address, :port

      def initialize(simulator, api:, address: "127.0.0.1", port: 8080)
        @simulator = simulator
        @api = api
        @address = address
        @port = port
        @clients = []
      end

      def start
        @server = TCPServer.new(@address, @port)
        @port = @server.addr[1]
        self
      end

      def stop
        @clients.each { _1.io.close unless _1.io.closed? }
        @clients.clear
        @server&.close
        @server = nil
      end

      def poll
        return unless @server

        accept
        @clients.each { |c| c.output.empty? ? read(c) : flush(c) }
        @clients.reject! { |c| c.io.closed? }
      end

      def status
        { version: VERSION, api: Api::VERSION, system_id: @simulator.router.system_id_s,
          systems: @simulator.topology.systems.size, links: @simulator.topology.links.size,
          generating: @simulator.generating?, aging: @simulator.aging?, faults: @simulator.faults.size,
          behaviour: @simulator.behaviour&.fetch(:name),
          paths: { get: READS.keys, post: ACTIONS.keys } }
      end

      def catalog
        { faults: (Fault.catalog + Fault.flex_algo_catalog).map { _1.except(:build) }, behaviours: Fault.behaviours,
          actions: ACTIONS.transform_values(&:first) }
      end

      def fault(params, plan:)
        name = params.fetch("case") { raise ArgumentError, "fault needs case, one of #{Fault.names.join(', ')}" }
        router = params.fetch("router") { raise ArgumentError, "fault needs router, a simulated system's name" }
        index = params["index"] && Integer(params["index"])
        @simulator.fault(name, router: router, prefix: params["prefix"], index: index, plan: plan)
      end

      # A behaviour of the catalog: name, and its own parameters.
      def behave(params)
        name = params.fetch("name") { raise ArgumentError, "behave needs name, one of #{Fault.behaviour_names.join(', ')}" }
        @simulator.behave(name, **params.except("name").transform_keys(&:to_sym))
      end

      # The answer to one request: [status, body].
      def answer(method, target, headers, body)
        uri = URI.parse(target)
        path = uri.path
        if method == "GET"
          read = READS[path] or return not_found(path)
          [200, read.call(self, URI.decode_www_form(uri.query || "").to_h)]
        elsif method == "POST"
          return [403, { error: "a POST needs the header X-ISIS4R: routescope" }] unless allowed?(headers)

          keys, action = ACTIONS[path] || (return not_found(path))
          params = body.empty? ? {} : JSON.parse(body)
          return [400, { error: "the body is not a JSON object" }] unless params.is_a?(Hash)

          unknown = params.keys - keys
          return [400, { error: "#{path} takes #{keys.join(', ')}, not #{unknown.join(', ')}" }] unless unknown.empty?

          [200, action.call(self, params)]
        else
          [405, { error: "#{method} is not GET or POST" }]
        end
      rescue JSON::ParserError
        [400, { error: "the body is not JSON" }]
      rescue ArgumentError, KeyError => e
        [400, { error: e.message }]
      end

      private

      def allowed?(headers)
        headers[HEADER].to_s.strip.downcase == TOKEN
      end

      def not_found(path)
        [404, { error: "no #{path}; GET #{READS.keys.join(', ')}; POST #{ACTIONS.keys.join(', ')}" }]
      end

      def accept
        while @clients.size < MAX_CLIENTS
          io = @server.accept_nonblock(exception: false)
          break if io == :wait_readable

          @clients << Client.new(io, +"", +"")
        end
      end

      def read(client)
        data = client.io.read_nonblock(65_536, exception: false)
        return if data == :wait_readable
        return client.io.close if data.nil?

        client.input << data
        return respond(client, 413, { error: "request too large" }) if client.input.bytesize > MAX_REQUEST

        request(client)
      rescue SystemCallError, IOError
        client.io.close unless client.io.closed?
      end

      # A whole request is the header lines, a blank line, and as many
      # octets of body as Content-Length says.
      def request(client)
        head, rest = client.input.split("\r\n\r\n", 2)
        return unless rest

        lines = head.split("\r\n")
        method, target, = lines.shift.to_s.split(" ")
        headers = lines.to_h { |l| k, v = l.split(":", 2); [k.to_s.strip.downcase, v.to_s.strip] }
        length = headers["content-length"].to_i
        return if rest.bytesize < length

        status, body = answer(method.to_s, target.to_s, headers, rest.byteslice(0, length))
        respond(client, status, body)
      end

      REASONS = { 200 => "OK", 400 => "Bad Request", 403 => "Forbidden", 404 => "Not Found",
                  405 => "Method Not Allowed", 413 => "Payload Too Large" }.freeze

      def respond(client, status, body)
        json = JSON.generate(body)
        client.output << "HTTP/1.1 #{status} #{REASONS.fetch(status, 'Error')}\r\n" \
                         "Content-Type: application/json\r\nContent-Length: #{json.bytesize}\r\n" \
                         "Connection: close\r\n\r\n#{json}"
        flush(client)
      end

      def flush(client)
        n = client.io.write_nonblock(client.output, exception: false)
        return if n == :wait_writable

        client.output = client.output.byteslice(n..)
        client.io.close if client.output.empty?
      rescue SystemCallError, IOError
        client.io.close unless client.io.closed?
      end
    end
  end
end
