# frozen_string_literal: true

module ISIS
  # A circuit is one IS instance on one link. It owns a datalink socket,
  # sends periodic Hellos, receives them, and runs the adjacency handshake.
  #
  # The socket is any open Datalink::Socket. For the PoC it is usually the
  # loopback backend, so two circuits share one in-memory wire with no
  # privileges.
  class Circuit
    DEFAULT_AREA = "49.0001"

    attr_reader :system_id, :snpa, :area, :adjacencies

    def initialize(socket, system_id:, snpa:, area: DEFAULT_AREA,
                   level: 1, holding_time: 30, priority: 64, logger: nil)
      @socket = socket
      @system_id = system_id.is_a?(SystemId) ? system_id : SystemId.new(system_id)
      @snpa = snpa.is_a?(Datalink::MAC) ? snpa : Datalink::MAC.new(snpa)
      @area = area
      @level = level
      @holding_time = holding_time
      @priority = priority
      @logger = logger
      @adjacencies = {} # system id string => Adjacency
      @all_iss = Link.all_iss(level)
    end

    # Build and send one Hello. Its IS Neighbors TLV lists every neighbor
    # we have heard, which is what lets the other side reach :up.
    def send_hello
      hello = LanHello.new(
        source_id: @system_id,
        circuit_type: @level,
        holding_time: @holding_time,
        priority: @priority,
        area_addresses: [@area],
        neighbors: @adjacencies.values.map(&:snpa),
        protocols: [NLPID_IPV4],
        pdu_type: @level == 2 ? L2_LAN_IIH : L1_LAN_IIH
      )
      payload = Link.llc.wrap(hello.encode)
      frame = Datalink::Frame.ieee_802_3(dst: @all_iss, src: @snpa, payload: payload)
      @socket.send(frame)
      hello
    end

    # Drain all frames currently available, updating adjacencies. Returns
    # the number of IS-IS Hellos processed.
    def poll(timeout: nil)
      @socket.recv_timeout = timeout unless timeout.nil?
      processed = 0
      loop do
        captured = @socket.recv
        processed += 1 if process(captured.frame)
      rescue Datalink::TimeoutError
        break
      end
      processed
    end

    # Remove adjacencies whose holding time has elapsed.
    def expire_adjacencies
      @adjacencies.delete_if do |key, adj|
        dead = adj.expired?
        log("adj #{key} expired") if dead
        dead
      end
    end

    def adjacency(system_id)
      @adjacencies[system_id.to_s]
    end

    def adjacency_state(system_id)
      adjacency(system_id)&.state
    end

    # True when every known adjacency is up, or when a specific neighbor is
    # up. With no neighbors known, false.
    def up?(system_id = nil)
      return adjacency_state(system_id) == :up if system_id

      @adjacencies.any? && @adjacencies.values.all?(&:up?)
    end

    # Process one received frame. Returns the LanHello if it was an IS-IS
    # Hello for us, else nil.
    def process(frame)
      return nil unless frame.dst == @all_iss || frame.dst == @snpa

      sdu = frame.sdu # datalink-socket trims any 802.3 NIC padding for us
      return nil unless Link.isis_llc?(sdu)

      _llc, pdu = Datalink::LLC.parse(sdu)
      return nil if pdu.empty? || pdu.getbyte(0) != IRPD
      return nil unless [L1_LAN_IIH, L2_LAN_IIH].include?(pdu.getbyte(4))

      hello = LanHello.parse(pdu)
      return nil if hello.source_id == @system_id # ignore our own echo

      update_adjacency(hello, frame.src)
      hello
    rescue ParseError, Datalink::ParseError => e
      log("dropped malformed PDU: #{e.message}")
      nil
    end

    private

    def update_adjacency(hello, src_mac)
      key = hello.source_id.to_s
      heard_us = hello.neighbors.any? { |m| m == @snpa }
      new_state = heard_us ? :up : :init

      adj = @adjacencies[key]
      if adj.nil?
        @adjacencies[key] = Adjacency.new(
          system_id: hello.source_id, snpa: src_mac,
          state: new_state, holding_time: hello.holding_time
        )
        log("adj #{key} -> #{new_state}")
      else
        adj.snpa = src_mac
        adj.holding_time = hello.holding_time
        if adj.state != new_state
          log("adj #{key} #{adj.state} -> #{new_state}")
          adj.state = new_state
        end
        adj.touch
      end
    end

    def log(message)
      @logger&.puts("[#{@system_id}] #{message}")
    end
  end
end
