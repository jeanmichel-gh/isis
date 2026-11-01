# frozen_string_literal: true

module ISIS
  # A circuit is one IS instance on one link. It sends Hellos, receives
  # them, and runs the adjacency handshake.
  #
  # Two things are injected. The transport moves frames: a
  # Link::SocketTransport over a real Datalink::Socket, or a
  # Link::SimulatedTransport on an in-memory wire. The clock gives protocol
  # time: a Runtime::MonotonicClock by default, or a Runtime::ManualClock in
  # tests, so holding times expire without real waiting.
  class Circuit
    DEFAULT_AREA = "49.0001"

    attr_reader :system_id, :snpa, :area, :adjacencies, :transport, :clock

    def initialize(transport, system_id:, snpa:, area: DEFAULT_AREA,
                   level: 1, holding_time: 30, priority: 64, logger: nil,
                   clock: Runtime::MonotonicClock.new)
      @transport = transport
      @clock = clock
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
      tlvs = [Tlv::AreaAddresses.new(@area), Tlv::ProtocolsSupported.new(:ipv4)]
      neighbors = @adjacencies.values.map(&:snpa)
      tlvs << Tlv::IsNeighbors.new(neighbors) unless neighbors.empty?
      hello = Pdu::LanHello.new(
        level: @level,
        circuit_type: @level == 2 ? :l2 : :l1,
        source_id: @system_id.to_s,
        holding_time: @holding_time,
        priority: @priority,
        lan_id: "#{@system_id}.00", # self, pseudonode 0, until a DIS is elected
        tlvs: tlvs
      )
      payload = Link.llc.wrap(hello.encode)
      frame = Datalink::Frame.ieee_802_3(dst: @all_iss, src: @snpa, payload: payload)
      @transport.send(frame)
      hello
    end

    # Drain the frames the transport has, updating adjacencies. Returns the
    # number of IS-IS Hellos processed. A real transport may wait up to
    # +timeout+ for each frame; a simulated one never waits.
    def poll(timeout: nil)
      processed = 0
      while (frame = @transport.receive(timeout: timeout))
        processed += 1 if process(frame)
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

    # Process one received frame. Returns the Pdu::LanHello if it was an
    # IS-IS LAN hello for us, else nil.
    def process(frame)
      return nil unless frame.dst == @all_iss || frame.dst == @snpa

      sdu = frame.sdu # datalink-socket trims any 802.3 NIC padding for us
      return nil unless Link.isis_llc?(sdu)

      _llc, octets = Datalink::LLC.parse(sdu)
      hello = Pdu.factory(Octets.new(octets))
      return nil unless hello.is_a?(Pdu::LanHello)

      unless hello.source_id.bytesize == SystemId::LENGTH
        log("dropped LAN hello with a #{hello.source_id.bytesize} octet Source ID")
        return nil
      end

      source = SystemId.from_bytes(hello.source_id)
      return nil if source == @system_id # ignore our own echo

      update_adjacency(hello, source, frame.src)
      hello
    rescue Datalink::ParseError => e
      log("dropped malformed PDU: #{e.message}")
      nil
    end

    private

    def update_adjacency(hello, source, src_mac)
      key = source.to_s
      heard_us = hello.neighbors.any? { |m| m == @snpa }
      new_state = heard_us ? :up : :init

      adj = @adjacencies[key]
      if adj.nil?
        @adjacencies[key] = Adjacency.new(
          system_id: source, snpa: src_mac,
          state: new_state, holding_time: hello.holding_time, clock: @clock
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
