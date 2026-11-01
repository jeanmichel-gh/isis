# frozen_string_literal: true

module ISIS
  # A circuit is one IS instance on one link. It sends Hellos, receives
  # them, and runs the adjacency handshake.
  #
  # Three things are injected. The transport moves frames: a
  # Link::SocketTransport over a real Datalink::Socket, or a
  # Link::SimulatedTransport on an in-memory wire. The clock gives protocol
  # time: a Runtime::MonotonicClock by default, or a Runtime::ManualClock in
  # tests, so holding times expire without real waiting. The log takes
  # every state change with its reason, and every PDU through its tracer.
  # With none given, a Runtime::Log with nothing installed writes nothing.
  class Circuit
    DEFAULT_AREA = "49.0001"

    attr_reader :system_id, :snpa, :area, :adjacencies, :transport, :clock, :log, :name

    def initialize(transport, system_id:, snpa:, area: DEFAULT_AREA,
                   level: 1, holding_time: 30, priority: 64, name: "lan",
                   clock: Runtime::MonotonicClock.new, log: nil)
      @transport = transport
      @clock = clock
      @log = log || Runtime::Log.new(clock: clock)
      @name = name
      @system_id = system_id.is_a?(SystemId) ? system_id : SystemId.new(system_id)
      @snpa = snpa.is_a?(Datalink::MAC) ? snpa : Datalink::MAC.new(snpa)
      @area = area
      @level = level
      @holding_time = holding_time
      @priority = priority
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
      @log.trace(:sent, @name, hello, @all_iss.to_s)
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
        if dead
          @log.info("adjacency with #{key} #{adj.state} -> down: holding time of #{adj.holding_time} s expired",
                    circuit: @name, kind: :adjacency, neighbor: key, from: adj.state, to: :down, reason: :expired)
        end
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
      unless frame.dst == @all_iss || frame.dst == @snpa
        return ignore("frame for #{frame.dst}, neither AllISs for level #{@level} nor us")
      end

      sdu = frame.sdu # datalink-socket trims any 802.3 NIC padding for us
      return ignore("not IS-IS LLC") unless Link.isis_llc?(sdu)

      _llc, octets = Datalink::LLC.parse(sdu)
      hello = Pdu.factory(Octets.new(octets))
      @log.trace(:received, @name, hello, frame.src.to_s)
      return ignore("#{hello.class.name.split('::').last} is not a LAN hello") unless hello.is_a?(Pdu::LanHello)

      unless hello.source_id.bytesize == SystemId::LENGTH
        @log.info("hello refused: a #{hello.source_id.bytesize} octet Source ID, and this circuit uses six",
                  circuit: @name, kind: :refused, reason: :id_length)
        return nil
      end

      source = SystemId.from_bytes(hello.source_id)
      return ignore("own hello") if source == @system_id

      update_adjacency(hello, source, frame.src)
      hello
    rescue Datalink::ParseError => e
      @log.info("frame refused: #{e.message}", circuit: @name, kind: :refused, reason: :malformed)
      nil
    end

    private

    def update_adjacency(hello, source, src_mac)
      key = source.to_s
      heard_us = hello.neighbors.any? { |m| m == @snpa }
      new_state = heard_us ? :up : :init
      why = heard_us ? "its TLV 6 lists our SNPA #{@snpa}" : "its TLV 6 does not list our SNPA #{@snpa} yet"

      adj = @adjacencies[key]
      if adj.nil?
        @adjacencies[key] = Adjacency.new(
          system_id: source, snpa: src_mac,
          state: new_state, holding_time: hello.holding_time, clock: @clock
        )
        transition(key, :down, new_state, why)
      else
        adj.snpa = src_mac
        adj.holding_time = hello.holding_time
        if adj.state != new_state
          transition(key, adj.state, new_state, why)
          adj.state = new_state
        end
        adj.touch
      end
    end

    def transition(key, from, to, why)
      @log.info("adjacency with #{key} #{from} -> #{to}: #{why}",
                circuit: @name, kind: :adjacency, neighbor: key, from: from, to: to)
    end

    def ignore(why)
      @log.debug("#{why}, ignored", circuit: @name)
      nil
    end
  end
end
