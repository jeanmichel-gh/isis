# frozen_string_literal: true

module ISIS
  # A point to point circuit: one link, at most one neighbour, the RFC 5303
  # three-way handshake on top of RFC 1142 clause 8.2. Level 1 only, which
  # is phase 1's scope.
  #
  # Everything that varies is injected: the transport moves frames, the
  # scheduler runs the hello and holding timers on its clock, and the log
  # takes every line, event and PDU. Nothing here reads the system clock.
  #
  # Each step is a method a test can replace on one object: build_hello
  # makes the hello, transmit sends a PDU, and receive_hello decides what a
  # received hello changes. The defaults follow the clauses quoted beside
  # them, and every refusal is logged with its reason.
  class P2pCircuit
    # AllISs. RFC 5309 section 4.1 recommends it for point to point hellos
    # on a LAN; second hand, from FRR's isis_pfpacket.c, which cites that
    # section. RFC 5309 itself is not read here.
    ALL_ISS = "09:00:2b:00:00:05"

    Neighbor = Struct.new(:system_id, :snpa, :state, :extended_circuit_id, :holding_time, :areas, :expiry) do
      def system_id_s
        system_id.unpack1("H*").scan(/.{1,4}/).join(".")
      end
    end

    attr_reader :name, :system_id, :neighbor, :log, :scheduler, :transport
    attr_accessor :areas, :hello_interval, :hello_multiplier

    def initialize(transport:, scheduler:, log:, name:, system_id:, snpa:, areas: ["49.0001"],
                   extended_circuit_id: 1, local_circuit_id: 1, hello_interval: 3, hello_multiplier: 10,
                   ip_addresses: [], protocols: [:ipv4])
      @transport = transport
      @scheduler = scheduler
      @log = log
      @name = name
      @system_id = Pdu.dotted_octets(system_id)
      @snpa = snpa.is_a?(Datalink::MAC) ? snpa : Datalink::MAC.new(snpa)
      @areas = areas
      @extended_circuit_id = extended_circuit_id
      @local_circuit_id = local_circuit_id
      @hello_interval = hello_interval
      @hello_multiplier = hello_multiplier
      @ip_addresses = ip_addresses
      @protocols = protocols
      @neighbor = nil
      @hello_timer = nil
    end

    # Send a hello now and every hello_interval after.
    def start
      send_hello
      @hello_timer = @scheduler.after(@hello_interval) { start }
      self
    end

    def stop
      @hello_timer&.cancel
      @hello_timer = nil
      self
    end

    # This system's three-way state for the circuit: :down with no
    # neighbour. RFC 5303 section 3.2 reports Down when there is none.
    def three_way_state
      @neighbor ? @neighbor.state : :down
    end

    def up?
      three_way_state == :up
    end

    # The hello this circuit sends now. RFC 1142 clause 8.2.3 and RFC 5303
    # section 3.2: the Extended Local Circuit ID always, the neighbour's
    # System ID and Extended Local Circuit ID once they are known.
    def build_hello
      tlvs = [Tlv::AreaAddresses.new(@areas), Tlv::ProtocolsSupported.new(@protocols)]
      tlvs << Tlv::IpInterfaceAddresses.new(@ip_addresses) unless @ip_addresses.empty?
      three_way = { extended_circuit_id: @extended_circuit_id }
      if @neighbor
        three_way[:neighbor_system_id] = Octets.new(@neighbor.system_id)
        three_way[:neighbor_extended_circuit_id] = @neighbor.extended_circuit_id
      end
      tlvs << Tlv::ThreeWayAdjacency.new(three_way_state, **three_way.compact)
      Pdu::P2pHello.new(circuit_type: :l1, source_id: Octets.new(@system_id), holding_time: holding_time,
                        local_circuit_id: @local_circuit_id, tlvs: tlvs)
    end

    def send_hello
      transmit(build_hello)
    end

    # Hand one PDU to the transport, framed for AllISs.
    def transmit(pdu, dst: ALL_ISS)
      payload = Link.llc.wrap(pdu.encode)
      @transport.send(Datalink::Frame.ieee_802_3(dst: Datalink::MAC.new(dst), src: @snpa, payload: payload))
      @log.trace(:sent, @name, pdu, dst)
      pdu
    end

    # Read every frame the transport has and process it.
    def poll(timeout: nil)
      count = 0
      while (frame = @transport.receive(timeout: timeout))
        count += 1
        receive_frame(frame)
      end
      count
    end

    def receive_frame(frame)
      sdu = frame.sdu
      return @log.debug("not IS-IS LLC, ignored", circuit: @name) unless Link.isis_llc?(sdu)

      _llc, octets = Datalink::LLC.parse(sdu)
      pdu = Pdu.factory(Octets.new(octets))
      @log.trace(:received, @name, pdu, frame.src.to_s)
      return @log.debug("#{pdu.class.name.split('::').last} ignored on a point to point circuit", circuit: @name) unless pdu.is_a?(Pdu::P2pHello)

      receive_hello(pdu, frame.src)
    end

    # What a received hello changes. Returns the action taken, or the
    # reason it was refused, as a Symbol.
    def receive_hello(hello, snpa)
      if hello.source_id == @system_id
        @log.debug("own hello, ignored", circuit: @name)
        return :own
      end
      # RFC 1142 clause 8.2.4.1 b: an ID Length that is not ours.
      return refuse(:id_length, "ID Length #{hello.source_id.bytesize} octets, ours is #{@system_id.bytesize}") if hello.source_id.bytesize != @system_id.bytesize
      # Clause 9.7: circuit type 0 "the entire PDU shall be ignored".
      return refuse(:circuit_type, "circuit type 0 is reserved (RFC 1142 9.7)") if hello.circuit_type == 0

      three_way = hello.tlvs.find { |t| t.is_a?(Tlv::ThreeWayAdjacency) }
      reason = three_way && three_way_refusal(three_way)
      return refuse(*reason) if reason

      # A Level 1 circuit and a neighbour that is Level 2 only: no
      # adjacency. ISO's state table for this is not in the supplied text;
      # this follows FRR's process_p2p_hello.
      return drop_neighbor(:level, "neighbor is Level 2 only, this circuit is Level 1") if hello.circuit_type == :l2

      their_areas = hello.tlvs.select { |t| t.is_a?(Tlv::AreaAddresses) }.flat_map { |t| t.areas.map(&:to_s) }
      # RFC 1142 clause 8.2.4.2 b: a Level 1 system with no area in common
      # deletes the adjacency.
      return drop_neighbor(:area, "no area in common: theirs #{their_areas.join(', ')}, ours #{@areas.join(', ')}") if (their_areas & normalized_areas).empty?

      if @neighbor && @neighbor.system_id != hello.source_id
        drop_neighbor(:replaced, "hello from #{hello.source_id_s}, a different neighbor")
      end
      # RFC 5303 section 3.2 a: a new adjacency starts in three-way Down.
      @neighbor ||= Neighbor.new(hello.source_id, snpa, :down)

      # RFC 5303 section 3.2: with no TLV 240 the link is taken to work in
      # both directions, which is the ISO procedure's Up.
      action = three_way ? Adjacency::ThreeWay.action(@neighbor.state, three_way.state) : :up
      @log.debug("three-way #{@neighbor.state}, received #{three_way ? three_way.state : 'no TLV 240'}: #{action}",
                 circuit: @name)
      apply(action, hello, three_way, snpa)
      action
    end

    private

    def holding_time
      [@hello_interval * @hello_multiplier, 0xffff].min
    end

    def normalized_areas
      @areas.map { |a| AreaAddress.new(a).to_s }
    end

    # RFC 5303 section 3.2: an invalid state, or neighbour fields that do
    # not name this system and circuit, discard the PDU.
    def three_way_refusal(three_way)
      unless Adjacency::ThreeWay::TABLE.key?(three_way.state)
        return [:three_way_state, "three-way state #{three_way.state} is not 0, 1 or 2 (RFC 5303 3.2)"]
      end
      if three_way.neighbor_system_id && three_way.neighbor_system_id != @system_id
        return [:three_way_neighbor, "TLV 240 names neighbor #{three_way.to_hash[:neighbor_system_id]}, not us (RFC 5303 3.2)"]
      end
      if three_way.neighbor_extended_circuit_id && three_way.neighbor_extended_circuit_id != @extended_circuit_id
        return [:three_way_circuit,
                "TLV 240 names circuit #{three_way.neighbor_extended_circuit_id}, ours is #{@extended_circuit_id} (RFC 5303 3.2)"]
      end
      nil
    end

    def apply(action, hello, three_way, snpa)
      if action == :down
        drop_neighbor(:restarted, "neighbor reports three-way Up while ours is Down: neighbor restarted (RFC 5303 3.2)")
        return
      end

      before = @neighbor.state
      @neighbor.state = Adjacency::ThreeWay.after(action, before)
      # RFC 1142 clause 8.2.4.2 e: on Up or Accept, take the holding time
      # and areas from the PDU.
      @neighbor.snpa = snpa
      @neighbor.holding_time = hello.holding_time
      @neighbor.areas = hello.tlvs.select { |t| t.is_a?(Tlv::AreaAddresses) }.flat_map { |t| t.areas.map(&:to_s) }
      @neighbor.extended_circuit_id = three_way&.extended_circuit_id
      restart_holding_timer
      return if before == @neighbor.state

      @log.info("adjacency with #{@neighbor.system_id_s} #{before} -> #{@neighbor.state}",
                circuit: @name, kind: :adjacency, neighbor: @neighbor.system_id_s, from: before, to: @neighbor.state)
    end

    # RFC 1142 clause 8.2.5: a neighbour not heard from within its holding
    # time is purged.
    def restart_holding_timer
      @neighbor.expiry&.cancel
      seconds = @neighbor.holding_time
      @neighbor.expiry = @scheduler.after(seconds) do
        drop_neighbor(:expired, "holding time of #{seconds} s expired without a hello (RFC 1142 8.2.5)")
      end
    end

    def drop_neighbor(reason, why)
      if @neighbor
        @neighbor.expiry&.cancel
        @log.info("adjacency with #{@neighbor.system_id_s} #{@neighbor.state} -> down: #{why}",
                  circuit: @name, kind: :adjacency, neighbor: @neighbor.system_id_s, from: @neighbor.state,
                  to: :down, reason: reason)
        @neighbor = nil
      else
        @log.info("hello refused: #{why}", circuit: @name, kind: :refused, reason: reason)
      end
      reason
    end

    def refuse(reason, why)
      @log.info("hello refused: #{why}", circuit: @name, kind: :refused, reason: reason)
      reason
    end
  end
end
