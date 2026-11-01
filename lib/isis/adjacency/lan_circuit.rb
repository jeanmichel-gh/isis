# frozen_string_literal: true

module ISIS
  # A broadcast circuit at one level: LAN hellos, the adjacencies they make,
  # and the election of the LAN Designated Intermediate System. RFC 1142
  # clauses 8.4.1 to 8.4.4. A system that runs both levels on a LAN runs
  # one of these per level, each with its own adjacencies, hello timer and
  # election, which is how clause 8.4.1 describes them: "Separate
  # adjacencies shall be created by the receipt of Level 1 and Level 2 LAN
  # IIH PDUs."
  #
  # Everything that varies is injected, as for P2pCircuit: the transport,
  # the scheduler and its clock, and the log. Each step is a method a test
  # can replace on one object: build_hello, transmit, receive_hello and
  # elect.
  #
  # Not here yet: the update process on a LAN (CSNPs from the DIS, PSNPs
  # from the others), pseudonode LSPs, hello padding to maxsize (clause
  # 8.4.1) and hello timer jitter (clause 10.1).
  class LanCircuit
    # RFC 1142 annex defaults: "iSISHelloTimer-Default INTEGER ::= 3",
    # "dRISISHelloTimer-Default INTEGER ::= 1",
    # "l1IntermediateSystemPriority-Default INTEGER ::= 64", and clause
    # 7.3.21's ISISHoldingMultiplier, 10.
    HELLO_INTERVAL = 3
    DIS_HELLO_INTERVAL = 1
    HOLDING_MULTIPLIER = 10
    PRIORITY = 64
    # Clause 8.4.3: a hello goes out when its contents change, but only
    # "when at least 1 second has transpired since the last transmission".
    MINIMUM_HELLO_SPACING = 1

    # A LAN ID as routers print it, "1921.6800.1001.01": the System ID in
    # groups of four hex digits, then the circuit octet. A convention.
    def self.lan_id_text(octets)
      hex = octets.unpack1("H*")
      (hex[0...-2].scan(/.{1,4}/) + [hex[-2..]]).join(".")
    end

    # One neighbour on the LAN, keyed by its LAN address (clause 8.4.1.4).
    Neighbor = Struct.new(:system_id, :snpa, :state, :priority, :holding_time, :lan_id, :areas, :expiry) do
      def system_id_s
        system_id.unpack1("H*").scan(/.{1,4}/).join(".")
      end

      def lan_id_s
        LanCircuit.lan_id_text(lan_id)
      end
    end

    attr_reader :name, :level, :system_id, :snpa, :neighbors, :log, :scheduler, :transport, :dis
    attr_accessor :areas, :priority, :hello_interval, :dis_hello_interval, :hello_multiplier, :hello_key

    def initialize(transport:, scheduler:, log:, name:, system_id:, snpa:, level: 1, areas: ["49.0001"],
                   priority: PRIORITY, local_circuit_id: 1, hello_interval: HELLO_INTERVAL,
                   dis_hello_interval: DIS_HELLO_INTERVAL, hello_multiplier: HOLDING_MULTIPLIER,
                   ip_addresses: [], protocols: [:ipv4], hello_key: nil)
      raise ArgumentError, "a LAN circuit is Level 1 or Level 2, not #{level.inspect}" unless [1, 2].include?(level)

      @transport = transport
      @scheduler = scheduler
      @log = log
      @name = name
      @level = level
      @system_id = Pdu.dotted_octets(system_id)
      @snpa = snpa.is_a?(Datalink::MAC) ? snpa : Datalink::MAC.new(snpa)
      @areas = areas
      @priority = priority
      @local_circuit_id = local_circuit_id
      @hello_interval = hello_interval
      @dis_hello_interval = dis_hello_interval
      @hello_multiplier = hello_multiplier
      @ip_addresses = ip_addresses
      @protocols = protocols
      @hello_key = hello_key
      @neighbors = {} # LAN address as a String => Neighbor
      @dis = nil      # nil, :self, or the Neighbor elected
      @electing = false
      @hello_timer = nil
      @pending_hello = nil
      @last_hello_at = nil
    end

    # Clause 8.4.4: "Commence sending IIH PDUs with the LAN ID field set to
    # the concatenation of its own systemID and its locally assigned one
    # octet Local Circuit ID", and "After waiting iSISHelloTimer * 2
    # seconds, run the ... Designated Intermediate System election".
    def start
      periodic_hello
      @election_timer = @scheduler.after(@hello_interval * 2) do
        @electing = true
        @log.debug("election starts, #{@hello_interval * 2} s after the circuit (RFC 1142 8.4.4 d)", circuit: @name)
        elect
      end
      self
    end

    def stop
      [@hello_timer, @pending_hello, @election_timer].each { |t| t&.cancel }
      @neighbors.each_value { |n| n.expiry&.cancel }
      @hello_timer = @pending_hello = @election_timer = nil
      self
    end

    def dis?
      @dis == :self
    end

    # The LAN ID this system reports: its own while it is the DIS or there
    # is none, the DIS's otherwise (clause 8.4.4).
    def lan_id
      if @dis.is_a?(Neighbor)
        @dis.lan_id
      else
        (@system_id + [@local_circuit_id].pack("C")).b
      end
    end

    def lan_id_s
      LanCircuit.lan_id_text(lan_id)
    end

    def up_neighbors
      @neighbors.values.select { |n| n.state == :up }
    end

    # Clause 8.4.3: "ISISHoldingMultiplier * iSISHelloTimer", and
    # dRISISHelloTimer in place of iSISHelloTimer for a DIS.
    def holding_time
      [current_hello_interval * @hello_multiplier, 0xffff].min
    end

    # The hello this circuit sends now. Clause 8.4.1: "the transmitting
    # Intermediate system's ID, holding timer, Level n Priority and
    # manualAreaAddresses, plus a list containing the lANAddresses of all
    # the adjacencies ... (in state Initialising or Up)".
    def build_hello
      tlvs = [Tlv::AreaAddresses.new(@areas), Tlv::ProtocolsSupported.new(@protocols)]
      tlvs << Tlv::IpInterfaceAddresses.new(@ip_addresses) unless @ip_addresses.empty?
      listed = @neighbors.values.map(&:snpa)
      tlvs << Tlv::IsNeighbors.new(listed) unless listed.empty?
      hello = Pdu::LanHello.new(level: @level, circuit_type: @level == 2 ? :l2 : :l1,
                                source_id: Octets.new(@system_id), holding_time: holding_time,
                                priority: @priority, lan_id: Octets.new(lan_id),
                                tlvs: Receive::Authentication.keyed(tlvs, @hello_key))
      hello.key = @hello_key
      hello
    end

    def send_hello
      @last_hello_at = @scheduler.now
      transmit(build_hello)
    end

    # Hand one PDU to the transport, framed for AllL1ISs or AllL2ISs.
    def transmit(pdu, dst: Link.all_iss(@level))
      dst = Datalink::MAC.new(dst) unless dst.is_a?(Datalink::MAC)
      payload = Link.llc.wrap(pdu.encode)
      @transport.send(Datalink::Frame.ieee_802_3(dst: dst, src: @snpa, payload: payload))
      @log.trace(:sent, @name, pdu, dst.to_s)
      pdu
    end

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
      if pdu.is_a?(Pdu::LanHello)
        receive_hello(pdu, frame.src)
      else
        @log.debug("#{pdu.class.name.split('::').last} ignored: no LAN update process yet", circuit: @name)
      end
    end

    # What a received LAN hello changes. Returns what was done, or the
    # reason it was refused, as a Symbol.
    def receive_hello(hello, snpa)
      if hello.level != @level
        @log.debug("Level #{hello.level} hello ignored on a Level #{@level} circuit", circuit: @name)
        return :level
      end

      if hello.source_id == @system_id
        @log.debug("own hello, ignored", circuit: @name)
        return :own
      end
      # Clause 8.4.1.1 b.
      if hello.source_id.bytesize != @system_id.bytesize
        return refuse(:id_length, "ID Length #{hello.source_id.bytesize} octets, ours is #{@system_id.bytesize} " \
                                  "(RFC 1142 8.4.1.1 b)")
      end
      # Clause 9.5: circuit type 0, "the entire PDU shall be ignored".
      return refuse(:circuit_type, "circuit type 0 is reserved (RFC 1142 9.5)") if hello.circuit_type == 0
      # Clause 8.4.1.1 c, and RFC 5304 section 2.
      if (why = Receive::Authentication.refusal(hello, @hello_key, "RFC 1142 8.4.1.1 c"))
        return refuse(:authentication, why)
      end

      key = snpa.to_s
      their_areas = hello.tlvs.select { |t| t.is_a?(Tlv::AreaAddresses) }.flat_map { |t| t.areas.map(&:to_s) }
      # Clause 8.4.1.2: a Level 1 hello with no area in common rejects the
      # adjacency. Clause 8.4.1.3: a Level 2 one is accepted.
      if @level == 1 && (their_areas & normalized_areas).empty?
        return drop(key, :area, "no area in common: theirs #{their_areas.join(', ')}, ours #{@areas.join(', ')} " \
                                "(RFC 1142 8.4.1.2)")
      end

      neighbor = @neighbors[key]
      if neighbor && neighbor.system_id != hello.source_id
        drop(key, :replaced, "hello from #{hello.source_id_s} at #{key}, which was #{neighbor.system_id_s}")
        neighbor = nil
      end
      action = neighbor ? :updated : :new
      unless neighbor
        # Clause 8.4.1.5: "set the state of the adjacency to initialising".
        neighbor = @neighbors[key] = Neighbor.new(hello.source_id, snpa, :initializing)
        @log.info("adjacency with #{neighbor.system_id_s} at #{key} down -> initializing", circuit: @name,
                  kind: :adjacency, neighbor: neighbor.system_id_s, from: :down, to: :initializing)
      end
      # Clauses 8.4.1.4 and 8.4.1.5 b: holding time, priority and areas from
      # the PDU, and the LAN ID it reports, for the election.
      neighbor.priority = hello.priority
      neighbor.holding_time = hello.holding_time
      neighbor.lan_id = hello.lan_id
      neighbor.areas = their_areas
      restart_holding_timer(key, neighbor)

      listed = hello.neighbors.any? { |n| n.to_s == @snpa.to_s }
      if listed && neighbor.state != :up
        # Clause 8.4.1.5: "When R reports this circuit's lANAddress ... set
        # the adjacency's state to Up".
        transition(neighbor, :up, "it lists our LAN address #{@snpa}")
      elsif !listed && neighbor.state == :up
        # "If ... this system's lANAddress is no longer in N's IIH PDU, ...
        # set the adjacency's state to initialising".
        transition(neighbor, :initializing, "it no longer lists our LAN address #{@snpa}")
      end
      hello_contents_changed if action == :new
      elect
      action
    end

    # Clause 8.4.4: the DIS is "the highest priority Intermediate system ...
    # with numerically highest MAC source lANAddress breaking ties", among
    # this system and the neighbours Up. This system does not declare
    # itself DIS "until it has at least one Up ... adjacency". Returns the
    # result: nil, :self or a Neighbor.
    def elect
      return @dis unless @electing

      candidates = up_neighbors.map { |n| [n.priority, mac_octets(n.snpa), n] }
      winner =
        if candidates.empty?
          nil
        else
          best = (candidates + [[@priority, mac_octets(@snpa), :self]]).max_by { |p, mac, _| [p, mac] }
          best.last
        end
      if same_dis?(winner)
        # The same DIS reporting another LAN ID changes what this system
        # reports too (clause 8.4.4), so the next hello differs.
        if @reported_lan_id && @reported_lan_id != lan_id
          @log.info("LAN ID #{LanCircuit.lan_id_text(@reported_lan_id)} -> #{lan_id_s}: " \
                    "the DIS now reports it (RFC 1142 8.4.4)", circuit: @name, kind: :dis, lan_id: lan_id_s)
          hello_contents_changed
        end
      else
        change_dis(winner)
      end
      @reported_lan_id = lan_id
      @dis
    end

    private

    def normalized_areas
      @areas.map { |a| AreaAddress.new(a).to_s }
    end

    def current_hello_interval
      dis? ? @dis_hello_interval : @hello_interval
    end

    # Clause 7.1.5: addresses compare numerically on their encoded form.
    # Six octets each, so the octet strings compare as numbers.
    def mac_octets(mac)
      [mac.to_s.delete(":")].pack("H*")
    end

    def same_dis?(winner)
      return @dis.equal?(winner) if winner.nil? || winner == :self || @dis.nil? || @dis == :self

      @dis.snpa.to_s == winner.snpa.to_s
    end

    def change_dis(winner)
      before = @dis
      @dis = winner
      describe = lambda do |d|
        case d
        when nil then "none"
        when :self then "this system (priority #{@priority}, #{@snpa})"
        else "#{d.system_id_s} (priority #{d.priority}, #{d.snpa})"
        end
      end
      @log.info("Level #{@level} DIS #{describe.call(before)} -> #{describe.call(winner)}; LAN ID #{lan_id_s} " \
                "(RFC 1142 8.4.4)", circuit: @name, kind: :dis, from: describe.call(before), to: describe.call(winner),
                                    lan_id: lan_id_s)
      # Clause 8.4.3 c: a hello when this system becomes or resigns as DIS,
      # and the hello timer reset, since the interval changes with it.
      if before == :self || winner == :self
        @hello_timer&.cancel
        periodic_hello
      else
        hello_contents_changed
      end
    end

    def transition(neighbor, to, why)
      from = neighbor.state
      neighbor.state = to
      @log.info("adjacency with #{neighbor.system_id_s} at #{neighbor.snpa} #{from} -> #{to}: #{why} " \
                "(RFC 1142 8.4.1.5)", circuit: @name, kind: :adjacency, neighbor: neighbor.system_id_s,
                                      from: from, to: to)
    end

    # The hello timer, clause 8.4.3 a. Jitter (clause 10.1) is not applied.
    def periodic_hello
      @pending_hello&.cancel
      @pending_hello = nil
      send_hello
      @hello_timer = @scheduler.after(current_hello_interval) { periodic_hello }
    end

    # Clause 8.4.3 b: a hello whose contents would differ goes out now, or
    # once a second has passed since the last, without resetting the timer.
    def hello_contents_changed
      return if @pending_hello

      wait = @last_hello_at ? @last_hello_at + MINIMUM_HELLO_SPACING - @scheduler.now : 0
      if wait.positive?
        @pending_hello = @scheduler.after(wait) do
          @pending_hello = nil
          send_hello
        end
      else
        send_hello
      end
    end

    # Clause 8.4.1.5: "If a neighbour is not heard from in that time, the
    # IS shall purge it from the database".
    def restart_holding_timer(key, neighbor)
      neighbor.expiry&.cancel
      seconds = neighbor.holding_time
      neighbor.expiry = @scheduler.after(seconds) do
        drop(key, :expired, "holding time of #{seconds} s expired without a hello (RFC 1142 8.4.1.5)")
      end
    end

    def drop(key, reason, why)
      neighbor = @neighbors.delete(key)
      if neighbor
        neighbor.expiry&.cancel
        @log.info("adjacency with #{neighbor.system_id_s} at #{key} #{neighbor.state} -> down: #{why}",
                  circuit: @name, kind: :adjacency, neighbor: neighbor.system_id_s, from: neighbor.state,
                  to: :down, reason: reason)
        hello_contents_changed
        elect
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
