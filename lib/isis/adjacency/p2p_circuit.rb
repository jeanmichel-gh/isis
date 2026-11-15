# frozen_string_literal: true

module ISIS
  # A point to point circuit: one link, at most one neighbour, the RFC 5303
  # three-way handshake on top of RFC 1142 clause 8.2. At Level 1, Level 2
  # or both: one adjacency, and a P2pCircuit::Level per level the circuit
  # runs, each with its own database, originator and update process.
  #
  # Everything that varies is injected: the transport moves frames, the
  # scheduler runs the hello and holding timers on its clock, and the log
  # takes every line, event and PDU. Nothing here reads the system clock.
  #
  # Each step is a method a test can replace on one object: build_hello
  # makes the hello, transmit sends a PDU, and receive_hello decides what a
  # received hello changes. What a received LSP or sequence numbers PDU
  # does is its level's: level(n).receive_lsp and level(n).receive_snp. The
  # defaults follow the clauses quoted beside them, and every refusal is
  # logged with its reason.
  #
  # Which levels the adjacency serves, RFC 1142 clause 8.2.4.2: with an
  # area in common, the levels both sides run, from the hello's circuit
  # type; with none, "the adjacency is only valid if both Intermediate
  # systems are Level 2, and the IS shall mark the adjacency as Level 2
  # Only". The clause's Tables 4 to 7 did not survive the text extraction,
  # so this follows its prose.
  #
  # The update process at each level is UpdateProcess's, RFC 1142 clause
  # 7.3.15 for one non-broadcast circuit: the SRM and SSN flags on the database's entries, a PSNP every
  # partialSNPInterval carrying the entries with SSN set, a CSNP when the
  # adjacency comes up, and the LSPs with SRM set sent every
  # minimumLSPTransmissionInterval until the neighbour acknowledges them.
  # With an Originator, the circuit's adjacency goes into this system's
  # LSP, an Up or Down asks it for a new one (clause 7.3.6), and a received
  # copy of it is handled by clause 7.3.15.1 d. Purges, received and
  # started, are UpdateProcess's (clause 7.3.16.4).
  #
  # Authentication, RFC 5304 HMAC-MD5: hello_key for the hellos, the link
  # level password, and each level's area_key for that level's LSPs and
  # SNPs. With a key,
  # what this circuit sends carries TLV 10 first, and what it receives is
  # refused unless its digest checks out under that key. Without one,
  # nothing is added and nothing is checked.
  class P2pCircuit
    # AllISs. RFC 5309 section 4.1 recommends it for point to point hellos
    # on a LAN; second hand, from FRR's isis_pfpacket.c, which cites that
    # section. RFC 5309 itself is not read here.
    ALL_ISS = "09:00:2b:00:00:05"

    # +usage+ is the levels the adjacency serves, [1], [2] or [1, 2].
    # +ip_addresses+ is what its hellos carry in TLV 132 (RFC 1195 5.3.1),
    # and +ipv6_addresses+ in TLV 232, link-local only (RFC 5308 section 3).
    Neighbor = Struct.new(:system_id, :snpa, :state, :extended_circuit_id, :holding_time, :areas, :expiry,
                          :usage, :ip_addresses, :ipv6_addresses) do
      def system_id_s
        system_id.unpack1("H*").scan(/.{1,4}/).join(".")
      end
    end

    # RFC 1142 clause 7.3.21 and annex defaults: "partialSNPInterval-Default
    # INTEGER ::= 2" and "minimumLSPTransmissionInterval-Default INTEGER ::=
    # 5", in seconds.
    PARTIAL_SNP_INTERVAL = 2
    MINIMUM_LSP_TRANSMISSION_INTERVAL = 5

    CIRCUIT_TYPES = { [1] => :l1, [2] => :l2, [1, 2] => :l1l2 }.freeze
    TYPE_LEVELS = CIRCUIT_TYPES.invert.freeze

    attr_reader :name, :system_id, :neighbor, :log, :scheduler, :transport, :levels, :local_circuit_id
    attr_accessor :areas, :hello_interval, :hello_multiplier, :metric, :hello_key

    # +levels+ is the levels this circuit runs, each with its database,
    # originator and key: { 1 => { database:, originator:, area_key: } }.
    # Without it, the circuit runs Level 1 with +database+, +originator+
    # and +area_key+, as it did before it ran two.
    def initialize(transport:, scheduler:, log:, name:, system_id:, snpa:, areas: ["49.0001"],
                   extended_circuit_id: 1, local_circuit_id: 1, hello_interval: 3, hello_multiplier: 10,
                   ip_addresses: [], ipv6_addresses: [], protocols: [:ipv4], database: nil, originator: nil, metric: 10,
                   hello_key: nil, area_key: nil, levels: nil,
                   partial_snp_interval: PARTIAL_SNP_INTERVAL,
                   lsp_transmission_interval: MINIMUM_LSP_TRANSMISSION_INTERVAL)
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
      # RFC 5308 section 3: in hellos, "only the link-local IPv6 addresses
      # assigned to the interface that is sending the Hello".
      @ipv6_addresses = ipv6_addresses
      @protocols = protocols
      @neighbor = nil
      @hello_timer = nil
      @metric = metric
      @hello_key = hello_key
      levels ||= { 1 => { database: database, originator: originator, area_key: area_key } }
      unless CIRCUIT_TYPES.key?(levels.keys.sort)
        raise ArgumentError, "a point to point circuit runs Level 1, Level 2 or both, not #{levels.keys.inspect}"
      end

      @levels = levels.keys.sort.to_h do |n|
        opts = levels[n]
        db = opts[:database] || Database.new(level: n, clock: scheduler.clock, scheduler: scheduler, log: log)
        raise ArgumentError, "the Level #{n} database is Level #{db.level}" unless db.level == n

        [n, Level.new(circuit: self, level: n, database: db, originator: opts[:originator],
                      area_key: opts[:area_key], partial_snp_interval: partial_snp_interval,
                      lsp_transmission_interval: lsp_transmission_interval)]
      end
    end

    # The Level object for +n+, or nil when this circuit does not run it.
    def level(n)
      @levels[n]
    end

    # The levels this circuit runs, and the circuit type its hellos say.
    def level_numbers
      @levels.keys
    end

    def circuit_type
      CIRCUIT_TYPES.fetch(level_numbers)
    end

    # A circuit at one level answers for that level directly, as it did
    # before it could run two: its database, its originator, its key, and
    # the update process.
    def database = only_level.database
    def originator = only_level.originator
    def area_key = only_level.area_key
    def area_key=(key)
      only_level.area_key = key
    end

    %i[receive_lsp receive_snp send_psnp send_csnp send_srm_lsps].each do |name|
      define_method(name) { |*args| only_level.public_send(name, *args) }
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
      @levels.each_value(&:stop)
      self
    end

    # Whether it is sending hellos: started and not stopped.
    def hellos? = !@hello_timer.nil?

    # This system's three-way state for the circuit: :down with no
    # neighbour. RFC 5303 section 3.2 reports Down when there is none.
    def three_way_state
      @neighbor ? @neighbor.state : :down
    end

    # Up, and with +n+, Up and serving Level n.
    def up?(n = nil)
      return false unless three_way_state == :up

      n.nil? || @neighbor.usage.include?(n)
    end

    # The hello this circuit sends now. RFC 1142 clause 8.2.3 and RFC 5303
    # section 3.2: the Extended Local Circuit ID always, the neighbour's
    # System ID and Extended Local Circuit ID once they are known.
    def build_hello
      tlvs = [Tlv::AreaAddresses.new(@areas), Tlv::ProtocolsSupported.new(@protocols)]
      tlvs << Tlv::IpInterfaceAddresses.new(@ip_addresses) unless @ip_addresses.empty?
      tlvs << Tlv::Ipv6InterfaceAddresses.new(@ipv6_addresses) unless @ipv6_addresses.empty?
      three_way = { extended_circuit_id: @extended_circuit_id }
      if @neighbor
        three_way[:neighbor_system_id] = Octets.new(@neighbor.system_id)
        three_way[:neighbor_extended_circuit_id] = @neighbor.extended_circuit_id
      end
      tlvs << Tlv::ThreeWayAdjacency.new(three_way_state, **three_way.compact)
      hello = Pdu::P2pHello.new(circuit_type: circuit_type, source_id: Octets.new(@system_id), holding_time: holding_time,
                                local_circuit_id: @local_circuit_id, tlvs: keyed(tlvs, @hello_key))
      hello.key = @hello_key
      hello
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
      case pdu
      when Pdu::P2pHello then receive_hello(pdu, frame.src)
      when Pdu::Lsp, Pdu::Csnp, Pdu::Psnp then receive_update(pdu)
      else @log.debug("#{pdu.class.name.split('::').last} ignored on a point to point circuit", circuit: @name)
      end
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
      # Clause 8.2.4.1 c, and RFC 5304 section 2.
      if (why = authentication_refusal(hello, @hello_key, "RFC 1142 8.2.4.1 c"))
        return refuse(:authentication, why)
      end

      three_way = hello.tlvs.find { |t| t.is_a?(Tlv::ThreeWayAdjacency) }
      reason = three_way && three_way_refusal(three_way)
      return refuse(*reason) if reason

      their_areas = hello.tlvs.select { |t| t.is_a?(Tlv::AreaAddresses) }.flat_map { |t| t.areas.map(&:to_s) }
      theirs = TYPE_LEVELS.fetch(hello.circuit_type)
      common = level_numbers & theirs
      usage =
        if (their_areas & normalized_areas).empty?
          # RFC 1142 clause 8.2.4.2: with no area in common, "the adjacency
          # is only valid if both Intermediate systems are Level 2, and the
          # IS shall mark the adjacency as Level 2 Only". Clause b 1 and b
          # 2: a Level 1 system deletes the adjacency.
          unless common.include?(2)
            return drop_neighbor(:area, "no area in common: theirs #{their_areas.join(', ')}, ours #{@areas.join(', ')}")
          end

          [2]
        else
          common
        end
      # No level both sides run: no adjacency. ISO's tables for this are not
      # in the supplied text; refusing a Level 1 circuit's Level 2 only
      # neighbour follows FRR's process_p2p_hello.
      if usage.empty?
        return drop_neighbor(:level, "neighbor is Level #{theirs.join(' and ')} only, this circuit is " \
                                     "Level #{level_numbers.join(' and ')}")
      end

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
      apply(action, hello, three_way, snpa, usage)
      action
    end

    private

    # The IPv4 addresses a hello carries in TLV 132, as strings.
    def ip_addresses(hello)
      hello.tlvs.select { |t| t.is_a?(Tlv::IpInterfaceAddresses) }.flat_map { |t| t.addresses.map(&:to_s) }
    end

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

    def apply(action, hello, three_way, snpa, usage)
      if action == :down
        drop_neighbor(:restarted, "neighbor reports three-way Up while ours is Down: neighbor restarted (RFC 5303 3.2)")
        return
      end

      before = @neighbor.state
      @neighbor.state = Adjacency::ThreeWay.after(action, before)
      # RFC 1142 clause 8.2.4.2 e: on Up or Accept, take the holding time
      # and areas from the PDU.
      @neighbor.snpa = snpa
      addresses = [@neighbor.ip_addresses, @neighbor.ipv6_addresses]
      @neighbor.holding_time = hello.holding_time
      @neighbor.areas = hello.tlvs.select { |t| t.is_a?(Tlv::AreaAddresses) }.flat_map { |t| t.areas.map(&:to_s) }
      @neighbor.ip_addresses = ip_addresses(hello)
      @neighbor.ipv6_addresses = hello.tlvs.select { |t| t.is_a?(Tlv::Ipv6InterfaceAddresses) }
                                      .flat_map { |t| t.addresses.map(&:to_s) }
      @neighbor.extended_circuit_id = three_way&.extended_circuit_id
      restart_holding_timer
      was = @neighbor.usage || []
      @neighbor.usage = usage
      if before != @neighbor.state
        @log.info("adjacency with #{@neighbor.system_id_s} #{before} -> #{@neighbor.state}" \
                  "#{@neighbor.state == :up ? " at Level #{usage.join(' and ')}" : ''}",
                  circuit: @name, kind: :adjacency, neighbor: @neighbor.system_id_s, from: before,
                  to: @neighbor.state, levels: usage)
      elsif @neighbor.state == :up && was != usage
        @log.info("adjacency with #{@neighbor.system_id_s} now serves Level #{usage.join(' and ')}, " \
                  "was Level #{was.join(' and ')}", circuit: @name, kind: :adjacency,
                                                    neighbor: @neighbor.system_id_s, levels: usage)
      end
      # Up to Initializing or Down, by the neighbour's TLV 240: the levels
      # it served lose it, as when the holding timer expires.
      was.each { |n| level(n).adjacency_down } if before == :up && @neighbor.state != :up
      return unless @neighbor.state == :up

      gained = before == :up ? usage - was : usage
      lost = before == :up ? was - usage : []
      lost.each { |n| level(n).adjacency_down }
      gained.each { |n| level(n).adjacency_up(@neighbor.system_id_s) }
      # The next hop's address comes from the hellos' TLVs 132 and 232, so a
      # route through this neighbour moves when they do. Measured on FRR
      # 10.5.1: its first hellos carry no TLV 232, which it adds once the
      # kernel gives veth0 its link-local address, after the adjacency is Up.
      return unless before == :up && addresses != [@neighbor.ip_addresses, @neighbor.ipv6_addresses]

      (usage & was).each { |n| level(n).addresses_changed(@neighbor.system_id_s) }
    end

    # An LSP or SNP goes to its level, when the circuit runs that level
    # and the adjacency is up and serves it.
    def receive_update(pdu)
      name = pdu.class.name.split("::").last
      flooding = level(pdu.level)
      return @log.debug("Level #{pdu.level.inspect} #{name} ignored: this circuit does not run it", circuit: @name) unless flooding
      return @log.debug("#{name} ignored: no adjacency up at Level #{pdu.level}", circuit: @name) unless up?(pdu.level)

      pdu.is_a?(Pdu::Lsp) ? flooding.receive_lsp(pdu) : flooding.receive_snp(pdu)
    end

    public :receive_update

    def only_level
      return @levels.values.first if @levels.size == 1

      raise ArgumentError, "this circuit runs two levels: ask level(1) or level(2)"
    end

    def keyed(tlvs, key)
      Receive::Authentication.keyed(tlvs, key)
    end

    def authentication_refusal(pdu, key, clause)
      Receive::Authentication.refusal(pdu, key, clause)
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
        usage = @neighbor.state == :up ? (@neighbor.usage || []) : []
        @neighbor = nil
        usage.each { |n| level(n).adjacency_down }
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
