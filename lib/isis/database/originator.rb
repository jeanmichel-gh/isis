# frozen_string_literal: true

module ISIS
  # This system's LSP at its database's level: built from configuration and
  # from the circuits' adjacencies, stored in the database, and flooded by
  # setting SRM on every circuit with an adjacency up. RFC 1142 clauses
  # 7.3.5 to 7.3.7, 7.3.9 at Level 2, and 7.3.16.1 to 7.3.16.3. At Level 2
  # the content is the same list: clause 7.3.9's Partition Designated
  # Level 2 IS option is not sent, since partition repair is not here.
  #
  # Non-pseudonode, LSP Number 0 and as many more as the content needs.
  # What it carries, after clause 7.3.7 and RFC 1195:
  #
  #   TLV 1    the manual area addresses
  #   TLV 129  the protocols supported
  #   TLV 137  the hostname, when there is one (RFC 5301)
  #   TLV 132  the IP interface addresses, when there are any
  #   TLV 22   one entry per circuit's is_neighbor: on a point to point
  #            circuit with an adjacency Up, the neighbour's System ID
  #            with "an appended zero octet (indicating non-pseudonode)",
  #            and on a LAN with a DIS, the DIS's LAN ID, the pseudonode
  #            (7.3.7); at the circuit's metric. With addresses on the
  #            link, sub-TLV 6 carries this end's and, on a point to
  #            point circuit, sub-TLV 8 the neighbour's (RFC 5305
  #            sections 3.2 and 3.3)
  #   TLV 135  the configured prefixes, then the external prefixes
  #   TLV 232  the IPv6 interface addresses, non-link-local, when there are
  #            any (RFC 5308 section 3: in LSPs, "only the non-link-local
  #            IPv6 addresses assigned to the IS")
  #   TLV 236  the configured IPv6 prefixes, after the IPv4 ones, in every
  #            metric style, since TLV 236 has only a wide metric
  #   TLV 242  with segment routing, in LSP 0: the Router Capability with
  #            the SRGB, SR-Algorithm 0 and the SRLB (RFC 8667 section 3)
  #
  # With segment routing (SegmentRouting), TLV 22 entries also carry
  # Adj-SIDs, or LAN-Adj-SIDs toward a pseudonode, and the wide TLV 135
  # and TLV 236 entries a Prefix-SID: a configured prefix's from its sid:,
  # a leaked or summarized one's from the route it came from.
  #
  # A system with IPv6 lists :ipv6 in protocols, which RFC 5308 section 4
  # asks of it: "it MUST advertise this in the "NLPID" TLV".
  #
  # That is metric_style :wide, the default. :narrow sends TLV 2 and TLV
  # 128 in place of 22 and 135, with only the default metric supported,
  # and :transition sends all four, as a router moving between the two
  # does. A metric too large for the narrow six bits raises.
  #
  # +external_prefixes+ are prefixes this system takes from outside IS-IS,
  # { prefix:, metric:, external: }. In the narrow styles they go in TLV
  # 130, IP External Reachability (RFC 1195 section 5.3.5), allowed at
  # Level 1 by RFC 5302 section 2.2, with I/E set when +external+ says the
  # metric is of the external type. In the wide style they go in TLV 135
  # with the others, since RFC 5305's TLV 135 has no metric type, and
  # +external+ is not sent. An IPv6 one goes in TLV 236 with X, the
  # "external original bit", set, RFC 5308 section 2: "If the prefix was
  # distributed into IS-IS from another routing protocol, the external bit
  # SHALL be set to 1."
  #
  # +leaked_prefixes+ are Level 2 routes a system at both levels puts in
  # its Level 1 LSP, set by Spf::Leak: { prefix:, metric:, external: },
  # IPv4 or IPv6. Each goes with the up/down bit set, which RFC 5302
  # section 2 asks of "prefixes that are derived from L2 routing and are
  # advertised into L1 LSPs" (RFC 5305 section 4 and RFC 5308 section 2
  # for TLVs 135 and 236): narrow, in TLV 128, or TLV 130 for the external
  # type, at most the six bits' 63; wide, in TLV 135; IPv6, in TLV 236.
  #
  # +area_prefixes+ are the Level 1 area's prefixes a system at both levels
  # puts in its Level 2 LSP, set by Spf::Summary, in the same form and in
  # the same TLVs, without the up/down bit. RFC 1195 section 3.2: a sum
  # "greater than 63" goes as 63 when narrow.
  #
  # Content that does not fit in one LSP of buffer_size octets goes on in
  # LSP Number 1, 2 and so on, clause 7.3.4's rules: "The Area Addresses
  # option field shall occur only in the LSP with LSP Number zero", and IS
  # neighbours before IP prefixes, where "after means at a higher octet
  # number from the start of the same LSP or in an LSP with a higher LSP
  # Number". So TLVs 1, 129 and 132 open LSP 0, and the reachability TLVs
  # follow in order, each LSP filled before the next starts, measured by
  # encoding. Each LSP Number has its own sequence (7.3.16.1: "The
  # sequence numbers the Intermediate system generates for its Link State
  # PDUs with different values for LSP number are independent"). On a
  # change only the LSPs whose content changed are generated again (7.3.4:
  # "It is not required to reissue the unchanged LSPs"), their SRM flags
  # set together once all are stored, and an LSP Number no longer needed is
  # purged. Filling in order means a removal can move a later entry to a
  # lower LSP Number, which the clause calls undesirable rather than
  # forbidden.
  #
  # At Level 2, given the Level 1 database of the same system, TLV 1
  # carries clause 7.2.11's area addresses in place of the manual ones:
  # "the union of the sets of manualAreaAddresses reported in the Area
  # Addresses field of all Level 1 LSPs with LSP number zero in the local
  # Intermediate system's link state database", which clause 7.3.9 puts in
  # the Level 2 LSP. "This includes all source systems, whether currently
  # reachable or not", and this system's own Level 1 LSP. The union is
  # computed again as each Level 1 LSP is stored, and a change to it is a
  # change of content (7.3.6). A Level 2 only system has no Level 1
  # database, and sends its manual area addresses.
  #
  # Each step is a method a test can replace on one object: build makes
  # the LSP, and changed, refresh and receive_own decide when a new one is
  # made. The defaults follow the clauses quoted beside them.
  class Originator
    # RFC 1142 annex defaults, in seconds: "maximumLSPGenerationInterval-
    # Default INTEGER ::= 900" and "minimumLSPGenerationInterval-Default
    # INTEGER ::= 30".
    MAXIMUM_LSP_GENERATION_INTERVAL = 900
    MINIMUM_LSP_GENERATION_INTERVAL = 30
    # ReceiveLSPBufferSize, the default originating budget. CLAUDE.md, "The
    # 255 octet limit is a packing problem".
    LSP_BUFFER_SIZE = 1492
    # maximumAreaAddresses, which the Maximum Area Addresses octet's zero
    # stands for. Second hand, from Wireshark: see CLAUDE.md, "Things to
    # verify".
    MAXIMUM_AREA_ADDRESSES = 3

    attr_reader :system_id, :database, :circuits, :refresh_interval, :minimum_interval, :buffer_size, :numbers,
                :lifetime, :lsp_generation
    # The GenerationTimer that times a change, per LSP Number. A test may
    # put its own in its place.
    attr_accessor :generation_timer
    METRIC_STYLES = %i[wide narrow transition].freeze

    attr_accessor :areas, :protocols, :ip_addresses, :prefixes, :metric_style, :area_key, :is_type,
                  :ipv6_addresses, :ipv6_prefixes, :hostname
    attr_reader :leaked_prefixes, :area_prefixes, :external_prefixes
    attr_reader :overload, :attached, :segment_routing, :injected, :link_attributes
    attr_accessor :flex_algo

    def initialize(system_id:, database:, scheduler:, log:, areas: ["49.0001"], protocols: [:ipv4],
                   ip_addresses: [], prefixes: [], external_prefixes: [], metric_style: :wide, area_key: nil,
                   ipv6_addresses: [], ipv6_prefixes: [],
                   refresh_interval: MAXIMUM_LSP_GENERATION_INTERVAL,
                   minimum_interval: MINIMUM_LSP_GENERATION_INTERVAL, lsp_generation: nil,
                   buffer_size: LSP_BUFFER_SIZE, is_type: nil, level1_database: nil, overload: false,
                   hostname: nil, lifetime: Database::MAX_AGE, segment_routing: nil, link_attributes: {},
                   flex_algo: nil)
      @system_id = Pdu.dotted_octets(system_id)
      # The IS Type in the flags octet: what kind of system this is, not
      # which LSP. 1 for a Level 1 system, 3 for a Level 2 one, which a
      # system at both levels writes in its Level 1 LSP too (RFC 1142 9.8:
      # "3 (i.e. bits 1 and 2 set) Level 2 Intermediate system"). Nil
      # leaves it to the LSP's level: 1 at Level 1, 3 at Level 2.
      @is_type = is_type
      # The LSP ID without its LSP Number: the System ID and the pseudonode
      # octet, 0 for this system's own LSPs.
      @lsp_base = (@system_id + "\x00".b).b
      @database = database
      @scheduler = scheduler
      @log = log
      @areas = areas
      @protocols = protocols
      @hostname = hostname
      # A SegmentRouting, or nil: without it nothing of RFC 8667 is sent.
      @segment_routing = segment_routing
      # Each circuit's attributes for flex-algo, by circuit name: :affinity
      # (groups), :delay, :te_metric and :srlg (Router#link_attributes).
      @link_attributes = link_attributes
      # This level's Spf::FlexAlgo, or nil: the algorithms this system takes
      # part in, for SR-Algorithm and the Prefix-SIDs, and the FADs it
      # advertises.
      @flex_algo = flex_algo
      @ip_addresses = ip_addresses
      @ipv6_addresses = ipv6_addresses
      @ipv6_prefixes = ipv6_prefixes
      @prefixes = prefixes
      @external_prefixes = external_prefixes
      @leaked_prefixes = []
      @area_prefixes = []
      raise ArgumentError, "metric style is :wide, :narrow or :transition" unless METRIC_STYLES.include?(metric_style)

      @metric_style = metric_style
      @area_key = area_key
      @refresh_interval = refresh_interval
      # The Remaining Lifetime each LSP starts with: MaxAge (7.3.16.3), or
      # less for a simulator that wants its LSPs to age out within a test.
      @lifetime = lifetime
      @minimum_interval = minimum_interval
      # nil, RFC 1142's fixed hold of minimum_interval; or a map of
      # initial, secondary and maximum, the backoff
      # (docs/design/lsp-generation.md).
      @lsp_generation = lsp_generation
      @generation_timer = GenerationTimer.build(minimum: minimum_interval, backoff: lsp_generation)
      @buffer_size = buffer_size
      @level1_database = level1_database
      @overload = overload
      @attached = false
      @circuits = []
      # Clause 7.3.16.1: "When a system initialises, it shall start with
      # sequence number 1". The first generation adds one to this, per LSP
      # Number.
      @sequences = Hash.new(0)
      # The LSP Numbers generated now.
      @numbers = []
      @generated_at = nil
      @pending = nil
      # When the first change of the round that @pending waits for came.
      @since = nil
      @refresh_timer = nil
      @started = false
      @union = nil
      level1_database&.listen(self)
    end

    # A circuit whose adjacency goes into TLV 22 and which floods the LSP.
    # It answers is_neighbor (nil, or the neighbour ID, the metric and,
    # optionally, the link's addresses { interface:, neighbor: }) and
    # flood(entry).
    def attach(circuit)
      @circuits << circuit unless @circuits.include?(circuit)
      self
    end

    # The LSP ID of LSP Number +number+.
    def lsp_id(number = 0)
      (@lsp_base + [number].pack("C")).b
    end

    def lsp_id_s(number = 0)
      Pdu.lsp_id_s(lsp_id(number))
    end

    # The sequence of LSP Number +number+, 0 before it is generated.
    def sequence(number = 0)
      @sequences[number]
    end

    # The level of the LSPs this generates: its database's. A Level 2 LSP
    # carries IS type 3, "In a Level 2 Link State PDU, IS Type shall be 3"
    # (RFC 1142 9.9), which Pdu::Lsp writes for it.
    def level
      @database.level
    end

    # Generate the first LSP and start the refresh timer.
    def start
      @started = true
      @union = area_addresses
      generate("initialisation (RFC 1142 7.3.16.1)", event: false)
      self
    end

    def stop
      [@refresh_timer, @pending].each { |t| t&.cancel }
      @refresh_timer = @pending = @since = nil
      @started = false
      self
    end

    # The area addresses TLV 1 carries: the manual ones, or at Level 2 with
    # a Level 1 database, clause 7.2.11's union, as AreaAddress objects in
    # ascending order. Clause 7.2.11: "If more than maximumAreaAddresses
    # are present, the Intermediate system shall retain only those areas
    # with numerically lowest area address (as described in 7.1.5)."
    def area_addresses
      manual = @areas.map { |a| AreaAddress.new(a) }
      return manual unless @level1_database && level == 2

      found = manual + @level1_database.entries.flat_map do |e|
        next [] if e.lsp.nil? || e.lsp_id.getbyte(-1) != 0

        e.lsp.tlvs.select { |t| t.is_a?(Tlv::AreaAddresses) }.flat_map(&:areas)
      end
      union = found.uniq(&:octets).sort { |a, b| Originator.compare_areas(a, b) }
      kept = union.first(MAXIMUM_AREA_ADDRESSES)
      dropped = manual.map(&:octets) - kept.map(&:octets)
      unless dropped.empty? || @dropped == dropped
        @log.warn("#{lsp_id_s}: manualAddressDroppedFromArea, " \
                  "#{dropped.map { |o| AreaAddress.new_ntop(o) }.join(', ')} not among the lowest " \
                  "#{MAXIMUM_AREA_ADDRESSES} area addresses (RFC 1142 7.2.11)",
                  kind: :manual_address_dropped)
      end
      @dropped = dropped
      kept
    end

    # Clause 7.1.5: "numerical comparison of addresses shall be performed on
    # the encoded form of the address, by padding the shorter address with
    # trailing zeros to the length of the longer address". That is the
    # octets compared one by one, which Ruby's String#<=> does, except that
    # two equal once padded, 49 and 4900, are equal to the clause; String
    # puts the shorter first, which keeps the order total.
    def self.compare_areas(a, b)
      a.octets <=> b.octets
    end

    # A Level 1 LSP stored in the Level 1 database: generate again if the
    # union of area addresses moved.
    def stored(_entry)
      return unless @started

      union = area_addresses
      return if union.map(&:octets) == @union.map(&:octets)

      @union = union
      changed("area addresses now #{union.join(', ')} (RFC 1142 7.2.11)")
    end

    # True for an LSP ID this system currently generates: clause 7.3.15.1
    # d's "set of currently generated LSPs".
    def generates?(lsp_id)
      lsp_id = lsp_id.b
      lsp_id.byteslice(0, @lsp_base.bytesize) == @lsp_base && @numbers.include?(lsp_id.getbyte(-1))
    end

    # LSP Number +number+ as this system would send it now with +sequence+.
    # Builds and does nothing else. +tlvs+ defaults to what that LSP Number
    # carries now. With area_key, TLV 10 goes first and the LSP carries an
    # RFC 5304 HMAC-MD5 digest.
    def build(sequence: self.sequence, number: 0, tlvs: nil)
      list = (tlvs || lsp_tlvs.fetch(number, [])).dup
      list.unshift(Tlv::Authentication.new(:hmac_md5)) if @area_key
      lsp = Pdu::Lsp.new(level: level, lsp_id: Octets.new(lsp_id(number)), lifetime: @lifetime,
                         sequence: sequence, tlvs: list, is_type: @is_type, overload: @overload && number.zero?,
                         attached: @attached && number.zero? ? [:default] : [])
      lsp.key = @area_key
      lsp
    end

    # Every TLV this system advertises, in order, whatever LSP Number each
    # lands in: entries packed into as many TLVs of one type as their
    # encoded size needs, each at most 255 octets of value.
    def tlvs
      fixed_tlvs + variable_tlvs
    end

    # The TLVs of each LSP Number, in order: LSP 0 first. Each LSP is filled
    # to buffer_size octets, measured as the empty LSP's octets plus each
    # TLV's, encoded once. Raises when a TLV cannot fit even an empty LSP,
    # or the content needs more than the 256 LSP Numbers an octet holds.
    def lsp_tlvs
      empty = build(sequence: 0, tlvs: []).encode.bytesize
      groups = [fixed_tlvs]
      size = empty + groups.first.sum { |t| t.encode.bytesize }
      raise Error, "#{lsp_id_s}'s first TLVs are #{size} octets, over the #{@buffer_size} octet budget" if size > @buffer_size

      variable_tlvs.each do |tlv|
        n = tlv.encode.bytesize
        raise Error, "a TLV of #{n} octets does not fit an LSP of #{@buffer_size} octets" if empty + n > @buffer_size

        if size + n > @buffer_size
          groups << []
          size = empty
        end
        groups.last << tlv
        size += n
      end
      raise Error, "#{groups.size} LSPs needed, and an LSP Number is one octet" if groups.size > 256

      groups
    end

    # The LSP Database Overload bit, in LSP Number 0. Clause 7.3.19.1: the
    # system "shall generate and flood its own LSP with zero LSP number with
    # the LSP Database Overload Bit set", which "prevents this Intermediate
    # system from being considered as a forwarding path by other
    # Intermediate Systems"; and clause 7.2.5 has a receiver take the bit
    # from LSP Number 0 only. Setting it here is the operator's choice, not
    # the clause's waiting state, which needs a database that can run out of
    # room. A change is a change of content (7.3.6).
    # The Level 2 routes to put in this Level 1 LSP, as Spf::Leak chooses
    # them. A change is a change of content (7.3.6).
    # The prefixes this system takes from outside IS-IS, as Redistribution
    # chooses them or a test sets them. A change is a change of content
    # (7.3.6).
    def external_prefixes=(list)
      @external_prefixes = list
      changed("external prefixes changed") if @generated_at
    end

    def leaked_prefixes=(list)
      @leaked_prefixes = list
      changed("leaked prefixes changed (RFC 5302 section 2)") if @generated_at
    end

    # The Level 1 area's prefixes to put in this Level 2 LSP, as
    # Spf::Summary chooses them. A change is a change of content (7.3.6).
    def area_prefixes=(list)
      @area_prefixes = list
      changed("area prefixes changed (RFC 1195 section 3.2)") if @generated_at
    end

    def overload=(on)
      @overload = on
      changed("LSP Database Overload bit #{on ? 'set' : 'cleared'} (RFC 1142 7.3.19.1)") if @generated_at
    end

    # The default metric's ATT bit, in LSP Number 0. Set by the Level 2
    # Decision Process of a system at both levels on its Level 1
    # originator. Clause 7.2.9.2: a Level 2 system that "can reach at least
    # one other area" shall "set AttachedFlag for metric k to True" and
    # "regenerate its Level 1 LSP with LSP number zero", and one that
    # "cannot reach any other areas" sets it to False and regenerates the
    # same. Only the default metric is computed, so only its bit is set.
    def attached=(on)
      @attached = on
      changed("AttachedFlag #{on ? 'set' : 'cleared'} (RFC 1142 7.2.9.2)") if @generated_at
    end

    # TLVs a test or the simulator puts in this system's LSPs on purpose,
    # wrong ones included (ISIS::Fault): a Router Capability among them
    # takes the place of this system's own, and the others follow its
    # reachability. [] takes them out. Generated again as any change is.
    # Never set by ordinary origination (CLAUDE.md, "Ordinary production and
    # deliberate overrides").
    def inject(tlvs, reason)
      @injected = tlvs.dup.freeze
      changed(reason)
    end

    # Clause 7.3.6: an event "which would cause the information content to
    # change". The LSPs whose content did change are generated again, when
    # the generation timer allows: by default not sooner than
    # minimumLSPGenerationInterval after the last one, "A source
    # Intermediate system shall wait at least this long before
    # re-generating one of its own Link State PDUs" (7.3.21), per LSP
    # Number (7.3.4). Changes while one waits go with it.
    def changed(reason)
      return if @pending

      @since ||= @scheduler.now
      attempt(reason)
    end

    # Clause 7.3.5: regenerate "at intervals of at most
    # maximumLSPGenerationInterval seconds", content changed or not. The
    # jitter clause 10.1 asks for is not applied yet.
    def refresh
      generate("refresh, #{@refresh_interval} s since the last (RFC 1142 7.3.5)", event: false)
    end

    # A received LSP with this system's ID that it still generates, clause
    # 7.3.15.1 d. Returns what was done.
    #
    # Newer than ours, clause 7.3.16.1: "it shall change its sequence number
    # to be the next number greater than the new one received, and shall
    # generate a link state PDU". The same sequence with another checksum,
    # clause 7.3.16.2: "change the LSP's sequence number to be the next
    # number greater than that of the received LSP and regenerate". Both
    # go out at once, without the minimum interval's wait.
    def receive_own(result, lsp)
      return result unless %i[newer confused].include?(result)

      number = lsp.lsp_id.getbyte(-1)
      @sequences[number] = [lsp.sequence, @sequences[number]].max
      generate("received #{lsp_id_s(number)} with sequence #{seq(lsp.sequence)} " \
               "(RFC 1142 #{result == :newer ? '7.3.16.1' : '7.3.16.2'})", only: number, event: false)
      :regenerated
    end

    private

    # Generate the LSPs a change touched, or wait for the latest of their
    # times, so LSPs an entry moved between still go out together (7.3.4).
    # When the wait is over, look again: what changed meanwhile may wait
    # longer.
    def attempt(reason)
      groups = lsp_tlvs
      numbers = (0...groups.size).reject { |n| unchanged?(n, groups[n]) }
      now = @scheduler.now
      wait = numbers.map { |n| @generation_timer.wait(n, now: now, since: @since) }.max
      if wait&.positive?
        @log.debug("#{lsp_id_s}: #{reason}; generating in #{wait.round(3)} s (#{timer_text})")
        @pending = @scheduler.after(wait) do
          @pending = nil
          attempt(reason)
        end
        return
      end

      @since = nil
      generate(reason, unless_unchanged: true, event: true)
    end

    def timer_text
      case @generation_timer
      when GenerationTimer::Fixed then "the minimum interval, RFC 1142 7.3.21"
      when GenerationTimer::Backoff then "the backoff"
      else @generation_timer.class.name
      end
    end

    # Whether LSP Number +n+, built from +tlvs+ now, says what the one held
    # says.
    def unchanged?(n, tlvs)
      held = @database[lsp_id(n)]
      held&.lsp && !held.purged? && same_content?(held.lsp, build(sequence: 0, number: n, tlvs: tlvs))
    end

    # The TLVs that open LSP Number 0 and only it: TLV 1, which "shall occur
    # only in the LSP with LSP Number zero" (7.3.4), and TLVs 129, 137, 132
    # and 232. RFC 5301 allows TLV 137 in any LSP Number; LSP 0 is our
    # choice.
    def fixed_tlvs
      list = [Tlv::AreaAddresses.new(area_addresses.map(&:to_s)), Tlv::ProtocolsSupported.new(@protocols)]
      list << Tlv::DynamicHostname.new(@hostname) if @hostname
      list << Tlv::IpInterfaceAddresses.new(@ip_addresses) unless @ip_addresses.empty?
      list << Tlv::Ipv6InterfaceAddresses.new(@ipv6_addresses) unless @ipv6_addresses.empty?
      if injected_capability?
        list.concat(@injected.select { |t| t.is_a?(Tlv::RouterCapability) })
      elsif @segment_routing && @flex_algo
        list.concat(@segment_routing.capabilities(algorithms: @flex_algo.participating, fads: @flex_algo.fads))
      elsif @segment_routing
        list << @segment_routing.capability
      end
      list
    end

    def injected_capability?
      (@injected || []).any? { |t| t.is_a?(Tlv::RouterCapability) }
    end

    # The reachability TLVs, IS neighbours before IP prefixes (7.3.4 b, c).
    # With segment routing, each neighbour carries its Adj-SIDs as a fourth
    # element: a point to point neighbour its own (RFC 8667 section 2.2.1),
    # the entry to a LAN's pseudonode one LAN-Adj-SID per neighbour Up on
    # that LAN (section 2.2.2).
    # Each carries its link attributes as a fifth (Router#link_attributes).
    def variable_tlvs
      neighbors = @circuits.filter_map do |c|
        n = c.is_neighbor or next
        # [ID, metric, addresses]; a simulated link answers without addresses.
        attributes = @link_attributes.empty? ? nil : @link_attributes[circuit_name(c)]
        [n[0], n[1], n[2], @segment_routing ? adj_sids(c, n.first) : nil, attributes]
      end
      reachability(neighbors, @prefixes, @external_prefixes, @leaked_prefixes, @area_prefixes) +
        (@injected || []).reject { |t| t.is_a?(Tlv::RouterCapability) }
    end

    # A LAN circuit answers its name; a point to point level, its circuit's.
    def circuit_name(circuit)
      circuit.respond_to?(:name) ? circuit.name : circuit.circuit.name
    end

    def adj_sids(circuit, id)
      name = circuit_name(circuit)
      if id.getbyte(-1).zero?
        @segment_routing.adj_sids(name, id.byteslice(0, 6))
      else
        @segment_routing.lan_adj_sids(name, circuit.up_neighbors.map { |n| n.system_id.b })
      end
    end

    # A prefix as TLV 135 or 236 takes it: its prefix and metric, and with
    # segment routing the Prefix-SID its configuration gives.
    # With flex-algo, a Prefix-SID too for each algorithm this system
    # takes part in that the prefix's algorithm_sids names.
    def own_prefix(p)
      h = p.slice(:prefix, :metric)
      return h unless @segment_routing

      sids = SegmentRouting.prefix_sids(p, @flex_algo ? @flex_algo.participating : [])
      sids.empty? ? h : h.merge(subtlvs: sids)
    end

    # A prefix from the other level with the Prefix-SID its route came
    # with, propagated as RFC 8667 section 2.1.2 says.
    def carried(p, h)
      sid = @segment_routing && SegmentRouting.propagated_sid(p[:sid])
      sid ? h.merge(subtlvs: [sid]) : h
    end

    # The IS and IP reachability TLVs for +neighbors+, [ID, metric] pairs,
    # and +prefixes+, then +externals+, then +leaked+, then +area+, in the
    # metric style.
    def reachability(neighbors, prefixes, externals = [], leaked = [], area = [])
      list = []
      leaked6, leaked4 = leaked.partition { |p| p.fetch(:prefix).include?(":") }
      area6, area4 = area.partition { |p| p.fetch(:prefix).include?(":") }
      externals6, externals = externals.partition { |p| p.fetch(:prefix).include?(":") }
      capped = ->(p) { p.slice(:prefix, :metric).merge(metric: [p.fetch(:metric), Tlv::NarrowMetrics::VALUE].min) }
      down = ->(p) { carried(p, p.slice(:prefix, :metric).merge(up_down: true)) }
      across = ->(p) { carried(p, p.slice(:prefix, :metric)) }
      narrow_down = ->(p) { capped.call(p).merge(up_down: true) }
      if @metric_style != :wide
        # The Virtual Flag takes the first octet of each TLV 2's value, and
        # this system writes 0 at either level, since it does not repair
        # partitions (RFC 1142 9.8, 9.9).
        narrow = neighbors.map do |id, metric|
          metrics = Tlv::NarrowMetrics.build(metric: metric, ie_octets: Tlv::IsReachability::IE_OCTETS)
          Tlv::IsReachability::Entry.new(metrics: metrics, neighbor: id)
        end
        list.concat(pack(Tlv::IsReachability, narrow, overhead: 1))
        internal = prefixes.map { |p| p.slice(:prefix, :metric) } + leaked4.reject { |p| p[:external] }.map(&narrow_down) +
                   area4.reject { |p| p[:external] }.map(&capped)
        reach = internal.map { |p| Tlv::IpInternalReachability.new(p).entries.first }
        list.concat(pack(Tlv::IpInternalReachability, reach))
        external = externals + leaked4.select { |p| p[:external] }.map { |p| narrow_down.call(p).merge(external: true) } +
                   area4.select { |p| p[:external] }.map { |p| capped.call(p).merge(external: true) }
        reach = external.map { |p| Tlv::IpExternalReachability.new(p).entries.first }
        list.concat(pack(Tlv::IpExternalReachability, reach))
      end
      if @metric_style != :narrow
        wide = neighbors.map do |id, metric, addresses, sids, attributes|
          Tlv::ExtendedIsReachability::Entry.new(neighbor: id, metric: metric,
                                                 subtlvs: link_subtlvs(addresses, sids, attributes))
        end
        list.concat(pack(Tlv::ExtendedIsReachability, wide))
        list.concat(asla_srlgs(neighbors))
        reach = (prefixes.map { |p| own_prefix(p) } + externals.map { |p| p.slice(:prefix, :metric) } + leaked4.map(&down) +
                 area4.map(&across)).map do |p|
          Tlv::ExtendedIpReachability.new(p).entries.first
        end
        list.concat(pack(Tlv::ExtendedIpReachability, reach))
      end
      reach6 = (@ipv6_prefixes.map { |p| own_prefix(p) } + externals6.map { |p| p.slice(:prefix, :metric).merge(external: true) } +
                leaked6.map(&down) + area6.map(&across)).map do |p|
        Tlv::Ipv6Reachability.new(p).entries.first
      end
      list.concat(pack(Tlv::Ipv6Reachability, reach6))
      list
    end

    # TLV 22 sub-TLVs 6 and 8 for a circuit's link addresses, { interface:,
    # neighbor: }, either may be absent (RFC 5305 sections 3.2 and 3.3),
    # then the Adj-SIDs, hashes keyed as a sub-TLV list keys them, then the
    # link's attributes for flex-algo.
    def link_subtlvs(addresses, sids = nil, attributes = nil)
      list = SubTlv::List.new(Tlv::ExtendedIsReachability::TYPE)
      if addresses
        list << SubTlv::Ipv4InterfaceAddress.new(addresses[:interface]) if addresses[:interface]
        list << SubTlv::Ipv4NeighborAddress.new(addresses[:neighbor]) if addresses[:neighbor]
      end
      Array(sids).each do |h|
        key, value = h.first
        list << SubTlv.key_under(Tlv::ExtendedIsReachability::TYPE, key).new(value)
      end
      asla = self.class.asla(attributes)
      list << asla if asla
      list
    end

    # The ASLA sub-TLV for a link's +attributes+, or nil when it has none
    # but SRLGs. RFC 9350 section 12: flex-algo's link attributes "MUST
    # use" ASLA; the X bit alone, L clear. RFC 9479 section 6.1: a new
    # application "MUST NOT make use of legacy advertisements", so none are
    # sent (decision 4). Affinity goes as an Extended Admin Group, as long
    # as its highest group needs. The delay goes as RFC 9350's metric type
    # 1 reads it, Min/Max (34), min and max the same, and as the average
    # (33), as FRR 10.7.1 sends a link with "delay N min N max N". The EAG
    # takes the fewest words its highest group needs.
    def self.asla(attributes)
      a = attributes or return nil
      subs = []
      subs << SubTlv::ExtendedAdminGroup.new(groups: a[:affinity]) if a[:affinity]
      subs << SubTlv::TeDefaultMetric.new(metric: a[:te_metric]) if a[:te_metric]
      if a[:delay]
        subs << SubTlv::LinkDelay.new(delay: a[:delay])
        subs << SubTlv::MinMaxLinkDelay.new(min: a[:delay], max: a[:delay])
      end
      return nil if subs.empty?

      SubTlv::Asla.new(applications: %w[X], subtlvs: subs)
    end

    # TLV 238 for each neighbour whose link has SRLGs: the X bit, the link
    # named by its IPv4 addresses (RFC 9479 section 4.3's Table 2, 6 and
    # 8), as many TLVs as the SRLGs need. A link without an IPv4 address
    # cannot be named this way and gets none; Router refuses srlg without
    # ip_addresses.
    def asla_srlgs(neighbors)
      neighbors.flat_map do |id, _metric, addresses, _sids, attributes|
        srlgs = attributes && attributes[:srlg]
        next [] if srlgs.nil? || srlgs.empty? || addresses.nil? || addresses[:interface].nil?

        links = [{ ipv4_interface_address: addresses[:interface] }]
        links << { ipv4_neighbor_address: addresses[:neighbor] } if addresses[:neighbor]
        fixed = Tlv::AslaSrlg.new(neighbor: neighbor_text(id), applications: %w[X], links: links).encode.bytesize - 2
        srlgs.each_slice((255 - fixed) / 4).map do |slice|
          Tlv::AslaSrlg.new(neighbor: neighbor_text(id), applications: %w[X], links: links, srlgs: slice)
        end
      end
    end

    def neighbor_text(id)
      hex = id.unpack1("H*")
      "#{hex[0, 12].scan(/.{4}/).join('.')}.#{hex[12, 2]}"
    end

    # Generate the LSP Numbers whose content changed, or with
    # unless_unchanged false all of them, or with +only+ just that one.
    # Every LSP is stored before any SRM flag is set, so two LSPs an entry
    # moved between go out together (7.3.4: "the SRMflags ... for the two
    # new LSPs shall be set as an atomic action"). Returns the LSP Number 0
    # generated, or the first, or nil.
    def generate(reason, unless_unchanged: false, only: nil, event: true)
      groups = lsp_tlvs
      wanted = (0...groups.size).to_a
      numbers = only ? [only] & wanted : wanted
      generated = numbers.filter_map do |n|
        next if unless_unchanged && unchanged?(n, groups[n])

        held = @database[lsp_id(n)]

        lsp = build(sequence: @sequences[n] + 1, number: n, tlvs: groups[n])
        size = lsp.encode.bytesize
        raise Error, "#{lsp_id_s(n)} is #{size} octets, over the #{@buffer_size} octet budget" if size > @buffer_size

        @sequences[n] = lsp.sequence
        # A refresh is marked, so a viewer can leave it out.
        refresh = held&.lsp && !held.purged? && same_content?(held.lsp, lsp) ? { refresh: true } : {}
        @log.info("#{lsp_id_s(n)} sequence #{seq(lsp.sequence)} generated: #{reason}", kind: :origination,
                                                                                       lsp_id: lsp_id_s(n),
                                                                                       sequence: lsp.sequence, **refresh)
        @generation_timer.generated(n, now: @scheduler.now, event: event)
        @database.entry(lsp_id(n)).store(lsp)
      end
      stale = only ? [] : @numbers - wanted
      @numbers = wanted unless only
      stale.each do |n|
        held = @database[lsp_id(n)]
        next if held.nil? || held.placeholder? || held.remaining_lifetime.zero?

        @database.purge(held, "LSP Number #{n} is no longer needed (RFC 1142 7.3.4)", retain: Database::MAX_AGE)
      end
      if generated.empty?
        @log.debug("#{lsp_id_s}: #{reason}; content unchanged, not generated (RFC 1142 7.3.6)") if stale.empty?
        return nil
      end

      @generated_at = @scheduler.now
      # Clause 7.3.6: "propagate the LSP(s) on every circuit by setting
      # SRMflag for each circuit". Each circuit sets it only with an
      # adjacency up, as clause 7.3.5 asks.
      generated.each { |entry| @circuits.each { |c| c.flood(entry) } }
      schedule_refresh
      generated.first.lsp
    end

    # Clause 7.3.6: "The timer maximumLSPGenerationInterval shall not be
    # reset" by an event, so only the first generation and a refresh set it.
    def schedule_refresh
      return if @refresh_timer && !@refreshing

      @refresh_timer = @scheduler.after(@refresh_interval) do
        @refreshing = true
        refresh
        @refreshing = false
      end
    end

    # Entries into TLVs of +klass+, as many to a TLV as fit in 255 octets
    # of value. Each entry is encoded once and measured.
    def pack(klass, entries, overhead: 0)
      groups = []
      size = 0
      entries.each do |e|
        n = e.encode.bytesize
        if groups.empty? || size + n > 255 - overhead
          groups << []
          size = 0
        end
        groups.last << e
        size += n
      end
      groups.map { |g| klass.new(g) }
    end

    def same_content?(held, fresh) = Database.same_content?(held, fresh)

    def seq(n)
      format("0x%08x", n)
    end
  end
end
