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
  #   TLV 132  the IP interface addresses, when there are any
  #   TLV 22   one entry per circuit's is_neighbor: on a point to point
  #            circuit with an adjacency Up, the neighbour's System ID
  #            with "an appended zero octet (indicating non-pseudonode)",
  #            and on a LAN with a DIS, the DIS's LAN ID, the pseudonode
  #            (7.3.7); at the circuit's metric
  #   TLV 135  the configured prefixes
  #
  # That is metric_style :wide, the default. :narrow sends TLV 2 and TLV
  # 128 in place of 22 and 135, with only the default metric supported,
  # and :transition sends all four, as a router moving between the two
  # does. A metric too large for the narrow six bits raises.
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

    attr_reader :system_id, :database, :circuits, :refresh_interval, :minimum_interval, :buffer_size, :numbers
    METRIC_STYLES = %i[wide narrow transition].freeze

    attr_accessor :areas, :protocols, :ip_addresses, :prefixes, :metric_style, :area_key, :is_type
    attr_reader :overload

    def initialize(system_id:, database:, scheduler:, log:, areas: ["49.0001"], protocols: [:ipv4],
                   ip_addresses: [], prefixes: [], metric_style: :wide, area_key: nil,
                   refresh_interval: MAXIMUM_LSP_GENERATION_INTERVAL,
                   minimum_interval: MINIMUM_LSP_GENERATION_INTERVAL,
                   buffer_size: LSP_BUFFER_SIZE, is_type: nil, level1_database: nil, overload: false)
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
      @ip_addresses = ip_addresses
      @prefixes = prefixes
      raise ArgumentError, "metric style is :wide, :narrow or :transition" unless METRIC_STYLES.include?(metric_style)

      @metric_style = metric_style
      @area_key = area_key
      @refresh_interval = refresh_interval
      @minimum_interval = minimum_interval
      @buffer_size = buffer_size
      @level1_database = level1_database
      @overload = overload
      @circuits = []
      # Clause 7.3.16.1: "When a system initialises, it shall start with
      # sequence number 1". The first generation adds one to this, per LSP
      # Number.
      @sequences = Hash.new(0)
      # The LSP Numbers generated now.
      @numbers = []
      @generated_at = nil
      @pending = nil
      @refresh_timer = nil
      @started = false
      @union = nil
      level1_database&.listen(self)
    end

    # A circuit whose adjacency goes into TLV 22 and which floods the LSP.
    # It answers is_neighbor (nil, or the neighbour ID and metric) and
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
      generate("initialisation (RFC 1142 7.3.16.1)")
      self
    end

    def stop
      [@refresh_timer, @pending].each { |t| t&.cancel }
      @refresh_timer = @pending = nil
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
      lsp = Pdu::Lsp.new(level: level, lsp_id: Octets.new(lsp_id(number)), lifetime: Database::MAX_AGE,
                         sequence: sequence, tlvs: list, is_type: @is_type, overload: @overload && number.zero?)
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
    def overload=(on)
      @overload = on
      changed("LSP Database Overload bit #{on ? 'set' : 'cleared'} (RFC 1142 7.3.19.1)") if @generated_at
    end

    # Clause 7.3.6: an event "which would cause the information content to
    # change". The LSP is generated again if its content did change, but
    # not sooner than minimumLSPGenerationInterval after the last one: "A
    # source Intermediate system shall wait at least this long before
    # re-generating one of its own Link State PDUs" (7.3.21).
    def changed(reason)
      return if @pending

      wait = @generated_at ? @generated_at + @minimum_interval - @scheduler.now : 0
      if wait.positive?
        @log.debug("#{lsp_id_s}: #{reason}; generating in #{wait.round(1)} s, the minimum interval " \
                   "(RFC 1142 7.3.21)")
        @pending = @scheduler.after(wait) do
          @pending = nil
          generate(reason, unless_unchanged: true)
        end
      else
        generate(reason, unless_unchanged: true)
      end
    end

    # Clause 7.3.5: regenerate "at intervals of at most
    # maximumLSPGenerationInterval seconds", content changed or not. The
    # jitter clause 10.1 asks for is not applied yet.
    def refresh
      generate("refresh, #{@refresh_interval} s since the last (RFC 1142 7.3.5)")
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
               "(RFC 1142 #{result == :newer ? '7.3.16.1' : '7.3.16.2'})", only: number)
      :regenerated
    end

    private

    # The TLVs that open LSP Number 0 and only it: TLV 1, which "shall occur
    # only in the LSP with LSP Number zero" (7.3.4), and TLVs 129 and 132.
    def fixed_tlvs
      list = [Tlv::AreaAddresses.new(area_addresses.map(&:to_s)), Tlv::ProtocolsSupported.new(@protocols)]
      list << Tlv::IpInterfaceAddresses.new(@ip_addresses) unless @ip_addresses.empty?
      list
    end

    # The reachability TLVs, IS neighbours before IP prefixes (7.3.4 b, c).
    def variable_tlvs
      reachability(@circuits.filter_map(&:is_neighbor), @prefixes)
    end

    # The IS and IP reachability TLVs for +neighbors+, [ID, metric] pairs,
    # and +prefixes+, in the metric style.
    def reachability(neighbors, prefixes)
      list = []
      if @metric_style != :wide
        # The Virtual Flag takes the first octet of each TLV 2's value, and
        # this system writes 0 at either level, since it does not repair
        # partitions (RFC 1142 9.8, 9.9).
        narrow = neighbors.map do |id, metric|
          metrics = Tlv::NarrowMetrics.build(metric: metric, ie_octets: Tlv::IsReachability::IE_OCTETS)
          Tlv::IsReachability::Entry.new(metrics: metrics, neighbor: id)
        end
        list.concat(pack(Tlv::IsReachability, narrow, overhead: 1))
        reach = prefixes.map { |p| Tlv::IpInternalReachability.new(p).entries.first }
        list.concat(pack(Tlv::IpInternalReachability, reach))
      end
      if @metric_style != :narrow
        wide = neighbors.map { |id, metric| Tlv::ExtendedIsReachability::Entry.new(neighbor: id, metric: metric) }
        list.concat(pack(Tlv::ExtendedIsReachability, wide))
        reach = prefixes.map { |p| Tlv::ExtendedIpReachability.new(p).entries.first }
        list.concat(pack(Tlv::ExtendedIpReachability, reach))
      end
      list
    end

    # Generate the LSP Numbers whose content changed, or with
    # unless_unchanged false all of them, or with +only+ just that one.
    # Every LSP is stored before any SRM flag is set, so two LSPs an entry
    # moved between go out together (7.3.4: "the SRMflags ... for the two
    # new LSPs shall be set as an atomic action"). Returns the LSP Number 0
    # generated, or the first, or nil.
    def generate(reason, unless_unchanged: false, only: nil)
      groups = lsp_tlvs
      wanted = (0...groups.size).to_a
      numbers = only ? [only] & wanted : wanted
      generated = numbers.filter_map do |n|
        held = @database[lsp_id(n)]
        if unless_unchanged && held&.lsp && !held.purged? &&
           same_content?(held.lsp, build(sequence: 0, number: n, tlvs: groups[n]))
          next
        end

        lsp = build(sequence: @sequences[n] + 1, number: n, tlvs: groups[n])
        size = lsp.encode.bytesize
        raise Error, "#{lsp_id_s(n)} is #{size} octets, over the #{@buffer_size} octet budget" if size > @buffer_size

        @sequences[n] = lsp.sequence
        @log.info("#{lsp_id_s(n)} sequence #{seq(lsp.sequence)} generated: #{reason}", kind: :origination,
                                                                                       lsp_id: lsp_id_s(n),
                                                                                       sequence: lsp.sequence)
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

    # The same TLVs and flags: what a regeneration would change.
    def same_content?(held, fresh)
      held.flags == fresh.flags && held.tlvs.to_shex == fresh.tlvs.to_shex
    end

    def seq(n)
      format("0x%08x", n)
    end
  end
end
