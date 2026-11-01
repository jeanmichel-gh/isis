# frozen_string_literal: true

module ISIS
  # This system's Level 1 LSP: built from configuration and from the
  # circuits' adjacencies, stored in the database, and flooded by setting
  # SRM on every circuit with an adjacency up. RFC 1142 clauses 7.3.5 to
  # 7.3.7 and 7.3.16.1 to 7.3.16.3.
  #
  # One LSP, LSP Number 0, non-pseudonode. What it carries, after clause
  # 7.3.7 and RFC 1195:
  #
  #   TLV 1    the manual area addresses
  #   TLV 129  the protocols supported
  #   TLV 132  the IP interface addresses, when there are any
  #   TLV 22   one entry per adjacency Up, the neighbour's System ID with
  #            "an appended zero octet (indicating non-pseudonode)"
  #            (7.3.7), at the circuit's metric
  #   TLV 135  the configured prefixes
  #
  # Wide metrics only: no TLV 2 or 128 yet. More than fits in one LSP
  # raises rather than going out as a second LSP Number, which is not here
  # yet.
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

    attr_reader :system_id, :database, :sequence, :circuits, :lsp_id
    attr_accessor :areas, :protocols, :ip_addresses, :prefixes

    def initialize(system_id:, database:, scheduler:, log:, areas: ["49.0001"], protocols: [:ipv4],
                   ip_addresses: [], prefixes: [],
                   refresh_interval: MAXIMUM_LSP_GENERATION_INTERVAL,
                   minimum_interval: MINIMUM_LSP_GENERATION_INTERVAL,
                   buffer_size: LSP_BUFFER_SIZE)
      @system_id = Pdu.dotted_octets(system_id)
      @lsp_id = (@system_id + "\x00\x00".b).b
      @database = database
      @scheduler = scheduler
      @log = log
      @areas = areas
      @protocols = protocols
      @ip_addresses = ip_addresses
      @prefixes = prefixes
      @refresh_interval = refresh_interval
      @minimum_interval = minimum_interval
      @buffer_size = buffer_size
      @circuits = []
      # Clause 7.3.16.1: "When a system initialises, it shall start with
      # sequence number 1". The first generation adds one to this.
      @sequence = 0
      @generated_at = nil
      @pending = nil
      @refresh_timer = nil
    end

    # A circuit whose adjacency goes into TLV 22 and which floods the LSP.
    # It answers is_neighbor (nil, or the neighbour ID and metric) and
    # flood(entry).
    def attach(circuit)
      @circuits << circuit unless @circuits.include?(circuit)
      self
    end

    def lsp_id_s
      Pdu.lsp_id_s(@lsp_id)
    end

    # Generate the first LSP and start the refresh timer.
    def start
      generate("initialisation (RFC 1142 7.3.16.1)")
      self
    end

    def stop
      [@refresh_timer, @pending].each { |t| t&.cancel }
      @refresh_timer = @pending = nil
      self
    end

    # True for an LSP ID this system currently generates: clause 7.3.15.1
    # d's "set of currently generated LSPs".
    def generates?(lsp_id)
      lsp_id.b == @lsp_id
    end

    # The LSP this system would send now with +sequence+. Builds and does
    # nothing else.
    def build(sequence: @sequence)
      Pdu::Lsp.new(level: 1, lsp_id: Octets.new(@lsp_id), lifetime: Database::MAX_AGE, sequence: sequence,
                   tlvs: tlvs)
    end

    # The TLVs, packed: entries into as many TLVs of one type as their
    # encoded size needs, each at most 255 octets of value.
    def tlvs
      list = [Tlv::AreaAddresses.new(@areas), Tlv::ProtocolsSupported.new(@protocols)]
      list << Tlv::IpInterfaceAddresses.new(@ip_addresses) unless @ip_addresses.empty?
      neighbors = @circuits.filter_map(&:is_neighbor).map do |id, metric|
        Tlv::ExtendedIsReachability::Entry.new(neighbor: id, metric: metric)
      end
      list.concat(pack(Tlv::ExtendedIsReachability, neighbors))
      reach = @prefixes.map { |p| Tlv::ExtendedIpReachability.new(p).entries.first }
      list.concat(pack(Tlv::ExtendedIpReachability, reach))
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
        @log.debug("#{lsp_id_s}: #{reason}; generating in #{wait.round(1)} s, the minimum interval (RFC 1142 7.3.21)")
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

      @pending&.cancel
      @pending = nil
      @sequence = [lsp.sequence, @sequence].max
      generate("received #{lsp_id_s} with sequence #{seq(lsp.sequence)} " \
               "(RFC 1142 #{result == :newer ? '7.3.16.1' : '7.3.16.2'})")
      :regenerated
    end

    private

    def generate(reason, unless_unchanged: false)
      held = @database[@lsp_id]
      if unless_unchanged && held&.lsp && held.lsp.tlvs.to_shex == Tlv::List.new(tlvs).to_shex
        @log.debug("#{lsp_id_s}: #{reason}; content unchanged, not generated (RFC 1142 7.3.6)")
        return nil
      end

      lsp = build(sequence: @sequence + 1)
      size = lsp.encode.bytesize
      raise Error, "#{lsp_id_s} is #{size} octets, over the #{@buffer_size} octet budget" if size > @buffer_size

      @sequence = lsp.sequence
      entry = @database.entry(@lsp_id).store(lsp)
      @generated_at = @scheduler.now
      @log.info("#{lsp_id_s} sequence #{seq(@sequence)} generated: #{reason}", kind: :origination,
                                                                                lsp_id: lsp_id_s, sequence: @sequence)
      # Clause 7.3.6: "propagate the LSP(s) on every circuit by setting
      # SRMflag for each circuit". Each circuit sets it only with an
      # adjacency up, as clause 7.3.5 asks.
      @circuits.each { |c| c.flood(entry) }
      schedule_refresh
      lsp
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
    def pack(klass, entries)
      groups = []
      size = 0
      entries.each do |e|
        n = e.encode.bytesize
        if groups.empty? || size + n > 255
          groups << []
          size = 0
        end
        groups.last << e
        size += n
      end
      groups.map { |g| klass.new(g) }
    end

    def seq(n)
      format("0x%08x", n)
    end
  end
end
