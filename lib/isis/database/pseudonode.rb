# frozen_string_literal: true

module ISIS
  # The Level 1 pseudonode LSP this system generates for a LAN circuit
  # while it is the circuit's DIS. RFC 1142 clause 7.3.8.
  #
  # Its LSP ID is the circuit's own LAN ID, this system's ID and the Local
  # Circuit ID, with LSP Number 0. What it carries, after the clause:
  #
  #   no TLV 1   "The Area Addresses option is not present."
  #   TLV 22     "The Designated Intermediate System's own systemID with an
  #              appended zero octet", and the same for each adjacency Up
  #              on the circuit, "a value of zero ... for all supported
  #              routeing metrics"
  #
  # TLV 2 in place of TLV 22, or both, as the metric style says, the same
  # as for this system's own LSP. With an area key, TLV 10 goes first
  # (7.3.8, "In the Authentication Information field"). No End System
  # Neighbours: this system makes no adjacencies with end systems.
  #
  # Generation follows Originator's rules: refreshed every
  # maximumLSPGenerationInterval, generated again on a change no sooner
  # than minimumLSPGenerationInterval, and moved past a newer copy of
  # itself. start is becoming DIS and stop is resigning, which purges the
  # LSP network wide (7.2.3). After stop, this system no longer generates
  # it (7.3.15.1 c).
  class Pseudonode < Originator
    attr_reader :circuit

    def initialize(circuit:, database:, scheduler:, log:, metric_style: :wide, area_key: nil,
                   refresh_interval: MAXIMUM_LSP_GENERATION_INTERVAL,
                   minimum_interval: MINIMUM_LSP_GENERATION_INTERVAL, buffer_size: LSP_BUFFER_SIZE, is_type: nil)
      super(system_id: circuit.system_id.unpack1("H*"), database: database, scheduler: scheduler, log: log, areas: [],
            protocols: [], metric_style: metric_style, area_key: area_key, refresh_interval: refresh_interval,
            minimum_interval: minimum_interval, buffer_size: buffer_size, is_type: is_type)
      @circuit = circuit
      @lsp_id = (circuit.own_lan_id + "\x00".b).b
      @active = false
      attach(circuit)
    end

    def active?
      @active
    end

    # This system became DIS: generate now.
    def start
      @active = true
      generate("this system is DIS on #{@circuit.name} (RFC 1142 7.3.8)")
      self
    end

    # This system resigned as DIS: "it shall initiate a network wide purge
    # of its pseudonode Link State PDU(s) by setting their Remaining
    # Lifetime to zero" (RFC 1142 7.2.3). The header is kept for
    # MaxAge, as for any purge of an LSP whose lifetime had not run out.
    def stop
      was = @active
      @active = false
      super
      held = @database[@lsp_id]
      if was && held && !held.placeholder? && !held.remaining_lifetime.zero?
        @database.purge(held, "this system resigned as DIS on #{@circuit.name} (RFC 1142 7.2.3)",
                        retain: Database::MAX_AGE)
      end
      self
    end

    def generates?(lsp_id)
      @active && super
    end

    def changed(reason)
      super if @active
    end

    def tlvs
      ids = [@system_id] + @circuit.up_neighbors.map(&:system_id)
      reachability(ids.map { |id| [(id + "\x00".b).b, 0] }, [])
    end
  end
end
