# frozen_string_literal: true

module ISIS
  # One neighbor relationship on a circuit.
  #
  # State follows the IS-IS LAN handshake:
  #   :down  no Hello heard (not represented here; absence means down)
  #   :init  we heard the neighbor, but it has not yet listed us in its
  #          IS Neighbors TLV, so it may not have heard us
  #   :up    the neighbor lists our SNPA, so the link is two-way
  class Adjacency
    attr_accessor :system_id, :snpa, :state, :holding_time, :last_seen

    def initialize(system_id:, snpa:, state:, holding_time:)
      @system_id = system_id
      @snpa = snpa
      @state = state
      @holding_time = holding_time
      touch
    end

    def touch
      @last_seen = now
    end

    def expired?(at = now)
      at - @last_seen > @holding_time
    end

    def up?
      @state == :up
    end

    def to_s
      "#{@system_id} #{@state} via #{@snpa}"
    end

    private

    def now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
