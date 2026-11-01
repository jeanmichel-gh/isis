# frozen_string_literal: true

module ISIS
  # One neighbor relationship on a circuit.
  #
  # State follows the IS-IS LAN handshake:
  #   :down  no Hello heard (not represented here; absence means down)
  #   :init  we heard the neighbor, but it has not yet listed us in its
  #          IS Neighbors TLV, so it may not have heard us
  #   :up    the neighbor lists our SNPA, so the link is two-way
  #
  # Times come from the injected clock, never from the system's, so a test
  # can expire an adjacency by advancing a ManualClock.
  class Adjacency
    attr_accessor :system_id, :snpa, :state, :holding_time, :last_seen
    attr_reader :clock

    def initialize(system_id:, snpa:, state:, holding_time:, clock:)
      @system_id = system_id
      @snpa = snpa
      @state = state
      @holding_time = holding_time
      @clock = clock
      touch
    end

    def touch
      @last_seen = @clock.now
    end

    # True once more than the holding time has passed since the last hello.
    def expired?(at = @clock.now)
      at - @last_seen > @holding_time
    end

    def up?
      @state == :up
    end

    def to_s
      "#{@system_id} #{@state} via #{@snpa}"
    end
  end
end
