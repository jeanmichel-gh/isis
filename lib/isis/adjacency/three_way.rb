# frozen_string_literal: true

module ISIS
  class Adjacency
    # The RFC 5303 section 3.2 adjacency three-way state table, as data.
    # Rows are this system's current three-way state for the adjacency,
    # columns the Adjacency Three-Way State the neighbour sent in TLV 240:
    #
    #                    received Down   Initializing   Up
    #   current Down     Initialize      Up             Down
    #   current Init     Initialize      Up             Up
    #   current Up       Initialize      Accept         Accept
    #
    # Its verified errata renumber the ISO clauses the RFC cites and leave
    # this table as it was. The actions, from the same section:
    #
    # * :down deletes the adjacency, an adjacencyStateChange(Down) with the
    #   reason "Neighbor restarted";
    # * :initialize sets the three-way state to Initializing, no event;
    # * :up sets it to Up, an adjacencyStateChange(Up);
    # * :accept changes nothing.
    module ThreeWay
      TABLE = {
        down: { down: :initialize, initializing: :up, up: :down },
        initializing: { down: :initialize, initializing: :up, up: :up },
        up: { down: :initialize, initializing: :accept, up: :accept }
      }.freeze

      # The state the adjacency is in after +action+ from +current+, or nil
      # when the action deletes it.
      RESULT = { initialize: :initializing, up: :up, down: nil }.freeze

      module_function

      # The action for a +current+ state and a +received+ state.
      def action(current, received)
        TABLE.fetch(current) { raise ArgumentError, "no three-way state #{current.inspect}" }
             .fetch(received) { raise ArgumentError, "no three-way state #{received.inspect}" }
      end

      # The state after +action+, from +current+.
      def after(action, current)
        action == :accept ? current : RESULT.fetch(action)
      end
    end
  end
end
