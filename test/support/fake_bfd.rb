# frozen_string_literal: true

# A BFD::Client for tests (bfd4r bfd/client.rb): the same methods and the
# same events, with no bfdd4r. A test says what a session does with #tell,
# and what bfdd4r does with #lose and #connect; the next poll returns it,
# as the real client does.
class FakeBfd
  # BFD::Client::Event's fields and predicates, copied so the unit tests
  # need no bfd4r.
  Event = Struct.new(:type, :interface, :peer, :state, :from, :diag, :message, keyword_init: true) do
    def up? = type == :state && state == :up
    def failure? = type == :state && from == :up && state == :down
  end

  attr_reader :wanted, :calls, :polls

  def initialize(connected: true)
    @connected = connected
    @wanted = {}
    @states = {}
    @queue = []
    @calls = []
    @polls = 0
  end

  def want(interface:, peer:, local:, **_timers)
    @calls << [:want, interface, peer, local]
    @wanted[[interface, peer]] = local
    self
  end

  def drop(interface:, peer:)
    @calls << [:drop, interface, peer]
    @wanted.delete([interface, peer])
    @states.delete([interface, peer])
    self
  end

  def wanted?(interface:, peer:) = @wanted.key?([interface, peer])
  def state(interface:, peer:) = @states[[interface, peer]]
  def connected? = @connected

  def poll(_now)
    @polls += 1
    out = @queue
    @queue = []
    out
  end

  def close(release: false)
    @calls << [:close, release]
    nil
  end

  # The session to +peer+ on +interface+ is now +state+. Told only when
  # wanted, as BFD::Client tells only the sessions its router wants.
  def tell(interface, peer, state, diag: nil)
    key = [interface, peer]
    return unless @wanted.key?(key)

    from = @states[key]
    return if from == state

    @states[key] = state
    @queue << Event.new(type: :state, interface: interface, peer: peer, state: state, from: from, diag: diag)
  end

  # Every wanted session is now +state+.
  def tell_all(state)
    @wanted.each_key { |(i, p)| tell(i, p, state) }
  end

  def lose
    @connected = false
    @states.clear
    @queue << Event.new(type: :lost, message: "no bfdd4r")
  end

  def connect
    @connected = true
    @queue << Event.new(type: :connected, message: "bfdd4r answers")
  end
end
