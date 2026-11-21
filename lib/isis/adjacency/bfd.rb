# frozen_string_literal: true

module ISIS
  # BFD for this system's adjacencies: the one mechanism between the
  # circuits and bfdd4r (bfd4r's BFD::Client, routescope
  # docs/design/bfd-clients.md). A circuit with bfd: true asks it for
  # sessions and hears from it when one changes; it asks bfdd4r and tells
  # the circuits. Like every mechanism it is an object a test can replace,
  # and its client is injected: a test hands it a fake one.
  #
  # The client answers want(interface:, peer:, local:), drop(interface:,
  # peer:), state(interface:, peer:), connected? and poll(now), and poll
  # returns events with type, interface, peer, state and failure?, as
  # BFD::Client does.
  #
  # Two circuits may want the same session, a LAN interface at both levels
  # with the same neighbour: the session is let go when the last of them
  # does.
  #
  # Without bfdd4r, the system cannot run BFD, which RFC 5882 4.1 allows: a
  # :lost event tells every circuit, which then stops sending TLV 148, and
  # :connected tells them to start again. bfdd4r going does not take an
  # adjacency down.
  class Bfd
    attr_reader :client, :log

    def initialize(client:, log:)
      @client = client
      @log = log
      @circuits = []
      @holders = {} # [interface, peer] => [circuit, ...]
    end

    def attach(circuit)
      @circuits << circuit unless @circuits.include?(circuit)
      self
    end

    # Whether bfdd4r answers, so this system runs BFD.
    def running? = @client.connected?

    # +holder+ wants the session to +peer+ on +interface+, from +local+.
    def want(holder, interface:, peer:, local:)
      key = [interface, peer]
      holders = (@holders[key] ||= [])
      return if holders.include?(holder)

      holders << holder
      return unless holders.size == 1

      @log.debug("BFD session to #{peer} on #{interface} wanted, from #{local}", circuit: holder.name)
      @client.want(interface: interface, peer: peer, local: local)
    end

    # +holder+ no longer wants it; the last one lets it go.
    def drop(holder, interface:, peer:)
      key = [interface, peer]
      holders = @holders[key] or return
      return unless holders.delete(holder)
      return unless holders.empty?

      @holders.delete(key)
      @log.debug("BFD session to #{peer} on #{interface} no longer wanted", circuit: holder.name)
      @client.drop(interface: interface, peer: peer)
    end

    def wanted?(holder, interface:, peer:) = Array(@holders[[interface, peer]]).include?(holder)

    # The session's state as last told: :up, :down, :init, :admin_down, or
    # nil when nothing was told yet or bfdd4r is away.
    def state(interface:, peer:) = @client.state(interface: interface, peer: peer)

    # Reads what bfdd4r sent and tells the circuits. Never blocks.
    def poll(now)
      events = @client.poll(now)
      events.each { |e| dispatch(e) }
      events
    end

    # Lets go of every session, so bfdd4r takes those no other client holds
    # to AdminDown, which a peer does not act on (RFC 5882 4.2).
    def close
      @client.close(release: true) if @client.respond_to?(:close)
      @holders.clear
    end

    private

    def dispatch(event)
      case event.type
      when :state
        @log.info("BFD session to #{event.peer} on #{event.interface} #{event.from || 'unknown'} -> #{event.state}" \
                  "#{" (#{event.diag})" if event.diag}",
                  kind: :bfd, interface: event.interface, peer: event.peer, from: event.from, to: event.state)
        Array(@holders[[event.interface, event.peer]]).dup.each { |c| c.bfd_changed(event) }
      when :connected, :lost
        level = event.type == :lost ? :warn : :info
        @log.public_send(level, "BFD: #{event.message}; #{event.type == :lost ? 'not' : 'now'} sending TLV 148 " \
                                "(RFC 5882 4.1)", kind: :bfd, state: event.type)
        @circuits.each { |c| c.bfd_running_changed }
      when :error
        @log.warn("BFD: #{event.message}", kind: :bfd, interface: event.interface, peer: event.peer)
      end
    end
  end
end
