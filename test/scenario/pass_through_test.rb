# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/pass_through"

# Pass-through equivalence (CLAUDE.md, "Pass-through equivalence"): one
# router scenario, run from the same initial state on simulated time, with
# no controls installed and with every control installed and passing
# everything through, and with logging off and at debug. Every run must
# give the same ordered packet events per circuit, the same protocol state
# at each step, and the same ordered route operations.
#
# A control is how a test script takes over a mechanism: it replaces a
# method on the one object that runs it. So "every control installed" is
# every method of every mechanism object replaced, on that object, by one
# that calls the original: the scheduler, each transport, each circuit with
# its hello generation, update process and receive steps, each point to
# point level, each database, originator, pseudonode, decision process and
# forwarding adapter, and the log. A control that changed behaviour by
# being there would show as a difference.
#
# The topology: A and B on a point to point link, and B, C and D on a LAN,
# each advertising a /32. A and B run Level 2 too on their link, and B
# leaks its Level 2 routes into Level 1. The script brings it up, overloads C, cuts the
# point to point link and restores it, and silences D, the DIS.
class TestPassThroughEquivalence < Minitest::Test
  IDS = { a: "0000.0000.000a", b: "0000.0000.000b", c: "0000.0000.000c", d: "0000.0000.000d" }.freeze
  STEP = 0.5

  # One run of the scenario. Returns what the harness observed: packets per
  # circuit, a state snapshot per step, and route operations, each in order.
  class Run
    attr_reader :packets, :states, :operations, :lines, :calls

    def initialize(controls:, logging:)
      @controls = controls
      @logging = logging
      @packets = Hash.new { |h, k| h[k] = [] }
      @states = []
      @operations = []
      @lines = 0
      @mechanisms = []
      @calls = Hash.new(0)
      @clock = ISIS::Runtime::ManualClock.new
      @scheduler = ISIS::Runtime::Scheduler.new(@clock)
      @mechanisms << @scheduler
      @ab = ISIS::Link::SimulatedWire.new
      @lan = ISIS::Link::SimulatedWire.new
      @systems = IDS.keys.to_h { |w| [w, system(w)] }
      @a_transport = @systems[:a][:circuits].first.transport
      install_controls if controls
    end

    def system(who)
      log = ISIS::Runtime::Log.new(clock: @clock, logger: (logger if @logging), tracer: (tracer if @logging))
      db = ISIS::Database.new(level: 1, clock: @clock, scheduler: @scheduler, log: log)
      n = IDS.keys.index(who) + 1
      both = %i[a b].include?(who)
      orig = ISIS::Originator.new(system_id: IDS[who], database: db, scheduler: @scheduler, log: log,
                                  minimum_interval: 1, prefixes: [{ prefix: "192.0.2.#{n}/32", metric: 1 }],
                                  is_type: both ? 3 : nil)
      recorder = ISIS::Forwarding::Recorder.new
      decision = ISIS::Spf::Decision.new(system_id: IDS[who], database: db, scheduler: @scheduler, log: log,
                                         forwarding: recorder)
      l2 = both ? level2(who, n, log, orig) : nil
      circuits = []
      if both
        levels = { 1 => { database: db, originator: orig }, 2 => { database: l2[:db], originator: l2[:orig] } }
        circuits << ISIS::P2pCircuit.new(transport: transport(@ab, "#{who}-p2p"), scheduler: @scheduler, log: log,
                                         name: "#{who}-p2p", system_id: IDS[who], snpa: "00:00:00:00:01:0#{n}",
                                         ip_addresses: ["10.0.12.#{n}"], levels: levels,
                                         hello_interval: 1, hello_multiplier: 3)
      end
      unless who == :a
        circuits << ISIS::LanCircuit.new(transport: transport(@lan, "#{who}-lan"), scheduler: @scheduler, log: log,
                                         name: "#{who}-lan", system_id: IDS[who], snpa: "00:00:00:00:02:0#{n}",
                                         ip_addresses: ["10.0.1.#{n}"], database: db, originator: orig,
                                         hello_interval: 1, hello_multiplier: 3)
      end
      circuits.each do |c|
        if c.respond_to?(:levels)
          decision.attach(c.levels.fetch(1))
          l2[:decision].attach(c.levels.fetch(2))
        else
          decision.attach(c)
        end
      end
      @mechanisms.push(log, db, orig, recorder, decision, *circuits)
      @mechanisms.push(*l2.values) if l2
      { log: log, db: db, orig: orig, decision: decision, circuits: circuits, recorder: recorder, l2: l2 }
    end

    # A and B also run Level 2 on their point to point link, each with a
    # /32 of its own there. B leaks every Level 2 route into Level 1 (RFC
    # 5302 section 2), so C and D learn A's Level 2 prefix only through
    # B's up/down entry; both set the AttachedFlag for their Level 1 LSP,
    # all in one area, so false.
    def level2(who, n, log, level1_orig)
      db = ISIS::Database.new(level: 2, clock: @clock, scheduler: @scheduler, log: log)
      orig = ISIS::Originator.new(system_id: IDS[who], database: db, scheduler: @scheduler, log: log,
                                  minimum_interval: 1, prefixes: [{ prefix: "198.51.100.#{n}/32", metric: 1 }],
                                  is_type: 3, level1_database: level1_orig.database)
      leak = ISIS::Spf::Leak.new(originator: level1_orig, log: log,
                                 policy: who == :b ? ->(_route) { true } : ISIS::Spf::Leak::NONE)
      recorder = ISIS::Forwarding::Recorder.new
      decision = ISIS::Spf::Decision.new(system_id: IDS[who], database: db, scheduler: @scheduler, log: log,
                                         forwarding: recorder, attached_flag: level1_orig, leak: leak)
      { db: db, orig: orig, leak: leak, recorder: recorder, decision: decision }
    end

    # A transport the harness taps: every frame sent and received, in order,
    # under the circuit's name. The tap is the harness, not a control, so
    # it is there in every run.
    def transport(wire, name)
      t = ISIS::Link::SimulatedTransport.new(wire)
      packets = @packets
      t.define_singleton_method(:send) do |frame|
        packets[name] << [:sent, frame.encode.unpack1("H*")]
        super(frame)
      end
      t.define_singleton_method(:receive) do |**k|
        frame = super(**k)
        packets[name] << [:received, frame.encode.unpack1("H*")] if frame
        frame
      end
      t
    end

    def logger
      ->(_level, _message) { @lines += 1 }
    end

    def tracer
      ->(_direction, _circuit, pdu, _peer) { @lines += 1 if pdu }
    end

    # Every method each mechanism's class defines, public, protected or
    # private, replaced on that object by one that calls the original.
    def install_controls
      objects = @mechanisms + @systems.values.flat_map { |s| s[:circuits] }.map(&:transport) +
                @systems.values.flat_map { |s| s[:circuits] }.flat_map { |c| c.respond_to?(:levels) ? c.levels.values : [] } +
                @systems.values.flat_map { |s| s[:circuits] }.filter_map { |c| c.respond_to?(:pseudonode) && c.pseudonode }
      objects.uniq.each { |o| ISIS::Test.pass_through(o, @calls) }
    end

    def run
      @systems.each_value do |s|
        [s[:orig], s[:l2] && s[:l2][:orig], *s[:circuits], s[:decision], s[:l2] && s[:l2][:decision]]
          .compact.each(&:start)
      end
      run_for(40)
      @systems[:c][:orig].overload = true
      run_for(15)
      @ab.detach(@a_transport)
      run_for(15)
      @ab.attach(@a_transport)
      run_for(20)
      @systems[:d][:circuits].each(&:stop)
      @d_stopped = true
      run_for(20)
      @operations = @systems.transform_values do |s|
        [s[:recorder], s[:l2] && s[:l2][:recorder]].compact.map { |r| r.operations.map(&:to_s) }
      end
      self
    end

    def run_for(seconds)
      (seconds / STEP).ceil.times do
        @scheduler.advance(STEP)
        @systems.each do |who, s|
          s[:circuits].each { |c| c.poll unless who == :d && @d_stopped }
        end
        @states << snapshot
      end
    end

    def snapshot
      @systems.transform_values do |s|
        { circuits: s[:circuits].map { |c| circuit_state(c) },
          database: s[:db].entries.map do |e|
            [e.lsp_id_s, e.sequence, e.checksum, e.purged?, e.srm.to_a.sort, e.ssn.to_a.sort]
          end,
          routes: s[:decision].routes.values.map(&:to_s),
          level2: s[:l2] && level2_state(s[:l2]) }
      end
    end

    def level2_state(l2)
      { database: l2[:db].entries.map { |e| [e.lsp_id_s, e.sequence, e.checksum, e.purged?, e.srm.to_a.sort, e.ssn.to_a.sort] },
        routes: l2[:decision].routes.values.map(&:to_s), leaked: l2[:leak].leaked }
    end

    def circuit_state(circuit)
      if circuit.is_a?(ISIS::LanCircuit)
        [circuit.name, circuit.lan_id_s, circuit.dis == :self ? :self : circuit.dis&.system_id_s,
         circuit.neighbors.values.map { |n| [n.system_id_s, n.state] }]
      else
        [circuit.name, circuit.three_way_state, circuit.neighbor&.state]
      end
    end
  end

  def run_with(controls:, logging:)
    Run.new(controls: controls, logging: logging).run
  end

  def assert_same_run(expected, actual)
    assert_equal expected.packets, actual.packets, "packet events differ"
    expected.states.zip(actual.states).each_with_index do |(e, a), i|
      assert_equal e, a, "protocol state differs at step #{i}, #{(i + 1) * STEP} s"
    end
    assert_equal expected.states.size, actual.states.size
    assert_equal expected.operations, actual.operations, "route operations differ"
  end

  def setup
    @plain = run_with(controls: false, logging: false)
  end

  # The scenario does what it is meant to: each system reaches the others'
  # prefixes, and something moved, so a run that compared two idle
  # networks could not pass.
  def test_the_scenario_routes_and_changes
    ops = @plain.operations.transform_values(&:first)
    assert(ops[:a].any? { |o| o.start_with?("install 192.0.2.4/32") }, ops[:a].inspect)
    assert(ops[:a].any? { |o| o.start_with?("withdraw 192.0.2.4/32") }, ops[:a].inspect)
    # C reaches A's Level 2 prefix only through B's leak.
    assert(ops[:c].any? { |o| o.start_with?("install 198.51.100.1/32") }, ops[:c].inspect)
    assert(@plain.packets.values.sum(&:size) > 500, "few packets")
    assert_operator @plain.states.uniq.size, :>, 20
  end

  # Every kind of mechanism ran through its control, so the comparison is
  # not between two runs that happen to have no controls in them.
  MECHANISMS = [ISIS::Runtime::Scheduler, ISIS::Link::SimulatedTransport, ISIS::P2pCircuit, ISIS::P2pCircuit::Level,
                ISIS::LanCircuit, ISIS::Database, ISIS::Originator, ISIS::Pseudonode, ISIS::Spf::Decision,
                ISIS::Forwarding::Recorder, ISIS::Runtime::Log, ISIS::Spf::Leak].freeze

  def test_every_control_passing_through_changes_nothing
    controlled = run_with(controls: true, logging: false)
    called = controlled.calls.keys.map(&:first).uniq
    assert_empty MECHANISMS - called, "mechanisms no control saw"
    assert_operator controlled.calls.values.sum, :>, 10_000
    assert_same_run @plain, controlled
  end

  def test_logging_at_debug_changes_nothing
    logged = run_with(controls: false, logging: true)
    assert_operator logged.lines, :>, 1000
    assert_same_run @plain, logged
  end

  def test_controls_and_logging_together_change_nothing
    assert_same_run @plain, run_with(controls: true, logging: true)
  end
end
