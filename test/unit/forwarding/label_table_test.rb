# frozen_string_literal: true

require_relative "../../test_helper"

# Forwarding::LabelTable: the label routes of every level through one
# adapter, Level 1's where both levels give a label, and only what changed
# sent.
class TestForwardingLabelTable < Minitest::Test
  # A Recorder that refuses what it is told to, and counts flushes.
  class Adapter < ISIS::Forwarding::Recorder
    attr_accessor :refuse
    attr_reader :flushes

    def flush_labels = (@flushes = (@flushes || 0) + 1)

    def apply(op)
      super
      !Array(refuse).include?(op.entry.label)
    end
  end

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock))
    @adapter = Adapter.new
    @table = ISIS::Forwarding::LabelTable.new(adapter: @adapter, log: @log)
  end

  def adjacency(circuit) = ISIS::Spf::Adjacency.new(circuit: circuit, neighbor: "\x00\x00\x00\x00\x00\x02".b, circuit_id: 1,
                                                    address: "10.0.0.2")

  def entry(label, circuit, out) = ISIS::Spf::Labels::Entry.new(label, :swap, :prefix_sid, "p", [[adjacency(circuit), out]])

  # Labels of one level, as Spf::Labels gives them.
  def labels(*entries) = Struct.new(:entries).new(entries.to_h { [_1.label, _1] })

  def sent = @adapter.operations.map { [_1.kind, _1.entry.label, _1.entry.hops.first&.last] }

  def test_old_label_routes_are_flushed_at_start
    assert_equal 1, @adapter.flushes
  end

  def test_install_then_only_changes
    @table.update(1, labels(entry(100, "a", 200), entry(101, "a", 3)))
    assert_equal [[:install, 100, 200], [:install, 101, 3]], sent
    @adapter.operations.clear
    @table.update(1, labels(entry(100, "a", 200), entry(101, "a", 300)))
    assert_equal [[:install, 101, 300]], sent, "only the changed label"
    @adapter.operations.clear
    @table.update(1, labels(entry(100, "a", 200)))
    assert_equal [[:withdraw, 101, 300]], sent
  end

  # Both levels give label 100: Level 1's is installed. When Level 1 drops
  # it, Level 2's takes its place.
  def test_level_1_wins
    @table.update(2, labels(entry(100, "b", 222)))
    @table.update(1, labels(entry(100, "a", 111)))
    assert_equal 111, @table.installed[100].hops.first.last
    @table.update(1, nil)
    assert_equal 222, @table.installed[100].hops.first.last
  end

  # A flex-algo's table goes in beside algorithm 0's, and leaves alone
  # when the level stops taking part (docs/design/flex-algo.md, step 5).
  def test_flex_algo_tables_beside
    @table.update(1, labels(entry(100, "a", 200)), [labels(entry(110, "a", 210))])
    assert_equal [[:install, 100, 200], [:install, 110, 210]], sent
    @adapter.operations.clear
    @table.update(1, labels(entry(100, "a", 200)), [])
    assert_equal [[:withdraw, 110, 210]], sent
  end

  # A label the kernel refused is not counted installed, so the next
  # update sends it again.
  def test_a_refusal_is_retried
    @adapter.refuse = [100]
    @table.update(1, labels(entry(100, "a", 200)))
    refute @table.installed.key?(100)
    @adapter.refuse = []
    @adapter.operations.clear
    @table.update(1, labels(entry(100, "a", 200)))
    assert_equal [[:install, 100, 200]], sent
  end
end
