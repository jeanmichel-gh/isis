# frozen_string_literal: true

require_relative "../../test_helper"

# The link state database and its comparison rules, RFC 1142 clauses
# 7.3.15.1 e and 7.3.16.3, on a manual clock.
class TestDatabase < Minitest::Test
  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @db = ISIS::Database.new(level: 1, clock: @clock)
  end

  def lsp(id: "0000.0000.00cc.00-00", sequence: 5, lifetime: 1200)
    ISIS::Pdu::Lsp.new(level: 1, lsp_id: id, lifetime: lifetime, sequence: sequence,
                       tlvs: [ISIS::Tlv::AreaAddresses.new("49.0001")])
  end

  def held(**opts)
    l = lsp(**opts)
    @db.entry(l.lsp_id).store(l)
  end

  # Clause 7.3.16.3: the Remaining Lifetime counts down while held.
  def test_remaining_lifetime_counts_down_on_the_clock
    entry = held(lifetime: 100)
    @clock.advance(30.5)
    assert_equal 70, entry.remaining_lifetime
    @clock.advance(200)
    assert_equal 0, entry.remaining_lifetime
  end

  def test_larger_sequence_is_newer
    entry = held(sequence: 5)
    assert_equal :newer, compare(entry, 6)
    assert_equal :older, compare(entry, 4)
  end

  # Clause 7.3.15.1 e 2: same sequence, lifetimes both non-zero, same
  # checksum.
  def test_equal
    entry = held(sequence: 5)
    assert_equal :equal, compare(entry, 5, lifetime: 900)
  end

  # Clause 7.3.16.3: a non-zero lifetime against a held zero one, same
  # sequence: the held one is more recent.
  def test_held_expired_is_more_recent
    entry = held(sequence: 5, lifetime: 10)
    @clock.advance(11)
    assert_equal :older, compare(entry, 5)
  end

  # A zero lifetime against a held non-zero one is a purge, newer.
  def test_purge_is_newer
    entry = held(sequence: 5)
    assert_equal :newer, compare(entry, 5, lifetime: 0)
  end

  # Clause 7.3.16.2: same sequence, different checksum.
  def test_different_checksum_is_confused
    entry = held(sequence: 5)
    assert_equal :confused, compare(entry, 5, checksum: entry.checksum ^ 1)
  end

  # Clause 7.3.15.2 b 4: a sequence 0 entry with no LSP, which any reported
  # sequence is newer than.
  def test_placeholder
    entry = @db.entry(ISIS::Pdu.lsp_id_octets("0000.0000.00cc.00-00"))
    assert entry.placeholder?
    assert_equal [0, 0, 0], [entry.sequence, entry.checksum, entry.remaining_lifetime]
    assert_equal :newer, ISIS::Database.compare(entry, sequence: 1, lifetime: 1200, checksum: 1)
  end

  # Clause 9.10 wants CSNP entries in ascending LSP ID order.
  def test_entries_are_in_lsp_id_order
    %w[0000.0000.0003.00-00 0000.0000.0001.00-01 0000.0000.0001.00-00].each { |id| held(id: id) }
    assert_equal %w[0000.0000.0001.00-00 0000.0000.0001.00-01 0000.0000.0003.00-00], @db.entries.map(&:lsp_id_s)
  end

  def test_range_is_inclusive
    %w[0000.0000.0001.00-00 0000.0000.0002.00-00 0000.0000.0003.00-00].each { |id| held(id: id) }
    range = @db.range(ISIS::Pdu.lsp_id_octets("0000.0000.0001.00-00"), ISIS::Pdu.lsp_id_octets("0000.0000.0002.00-00"))
    assert_equal %w[0000.0000.0001.00-00 0000.0000.0002.00-00], range.map(&:lsp_id_s)
  end

  def test_snp_entry_reports_the_remaining_lifetime
    entry = held(sequence: 7, lifetime: 100)
    @clock.advance(40)
    reported = entry.snp_entry
    assert_equal [60, 7, entry.checksum], [reported.lifetime, reported.sequence, reported.checksum]
  end

  private

  def compare(entry, sequence, lifetime: 1200, checksum: entry.checksum)
    ISIS::Database.compare(entry, sequence: sequence, lifetime: lifetime, checksum: checksum)
  end
end
