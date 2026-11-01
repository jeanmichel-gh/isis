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

  # Clause 7.3.16.4 b 2: two purges of one sequence are equal, "Remaining
  # Lifetimes both zero", whatever their checksums.
  def test_two_purges_are_equal_whatever_their_checksums
    entry = held(lifetime: 0)
    assert_equal :equal, ISIS::Database.compare(entry, sequence: 5, lifetime: 0, checksum: entry.checksum ^ 0xffff)
  end

  private

  def compare(entry, sequence, lifetime: 1200, checksum: entry.checksum)
    ISIS::Database.compare(entry, sequence: sequence, lifetime: lifetime, checksum: checksum)
  end
end

# Expiry and purges, RFC 1142 clause 7.3.16.4, with a scheduler.
class TestDatabasePurge < Minitest::Test
  # What a database asks of a circuit: flood(entry).
  class Circuit
    attr_reader :flooded

    def initialize
      @flooded = []
    end

    def flood(entry)
      @flooded << [entry.lsp_id_s, entry.sequence, entry.remaining_lifetime]
    end
  end

  # FRR 8.4.4's pseudonode LSP 0000.0000.0002.02-00, sequence 1, as it
  # arrived before FRR resigned, and the purge it sent on resigning.
  PSEUDONODE = "831b01001201000000330494000000000002020000000001755501161600000000000200" \
               "000000000000000000010000000000"
  PURGE = File.read(File.expand_path("../../fixtures/frr-8.4.4-l1-lsp-purge.hex", __dir__)).strip

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    @db = ISIS::Database.new(level: 1, clock: @clock, scheduler: @scheduler)
    @circuit = Circuit.new
    @db.attach(@circuit)
  end

  def lsp(lifetime: 1200, sequence: 5)
    ISIS::Pdu::Lsp.new(level: 1, lsp_id: "0000.0000.00cc.00-00", lifetime: lifetime, sequence: sequence,
                       tlvs: [ISIS::Tlv::AreaAddresses.new("49.0001")])
  end

  def held(**opts)
    l = lsp(**opts)
    @db.entry(l.lsp_id).store(l)
  end

  # Clause 7.3.16.4 b, "retain only the LSP header": purging FRR's own
  # pseudonode LSP here gives the octets of the purge FRR sent for it.
  def test_a_purge_is_the_header_as_frr_writes_it
    lsp = ISIS::Pdu.factory(ISIS::Octets.new([PSEUDONODE].pack("H*")))
    assert_equal PSEUDONODE, lsp.to_shex
    entry = @db.entry(lsp.lsp_id).store(lsp)
    @db.purge(entry, "test")
    assert_equal PURGE, entry.lsp.to_shex
    assert entry.purged?
  end

  # The header keeps the flags octet of the LSP it purges: here IS type 3,
  # a Level 2 system's.
  def test_a_purge_keeps_the_flags
    entry = held
    entry.lsp.flags = 0x03
    @db.purge(entry, "test")
    assert_equal 0x03, entry.lsp.flags
  end

  # Clause 7.3.16.4 a: an LSP whose lifetime reaches zero is purged, with
  # SRM set on every circuit; c: its header goes ZeroAgeLifetime later.
  def test_an_lsp_expires_and_its_header_goes_a_minute_later
    held(lifetime: 10)
    @scheduler.advance(9)
    assert_empty @circuit.flooded
    @scheduler.advance(1)
    assert_equal [["0000.0000.00cc.00-00", 5, 0]], @circuit.flooded
    assert_equal 0, @db[lsp.lsp_id].lsp.tlvs.size
    @scheduler.advance(59)
    refute_nil @db[lsp.lsp_id]
    @scheduler.advance(1)
    assert_nil @db[lsp.lsp_id]
  end

  # A newer copy stored before expiry moves the expiry with it.
  def test_storing_again_resets_the_expiry
    held(lifetime: 10)
    @scheduler.advance(8)
    held(lifetime: 10, sequence: 6)
    @scheduler.advance(8)
    assert_empty @circuit.flooded
    @scheduler.advance(2)
    assert_equal [["0000.0000.00cc.00-00", 6, 0]], @circuit.flooded
  end

  # "When a purge of an LSP with non-zero Remaining Lifetime is initiated,
  # the header shall be retained for MaxAge."
  def test_a_purge_started_here_keeps_the_header_for_max_age
    entry = held
    @db.purge(entry, "test", retain: ISIS::Database::MAX_AGE)
    @scheduler.advance(ISIS::Database::MAX_AGE - 1)
    refute_nil @db[lsp.lsp_id]
    @scheduler.advance(1)
    assert_nil @db[lsp.lsp_id]
  end

  # A received purge, stored, goes after ZeroAgeLifetime too.
  def test_a_stored_purge_goes_after_zero_age_lifetime
    held(lifetime: 0)
    @scheduler.advance(60)
    assert_nil @db[lsp.lsp_id]
  end

  # A placeholder has no lifetime to run out and stays.
  def test_a_placeholder_does_not_age
    @db.entry(lsp.lsp_id)
    @scheduler.advance(3000)
    refute_nil @db[lsp.lsp_id]
  end
end

