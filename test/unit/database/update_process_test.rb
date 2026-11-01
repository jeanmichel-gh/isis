# frozen_string_literal: true

require_relative "../../test_helper"

# UpdateProcess on its own, in a host that is broadcast or not: the
# places RFC 1142 clause 7.3.15 says "if C is a non-broadcast circuit".
# The circuits' own tests run it end to end.
class TestUpdateProcess < Minitest::Test
  # The least a circuit provides: its name, ID, database, log, scheduler
  # and key, and transmit, which here keeps what was sent.
  class Host
    include ISIS::UpdateProcess

    attr_reader :database, :sent
    attr_accessor :area_key, :generators

    def initialize(broadcast:, scheduler:, log:)
      @broadcast = broadcast
      @name = "h-eth0"
      @system_id = ISIS::Pdu.dotted_octets("0000.0000.000a")
      @scheduler = scheduler
      @log = log
      @database = ISIS::Database.new(level: 1, clock: scheduler.clock)
      @database.attach(self)
      @area_key = nil
      @generators = []
      @lsp_transmission_interval = 5
      @sent = []
    end

    def broadcast?
      @broadcast
    end

    def level
      1
    end

    # As a circuit with an adjacency up does.
    def flood(entry)
      set_srm(entry)
    end

    def transmit(pdu)
      @sent << pdu
      pdu
    end
  end

  ID = "0000.0000.00cc.00-00"

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @scheduler = ISIS::Runtime::Scheduler.new(@clock)
    TestLogs.heading(name)
  end

  def host(broadcast)
    log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock), tracer: TestLogs.tracer(@clock))
    Host.new(broadcast: broadcast, scheduler: @scheduler, log: log)
  end

  def lsp(sequence = 5)
    ISIS::Pdu::Lsp.new(level: 1, lsp_id: ID, lifetime: 1200, sequence: sequence,
                       tlvs: [ISIS::Tlv::AreaAddresses.new("49.0001")])
  end

  def entry(h)
    h.database[ISIS::Pdu.lsp_id_octets(ID)]
  end

  # A PSNP reporting the LSP at +sequence+.
  def snp(sequence)
    reported = lsp(sequence)
    ISIS::Pdu::Psnp.new(level: 1, source_id: "0000.0000.000b.00",
                        tlvs: [ISIS::Tlv::LspEntries.new([ISIS::Tlv::LspEntries::Entry.new(1200, reported.lsp_id,
                                                                                            sequence,
                                                                                            reported.checksum)])])
  end

  def with_srm(h, sequence = 5)
    e = h.database.entry(lsp(sequence).lsp_id).store(lsp(sequence))
    e.srm << "h-eth0"
    e
  end

  # 7.3.15.1 e 1 iv: a new LSP sets SSN only on a non-broadcast circuit.
  def test_a_new_lsp_sets_ssn_only_off_a_lan
    { false => ["h-eth0"], true => [] }.each do |broadcast, ssn|
      h = host(broadcast)
      assert_equal :new, h.receive_lsp(lsp)
      assert_equal ssn, entry(h).ssn.to_a, "broadcast #{broadcast}"
    end
  end

  # 7.3.15.1 e 2 ii: so does an equal one.
  def test_an_equal_lsp_sets_ssn_only_off_a_lan
    { false => ["h-eth0"], true => [] }.each do |broadcast, ssn|
      h = host(broadcast)
      h.database.entry(lsp.lsp_id).store(lsp)
      assert_equal :equal, h.receive_lsp(lsp)
      assert_equal ssn, entry(h).ssn.to_a, "broadcast #{broadcast}"
    end
  end

  # 7.3.15.2 b 1: an SNP reporting an equal LSP clears SRM only on a
  # non-broadcast circuit.
  def test_an_equal_report_clears_srm_only_off_a_lan
    { false => [], true => ["h-eth0"] }.each do |broadcast, srm|
      h = host(broadcast)
      with_srm(h)
      h.receive_snp(snp(5))
      assert_equal srm, entry(h).srm.to_a, "broadcast #{broadcast}"
    end
  end

  # 7.3.15.2 b 3: a newer report sets SSN on both, and clears SRM only on a
  # non-broadcast circuit.
  def test_a_newer_report_clears_srm_only_off_a_lan
    { false => [], true => ["h-eth0"] }.each do |broadcast, srm|
      h = host(broadcast)
      with_srm(h, 4)
      h.receive_snp(snp(5))
      assert_equal srm, entry(h).srm.to_a, "broadcast #{broadcast}"
      assert_equal ["h-eth0"], entry(h).ssn.to_a
    end
  end

  # 7.3.15: SRM on a broadcast circuit is cleared once the LSP is sent; on
  # a non-broadcast one it stays, and the LSP goes again.
  def test_srm_is_cleared_by_sending_only_on_a_lan
    { false => ["h-eth0"], true => [] }.each do |broadcast, srm|
      h = host(broadcast)
      with_srm(h)
      assert_equal 1, h.send_srm_lsps
      assert_equal srm, entry(h).srm.to_a, "broadcast #{broadcast}"
    end
  end

  # -- Purges, RFC 1142 clause 7.3.16.4 --

  def purge(sequence = 5, tlvs: [])
    ISIS::Pdu::Lsp.new(level: 1, lsp_id: ID, lifetime: 0, sequence: sequence, tlvs: tlvs)
  end

  def held(h, sequence = 5)
    h.database.entry(lsp(sequence).lsp_id).store(lsp(sequence))
  end

  # b 1: a purge newer than the held LSP replaces it, SRM cleared for C,
  # SSN set only off a LAN.
  def test_a_newer_purge_replaces_the_held_lsp
    { false => ["h-eth0"], true => [] }.each do |broadcast, ssn|
      h = host(broadcast)
      held(h).srm << "h-eth0"
      assert_equal :newer, h.receive_lsp(purge)
      assert entry(h).purged?
      assert_empty entry(h).srm
      assert_equal ssn, entry(h).ssn.to_a, "broadcast #{broadcast}"
    end
  end

  # b 2 and b 3: an equal purge clears SRM; an older one sends ours back.
  def test_equal_and_older_purges
    h = host(false)
    e = held(h, 5)
    h.database.purge(e, "test")
    assert_equal ["h-eth0"], e.srm.to_a
    assert_equal :equal, h.receive_lsp(purge(5))
    assert_empty e.srm
    assert_equal :older, h.receive_lsp(purge(4))
    assert_equal ["h-eth0"], e.srm.to_a
  end

  # a: a purge of an LSP not held is acknowledged and not kept. Off a LAN
  # the acknowledgment is a PSNP naming it at lifetime 0; on a LAN nothing
  # is sent.
  def test_a_purge_not_held_is_acknowledged_and_not_kept
    { false => 1, true => 0 }.each do |broadcast, psnps|
      h = host(broadcast)
      assert_equal :not_held, h.receive_lsp(purge)
      assert_nil entry(h)
      sent = h.sent.select { |p| p.is_a?(ISIS::Pdu::Psnp) }
      assert_equal psnps, sent.size, "broadcast #{broadcast}"
      next if sent.empty?

      reported = sent.first.tlvs.first.entries.first
      assert_equal [0, 5, purge.checksum], [reported.lifetime, reported.sequence, reported.checksum]
    end
  end

  # A placeholder, an LSP asked for and not yet held (7.3.15.2 b 4), is
  # not an LSP in memory: a purge of it is acknowledged and the
  # placeholder dropped.
  def test_a_purge_of_a_placeholder_drops_it
    h = host(true)
    h.database.entry(lsp.lsp_id)
    assert_equal :not_held, h.receive_lsp(purge)
    assert_nil entry(h)
  end

  # The checksum of a purge is not checked (7.3.16.4 NOTE): one with a
  # wrong checksum is still a purge.
  def test_a_purge_with_a_wrong_checksum_is_still_a_purge
    h = host(true)
    held(h)
    octets = purge.encode
    octets[24, 2] = "\xde\xad".b
    assert_equal :newer, h.receive_lsp(ISIS::Pdu.factory(ISIS::Octets.new(octets)))
  end

  # 7.3.16.2: same sequence, another checksum: the held copy is kept with
  # zero lifetime and flooded.
  def test_confusion_purges_the_held_copy
    h = host(true)
    held(h)
    other = ISIS::Pdu::Lsp.new(level: 1, lsp_id: ID, lifetime: 1200, sequence: 5, tlvs: [])
    assert_equal :confused, h.receive_lsp(other)
    assert entry(h).purged?
    assert_equal 5, entry(h).sequence
    assert_equal ["h-eth0"], entry(h).srm.to_a
  end

  # RFC 5304 section 2, with a key: a purge carrying other TLVs is refused,
  # and a purge sent carries TLV 10 alone, with a digest that checks out.
  def test_keyed_purges
    h = host(true)
    h.area_key = "k"
    e = held(h)
    stuffed = purge(6, tlvs: [ISIS::Tlv::Authentication.new(:hmac_md5), ISIS::Tlv::AreaAddresses.new("49.0001")])
    stuffed.key = "k"
    assert_equal :purge_tlvs, h.receive_lsp(ISIS::Pdu.factory(ISIS::Octets.new(stuffed.encode)))
    h.database.purge(e, "test")
    h.send_srm_lsps
    out = ISIS::Pdu.factory(ISIS::Octets.new(h.sent.last.encode))
    assert_equal [ISIS::Tlv::Authentication], out.tlvs.map(&:class)
    assert out.authentic?("k")
    assert_equal 0, out.lifetime
  end

  # A generator stand-in, for this system's own LSPs.
  class Generator
    attr_reader :received

    def initialize(lsp_id)
      @lsp_id = lsp_id
    end

    def generates?(lsp_id)
      lsp_id == @lsp_id
    end

    def receive_own(result, lsp)
      @received = [result, lsp.sequence]
    end
  end

  OWN = "0000.0000.000a.00-00"

  # c: a purge of this system's own unexpired LSP is not stored; the
  # generator goes past its sequence.
  def test_a_purge_of_our_own_lsp_regenerates_it
    h = host(true)
    gen = Generator.new(ISIS::Pdu.lsp_id_octets(OWN))
    h.generators = [gen]
    own = ISIS::Pdu::Lsp.new(level: 1, lsp_id: OWN, lifetime: 1200, sequence: 3, tlvs: [])
    h.database.entry(own.lsp_id).store(own)
    gone = ISIS::Pdu::Lsp.new(level: 1, lsp_id: OWN, lifetime: 0, sequence: 3, tlvs: [])
    assert_equal :regenerated, h.receive_lsp(gone)
    assert_equal [:newer, 3], gen.received
    refute h.database[own.lsp_id].purged?
  end

  # 7.3.15.1 c: an LSP with our ID that no generator claims is purged at
  # the received sequence.
  def test_an_lsp_of_ours_nobody_generates_is_purged
    h = host(true)
    stale = ISIS::Pdu::Lsp.new(level: 1, lsp_id: "0000.0000.000a.01-00", lifetime: 1000, sequence: 9, tlvs: [])
    assert_equal :purged, h.receive_lsp(stale)
    e = h.database[stale.lsp_id]
    assert e.purged?
    assert_equal 9, e.sequence
    assert_equal ["h-eth0"], e.srm.to_a
  end
end

