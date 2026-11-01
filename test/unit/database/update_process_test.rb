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

    def initialize(broadcast:, scheduler:, log:)
      @broadcast = broadcast
      @name = "h-eth0"
      @system_id = ISIS::Pdu.dotted_octets("0000.0000.000a")
      @scheduler = scheduler
      @log = log
      @database = ISIS::Database.new(level: 1, clock: scheduler.clock)
      @area_key = nil
      @lsp_transmission_interval = 5
      @sent = []
    end

    def broadcast?
      @broadcast
    end

    def level
      1
    end

    def generators
      []
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
end
