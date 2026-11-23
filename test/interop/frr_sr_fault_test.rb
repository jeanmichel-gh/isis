# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/sr_fault_lab"
require_relative "../support/fault_matrix"

# The fault catalog's SR entries (ISIS::Fault::CATALOG) to isisd and to
# FRR's isisd at once (test/support/sr_fault_lab.rb): each entry goes in
# the simulator's own LSP, s1's, the next hop of both toward r. What each
# receiver then does: its label toward r's loopback, which takes s1's
# SRGB (RFC 8660 2.4, 2.10.1), and the label routes the entry added or
# took away.
#
# isisd is held to the RFC (FaultMatrix::SR_OUTCOME) and must name the
# entry's finding. FRR is held to what FRR 10.5.1 did here, recorded
# below; on another version its half is skipped. With ISIS_MATRIX_OUT,
# both are recorded for docs/fault-matrix.md.
#
# Runs only as root with FRR installed and ISIS_FRR=1.
class TestFrrSrFault < Minitest::Test
  FRR_VERSION = "10.5.1"
  R = "10.255.0.5/32"

  # What FRR 10.5.1 did, measured 2026-11-23: [whether it took s1's new
  # LSP, its label toward r, the label routes added]. It takes nothing
  # away. With s1's SRGB invalid its route to r loses its label, but its
  # label route 18005 still swaps to 17005. It discards the whole LSP
  # that carries a Prefix-SID with V set and L clear, keeping s1's
  # previous one. It installs a Prefix-SID whose algorithm s1 does not
  # advertise, a Prefix-SID carried as a label (24994, the label itself)
  # and one of the two colliding prefixes.
  FRR = {
    srgb_range_zero: [true, nil, [25_999]], srgb_overlap: [true, nil, [25_998]],
    srgb_reserved: [true, nil, [25_997]], sr_capabilities_twice: [true, 17_005, [25_996]],
    prefix_sid_vl_invalid: [false, 17_005, []], prefix_sid_label: [true, 17_005, [24_994]],
    algorithm_not_advertised: [true, 17_005, [25_993]], prefix_sid_duplicate: [true, 17_005, [25_992]]
  }.freeze

  # How long a receiver has to take an LSP once isisd has: FRR runs SPF
  # within a second here.
  SETTLE = 5

  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
  end

  def teardown
    @lab&.stop
  end

  def frr_version = `#{FrrLab::FRR}/isisd --version`[/version (\S+)/, 1]

  # [label toward r, in-labels] of each receiver.
  def isisd_reading
    route = @lab.isisd("show.routes").find { _1["prefix"] == R }
    [route&.dig("next_hops", 0, "label"), @lab.isisd("show.labels").map { _1["label"] }.sort]
  end

  def frr_reading
    route = @lab.frr_json("show ip route #{R} json")[R]&.first
    [route&.dig("nexthops", 0, "labels", 0), @lab.frr_json("show mpls table json").keys.map(&:to_i).sort]
  end

  # s1's LSP Number 0 as s1 holds it, and as each receiver does.
  def sequences
    own = ->(rows) { rows.find { _1["lsp_id"] == "0000.0000.0009.00-00" }&.fetch("sequence") }
    frr = @lab.vtysh("show isis database").lines.filter_map { _1[/^s1\.00-00\s+\*?\s+\d+\s+0x(\h{8})/, 1]&.hex }.first
    [own.call(@lab.api("sim", "show.database", "level" => 1)), own.call(@lab.isisd("show.database", "level" => 1)), frr]
  end

  # Both receivers hold s1's latest LSP, and have run SPF on it.
  def learned?
    s, i, f = sequences
    return false unless s && s == i && s == f

    sleep 3
    sequences == [s, s, s]
  end

  # isisd holds s1's latest LSP; then SETTLE seconds for FRR. Answers
  # whether FRR took it too.
  def isisd_learned_and_frr_taken?
    s, i, = sequences
    return nil unless s && s == i

    sleep SETTLE
    s2, i2, f = sequences
    return nil unless s2 == s && i2 == s

    f == s
  end

  def finding
    @lab.isisd("show.segment_routing").dig("levels", "1", "findings").map { _1["name"] }.first
  end

  def test_each_entry_to_isisd_and_frr
    @lab = SrFaultLab.new("sf#{Process.pid % 1000}").start
    assert @lab.wait_for(90) { isisd_reading[0] == 17_005 && frr_reading[0] == 17_005 && learned? },
           "both receivers label r's route through s1 first\n#{@lab.report}"
    base = { isisd: isisd_reading[1], frr: frr_reading[1] }
    check_frr = frr_version == FRR_VERSION
    ISIS::Fault.catalog.each do |e|
      name = e[:name]
      answer = @lab.sim("/api/fault", "case" => name.to_s, "router" => "s1")
      index = answer.dig("context", "index") or flunk "#{name}: #{answer}"
      taken = nil
      assert @lab.wait_for(40) { finding == name.to_s && !(taken = isisd_learned_and_frr_taken?).nil? },
             "#{name}: isisd names its finding\n#{@lab.report}"
      { isisd: isisd_reading, frr: frr_reading }.each do |who, (route, labels)|
        got = { route: route, added: labels - base[who], dropped: base[who] - labels,
                finding: who == :isisd ? finding : nil, taken: who == :isisd || taken }
        own = (who == :isisd ? SrFaultLab::ISISD_SRGB : SrFaultLab::FRR_SRGB) + index
        cell = FaultMatrix.sr_cell(name, got, own: own, first: 17_005)
        FaultMatrix.record(:sr, name, who, cell)
        if who == :isisd
          refute_equal false, cell[:agrees], "isisd, #{name}: #{cell[:text]}"
        elsif check_frr
          assert_equal FRR.fetch(name), [taken, route, got[:added]], "FRR, #{name}, as recorded"
        end
      end
      @lab.sim("/api/fault.clear", "router" => "s1")
      assert @lab.wait_for(30) { finding.nil? && learned? && isisd_reading[1] == base[:isisd] }, "#{name} cleared"
    end
  end

  def test_every_entry_is_recorded_for_frr
    assert_equal ISIS::Fault.names, FRR.keys
  end
end
