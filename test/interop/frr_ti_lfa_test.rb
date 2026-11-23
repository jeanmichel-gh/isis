# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/topology_lab"
require_relative "../support/fault_matrix"

# The catalog's TI-LFA topologies (ISIS::Fault::TOPOLOGIES) on real
# routers, in network namespaces (test/support/topology_lab.rb): isisd
# at every system, and the PLR either isisd or FRR's isisd. Each repair
# is read back as the routers forward it: from the first hop, a label in
# a router's SRGB is a Node-SID, any other that router's Adj-SID.
#
# isisd is held to RFC 9855, as the entry expects: its segments, then
# the destination's Prefix-SID in Q's SRGB unless Q is the destination
# (7.1). FRR is held to what FRR 10.5.1 did here, recorded below, so a
# change in FRR shows; on another version its half is skipped.
#
# ti_lfa_one_way stays a unit test: two real routers report a link both
# ways or neither.
#
# Runs only as root with FRR installed and ISIS_FRR=1.
class TestFrrTiLfa < Minitest::Test
  FRR_VERSION = "10.5.1"

  # What FRR 10.5.1 pushed, read as segments, measured 2026-11-22. FRR
  # ends a repair with Adj-SIDs to the destination where RFC 9855 7.1
  # asks the destination's Prefix-SID in Q's SRGB; on Figure 2 it first
  # pushes its first hop's own Node-SID; past 30 labels it still gives a
  # repair, which zebra does not install. FRR shows no backup where the
  # destination keeps another primary next hop, or has no repair.
  CHAIN = (0...ISIS::Fault::TOO_DEEP_CHAIN).map { |i| [:adj, "A#{i}", "A#{i + 1}"] }.freeze
  FRR = {
    ti_lfa_neighbor: { first_hop: "N", segments: [[:node, "D"]] },
    ti_lfa_pq_node: { first_hop: "A", segments: [[:node, "B"], [:adj, "B", "D"]] },
    ti_lfa_p_and_q_adjacent: { first_hop: "A", segments: [[:node, "B"], [:adj, "B", "D"]] },
    ti_lfa_figure_1: { first_hop: "N2", segments: [[:node, "R1"], [:adj, "R1", "R2"], [:adj, "R2", "R3"],
                                                    [:adj, "R3", "D"]] },
    ti_lfa_figure_2: { first_hop: "R7", segments: [[:node, "R7"], [:adj, "R7", "R8"], [:adj, "R8", "R4"],
                                                    [:adj, "R4", "R5"], [:adj, "R5", "D"]] },
    ti_lfa_no_path: { none: true },
    ti_lfa_ecmp: { none: true },
    ti_lfa_overload: { none: true },
    ti_lfa_too_deep: { first_hop: "A0",
                       segments: [[:node, "A0"], *CHAIN, [:adj, "A#{ISIS::Fault::TOO_DEEP_CHAIN}", "D"]] }
  }.freeze

  ON_REAL_ROUTERS = ISIS::Fault.topology_names - [:ti_lfa_one_way]

  # What isisd shows for an entry: the RFC's repair with 7.1's last
  # label; ECMP; or why not. A node repair too deep falls back to the
  # link's (isisd's node-protection link-fallback, docs/ti-lfa.md): for
  # ti_lfa_too_deep, A0 itself, whose way to D avoids the link S-F.
  def self.isisd_expects(entry)
    e = entry[:expect]
    return { first_hop: "A0", case: :neighbor, segments: [[:node, "D"]], fallback: true } if e[:unprotected] == :too_deep
    return { unprotected: e[:unprotected] } if e[:unprotected]
    return { ecmp: true } if e[:ecmp]

    last = e[:q] == entry[:destination] ? [] : [[:node, entry[:destination]]]
    { first_hop: e[:first_hop], case: e[:case], segments: e[:segments] + last }
  end

  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
  end

  def teardown
    @lab&.stop
  end

  def repair(name, plr)
    @lab = TopologyLab.new("tl#{Process.pid % 1000}", name, plr: plr).start
    @lab.settled_repair(180)
  end

  def frr_version = `#{FrrLab::FRR}/isisd --version`[/version (\S+)/, 1]

  ON_REAL_ROUTERS.each do |name|
    define_method(:"test_isisd_#{name}") do
      entry = ISIS::Fault.topology(name)
      got = repair(name, :isisd)
      FaultMatrix.record(:topology, name, :isisd, FaultMatrix.topology_cell(got, FaultMatrix.rfc_repair(entry)))
      assert_equal self.class.isisd_expects(entry), got, entry[:description]
    end

    define_method(:"test_frr_#{name}") do
      skip "FRR's answers are recorded on #{FRR_VERSION}; this is #{frr_version}" unless
        frr_version == FRR_VERSION || ENV["ISIS_MATRIX_OUT"]
      entry = ISIS::Fault.topology(name)
      got = repair(name, :frr)
      FaultMatrix.record(:topology, name, :frr, FaultMatrix.topology_cell(got, FaultMatrix.rfc_repair(entry)))
      skip "FRR #{frr_version} recorded for the matrix, not held to #{FRR_VERSION}'s answers" unless frr_version == FRR_VERSION
      assert_equal FRR.fetch(name), got, entry[:description]
    end
  end

  def test_every_entry_but_one_way_runs_on_frr
    assert_equal ON_REAL_ROUTERS, FRR.keys
  end
end
