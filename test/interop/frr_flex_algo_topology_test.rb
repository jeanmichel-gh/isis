# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/flex_topology_lab"
require_relative "../support/fault_matrix"

# The catalog's flex-algo topologies (ISIS::Fault::FLEX_ALGO_TOPOLOGIES)
# on real routers, in network namespaces (test/support/
# flex_topology_lab.rb): isisd at every system, and S, the system that
# computes, either isisd or FRR's isisd. What S selects, and its route
# to D in algorithm 128, is read back from S.
#
# isisd is held to RFC 9350, as the entry expects. FRR is held to what
# FRR 10.5.1 did here, recorded below, so a change in FRR shows; on
# another version its half is skipped.
#
# Runs only as root with FRR installed and ISIS_FRR=1.
class TestFrrFlexAlgoTopology < Minitest::Test
  FRR_VERSION = "10.5.1"

  # What FRR 10.5.1 did, measured 2026-11-26. It runs a FAD with the IGP
  # metric and affinity rules as the RFC asks, and protects 128's label
  # route with TI-LFA. It elects a FAD with a delay or TE metric, or with
  # an Exclude SRLG, then disables it as an "unsupported definition" and
  # does not take part (RFC 9350 section 5.3).
  BY_B = { winner: "D", first_hops: ["B"], metric: 10 }.freeze
  UNSUPPORTED = "disabled (unsupported definition)"
  FRR = {
    fa_exclude_any: BY_B, fa_include_any: BY_B, fa_include_all: BY_B,
    fa_exclude_srlg: { taking_part: false, winner: "D", state: UNSUPPORTED },
    fa_delay: { taking_part: false, winner: "D", state: UNSUPPORTED },
    fa_te_metric: { taking_part: false, winner: "D", state: UNSUPPORTED },
    fa_link_no_metric: { taking_part: false, winner: "D", state: UNSUPPORTED },
    fa_last_resort: { taking_part: false, winner: "D", state: UNSUPPORTED },
    fa_node_not_participating: BY_B,
    fa_one_way: { winner: "D", first_hops: ["A"], metric: 2 },
    fa_partition: { winner: "D", unreachable: true },
    fa_priority: { taking_part: false, winner: "B", state: UNSUPPORTED },
    fa_system_id_tie: { taking_part: false, winner: "B", state: UNSUPPORTED },
    fa_no_fad: { taking_part: false },
    fa_ti_lfa_constraint: { winner: "D", first_hops: ["F"], metric: 2,
                            repair: { first_hop: "B", segments: [[:node, "D"]] } }
  }.freeze

  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
  end

  def teardown
    @lab&.stop
  end

  def reading(name, plr)
    @lab = FlexTopologyLab.new("fa#{Process.pid % 1000}", name, plr: plr).start
    @lab.settled_flex(180)
  end

  def frr_version = `#{FrrLab::FRR}/isisd --version`[/version (\S+)/, 1]

  ISIS::Fault.flex_topology_names.each do |name|
    define_method(:"test_isisd_#{name}") do
      entry = ISIS::Fault.flex_topologies.find { _1[:name] == name }
      expected = FaultMatrix.flex_expected(entry)
      got = reading(name, :isisd)
      FaultMatrix.record(:flex_topology, name, :isisd, FaultMatrix.flex_cell(got, expected))
      assert_equal expected, got.merge(got[:repair] ? { repair: got[:repair].slice(:first_hop, :segments) } : {}),
                   entry[:description]
    end

    define_method(:"test_frr_#{name}") do
      skip "FRR's answers are recorded on #{FRR_VERSION}; this is #{frr_version}" unless
        frr_version == FRR_VERSION || ENV["ISIS_MATRIX_OUT"]
      entry = ISIS::Fault.flex_topologies.find { _1[:name] == name }
      got = reading(name, :frr)
      FaultMatrix.record(:flex_topology, name, :frr, FaultMatrix.flex_cell(got, FaultMatrix.flex_expected(entry)))
      skip "FRR #{frr_version} recorded for the matrix, not held to #{FRR_VERSION}'s answers" unless frr_version == FRR_VERSION
      assert_equal FRR.fetch(name), got, entry[:description]
    end
  end

  def test_every_entry_runs_on_frr
    assert_equal ISIS::Fault.flex_topology_names, FRR.keys
  end
end
