# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/srl_lab"

# Phase 1's gates against a second independent implementation, Nokia SR
# Linux, so a mistake isis4r and FRR share cannot pass unseen: a point to
# point adjacency comes up on both sides, each side holds the other's LSP
# at the originator's sequence and checksum, and each installs the other's
# prefix. CLAUDE.md, "Labs and interop".
#
# Runs only as root with docker and containerlab, and ISIS_SRL=1:
#
#   sudo env "PATH=$PATH" ISIS_SRL=1 rake interop_srl
#
# One test, because bringing SR Linux up takes most of half a minute
# (measured 2026-11-15, 25 s on a 6 core arm64 VM), and every claim below
# needs the same lab.
class TestSrlP2p < Minitest::Test
  def setup
    ok, why = SrlLab.available?
    # Asked for with ISIS_SRL=1 and unable to run is a failure, not a skip,
    # as for FRR: a CI job of skips is green.
    flunk "SR Linux interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_SRL"] == "1"
    skip why unless ok
    @lab = SrlLab.new("srl#{Process.pid % 10_000}")
  end

  def teardown
    @lab&.stop
  end

  def assert_eventually(message, timeout = 30, &block)
    assert @lab.wait_for(timeout, &block), "#{message}\n#{@lab.report}"
  end

  def test_adjacency_lsps_and_routes_both_ways
    @lab.start

    assert_eventually("adjacency did not come up on both sides") do
      @lab.srl_adjacency_state == "up" && @lab.isis4r_state == "up"
    end
    assert_includes @lab.isis4r_log, "adjacency with #{SrlLab::SRL_ID} "

    # Each side holds the other's LSP 0 as its originator holds it: the
    # same sequence and the same checksum. isis4r's must be past sequence
    # 1, the one it generated before the adjacency, so the LSP SR Linux
    # holds is the one that lists SR Linux in TLV 22.
    srl_lsp = "#{SrlLab::SRL_ID}.00-00"
    isis4r_lsp = "#{SrlLab::ISIS4R_ID}.00-00"
    assert_eventually("isis4r does not hold SR Linux's LSP as SR Linux does") do
      held = @lab.isis4r_database[srl_lsp]
      own = @lab.srl_database[srl_lsp]
      held && own && held["sequence"] == own["sequence"] && held["checksum"] == own["checksum"]
    end
    assert_eventually("SR Linux does not hold isis4r's LSP as isis4r does") do
      own = @lab.isis4r_database[isis4r_lsp]
      held = @lab.srl_database[isis4r_lsp]
      own && held && own["sequence"] >= 2 && held["sequence"] == own["sequence"] &&
        held["checksum"] == own["checksum"]
    end

    # isis4r reaches SR Linux's loopback through SR Linux, at isis4r's link
    # metric, 10, plus the loopback's, which SR Linux 26.7.2 advertises at
    # 0 for a passive interface (measured). Our arithmetic.
    assert_eventually("isis4r has no route to SR Linux's loopback") do
      route = @lab.isis4r_routes[SrlLab::SRL_LOOPBACK]
      route && route["metric"] == 10 && route["next_hops"].map { |h| h["address"] } == ["10.0.12.2"]
    end

    # SR Linux installs 192.0.2.1/32, which exists only in isis4r's TLV 135,
    # through isis4r, at its link metric plus isis4r's prefix metric, 10 + 5.
    assert_eventually("SR Linux did not install isis4r's prefix") do
      route = @lab.srl_route("192.0.2.1/32")
      route && route["route_type"] == "isis" && route["active"] &&
        route["metric"] == SrlLab::SRL_LINK_METRIC + 5 && route["next_hops"] == ["10.0.12.1"]
    end
  end
end
