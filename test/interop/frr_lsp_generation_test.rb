# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"

# When each side's change reaches the other: isisd with the backoff
# (lsp_generation, docs/design/lsp-generation.md, step 4) against FRR at
# its own defaults, whose lsp-gen-interval is 30 s. FRR holds a second
# change until 30 s after its last LSP; isisd sends each change within
# seconds, and FRR takes every one at isisd's sequence.
#
# Runs only as root with FRR installed and ISIS_FRR=1.
class TestFrrLspGeneration < Minitest::Test
  OWN = "#{FrrLab::ISIS4R_ID}.00-00".freeze
  FRRS = "#{FrrLab::FRR_ID}.00-00".freeze

  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
    @lab = FrrLab.new("lspgen#{Process.pid % 10_000}")
  end

  def teardown
    @lab&.stop
  end

  def assert_eventually(message, timeout = 20, &block)
    assert @lab.wait_for(timeout, &block), "#{message}\n#{@lab.report}"
  end

  def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  def isisd_sequence(lsp_id)
    @lab.isisd("show.database").find { _1["lsp_id"] == lsp_id }&.fetch("sequence")
  rescue SystemCallError
    nil
  end

  # FRR holds isis4r's LSP at the sequence and checksum isisd generated.
  def frr_holds_ours?(after)
    own = @lab.isisd("show.database").find { _1["self"] && _1["lsp_id"] == OWN } or return false
    frr = @lab.frr_database[OWN] or return false
    own["sequence"] > after && frr["sequence"] == own["sequence"] &&
      frr["checksum"] == own["checksum"].hex
  end

  def test_isisd_sends_each_change_at_once_where_frr_holds_its_own
    @lab.start(daemon: true, frr_lsp_gen_interval: nil,
               isis4r: { hostname: "isis4r-a", lsp_generation: { initial: 0, secondary: 1, maximum: 30 } })
    assert_eventually("the adjacency did not come up", 30) do
      @lab.frr_adjacency_state == "Up" && @lab.isisd("show.adjacencies").first&.fetch("state") == "up"
    end
    assert_equal "backoff", @lab.isisd("show.overview").dig("lsp_generation", "mode")
    assert_eventually("FRR does not hold isis4r's LSP", 30) { frr_holds_ours?(0) }

    # Three changes to isisd's LSP, each as soon as FRR holds the one
    # before. Fixed at 30 s the second and third would wait about 30 s.
    # With the backoff each waits 1, then 2 s, and the flooding's 5 s
    # retransmission timer can add to it (bfd-lab's ABOUT.md): 10 s is the
    # bound, a third of the fixed hold.
    times = [true, false, true].map do |on|
      before = isisd_sequence(OWN)
      t = now
      @lab.isisd("policy.overload", "on" => on)
      assert_eventually("FRR does not hold isis4r's LSP with overload #{on}", 15) { frr_holds_ours?(before) }
      now - t
    end
    times.each_with_index do |t, i|
      assert_operator t, :<, 10, "change #{i + 1} took #{t.round(1)} s: #{times.map { _1.round(1) }}\n#{@lab.report}"
    end

    # FRR's side, at its defaults: two metric changes in a row. The second
    # waits for FRR's lsp-gen-interval, 29.2 to 29.8 s on FRR 10.5.1
    # (2026-11-22). The first took from 1.7 to 12.0 s in five runs on a
    # loaded host; why it varies is not known, so it is printed, not
    # checked.
    frr_change = lambda do |metric|
      before = isisd_sequence(FRRS)
      t = now
      @lab.vtysh_config("interface veth0", "isis metric #{metric}")
      assert_eventually("isisd does not hold FRR's LSP after metric #{metric}", 45) do
        (s = isisd_sequence(FRRS)) && s > before
      end
      now - t
    end
    # Quiet first, so FRR's first change is not held by its start.
    sleep 31
    first = frr_change.call(20)
    second = frr_change.call(30)
    assert_operator second, :>, 20, "FRR's second change took #{second.round(1)} s: does it still hold for 30 s?"
    puts format("\n  isisd: %s s; FRR: first %.1f s, second %.1f s", times.map { _1.round(1) }.join(", "), first, second)
  end
end
