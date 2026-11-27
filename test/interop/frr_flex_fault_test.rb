# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/sr_fault_lab"
require_relative "../support/fault_matrix"

# The fault catalog's flex-algo entries (ISIS::Fault::FLEX_ALGO_CATALOG)
# to isisd and to FRR's isisd at once, as frr_sr_fault_test.rb does the
# SR entries: each goes in s1's own LSP (test/support/sr_fault_lab.rb).
# Both receivers take part in algorithm 128 and advertise no FAD, so a
# FAD in s1's LSP is the only one. A link entry is a second TLV 22 entry
# from s1 toward FRR, 10.0.0.1 to 10.0.0.2.
#
# isisd is held to the RFC (FaultMatrix::FLEX_OUTCOME) and must name the
# entry's finding, but where it does not read the entry yet. FRR is held
# to what FRR 10.5.1 did here, recorded below; on another version its
# half is skipped. With ISIS_MATRIX_OUT, both are recorded for
# docs/fault-matrix.md.
#
# Runs only as root with FRR installed and ISIS_FRR=1.
class TestFrrFlexFault < Minitest::Test
  FRR_VERSION = "10.5.1"
  S1 = "0000.0000.0009"
  K = ISIS::Fault::FLEX_ALGO

  # What FRR 10.5.1 did, measured 2026-11-26. It prints a link's ASLA as
  # it parsed it, but for one with a SABM of 9 octets, which it drops. It
  # uses a FAD where RFC 9350 asks it be ignored: with one sub-TLV twice
  # (the second), with the S bit; and the last, not the first, of FADs
  # split across sub-TLVs. It discards the whole LSP that carries a FAD
  # admin group of 5 octets, keeping s1's previous one. It prints no FAPM,
  # and installs the first of two Prefix-SIDs for one algorithm.
  FRR = {
    asla_mask_too_long: { taken: true, printed: nil, added: [] },
    asla_l_flag_values: { taken: true, printed: "an ASLA with L, TE metric 100", added: [] },
    asla_l_flag_mixed: { taken: true, printed: "an ASLA with L; an ASLA, TE metric 100", added: [] },
    asla_conflict: { taken: true, printed: "an ASLA, TE metric 100; an ASLA, TE metric 200", added: [] },
    asla_srlg_no_link_id: { taken: true, printed: "an ASLA, TE metric 100", added: [] },
    admin_group_mismatch: { taken: true, printed: "an ASLA, Admin Group 1, Ext Admin Group 2", added: [] },
    fad_algorithm_range: { taken: true, fad: nil, added: [] },
    fad_subtlv_twice: { taken: true, fad: { priority: 0, exclude: [2], taking_part: true }, added: [] },
    fad_split_differs: { taken: true, fad: { priority: 200, exclude: [], taking_part: true }, added: [] },
    fad_split_subtlv_twice: { taken: true, fad: { priority: 0, exclude: [2], taking_part: true }, added: [] },
    fad_s_bit: { taken: true, fad: { priority: 0, exclude: [], taking_part: true }, added: [] },
    fad_eag_length: { taken: false, fad: nil, added: [] },
    fad_unsupported: { taken: true, fad: { priority: 0, exclude: [], taking_part: false }, added: [] },
    fapm_algorithm_range: { taken: true, printed: nil, added: [] },
    fapm_twice: { taken: true, printed: nil, added: [] },
    prefix_sid_algorithm_twice: { taken: true, printed: nil, added: [25_984] }
  }.freeze

  def setup
    ok, why = FrrLab.available?
    flunk "FRR interop asked for and cannot run: #{why}" if !ok && ENV["ISIS_FRR"] == "1"
    skip why unless ok
  end

  def teardown
    @lab&.stop
  end

  def frr_version = `#{FrrLab::FRR}/isisd --version`[/version (\S+)/, 1]

  def sequences
    own = ->(rows) { rows.find { _1["lsp_id"] == "#{S1}.00-00" }&.fetch("sequence") }
    frr = @lab.vtysh("show isis database").lines.filter_map { _1[/^s1\.00-00\s+\*?\s+\d+\s+0x(\h{8})/, 1]&.hex }.first
    [own.call(@lab.api("sim", "show.database", "level" => 1)), own.call(@lab.isisd("show.database", "level" => 1)), frr]
  end

  # isisd holds s1's latest LSP and has run on it; then 6 s for FRR.
  # Answers whether FRR took it too.
  def isisd_learned_and_frr_taken?
    s, i, = sequences
    return nil unless s && s == i

    sleep 6
    s2, i2, f = sequences
    return nil unless s2 == s && i2 == s

    f == s
  end

  def isisd_labels = @lab.isisd("show.labels").map { _1["label"] }.sort
  def frr_labels = @lab.frr_json("show mpls table json").keys.map(&:to_i).sort

  # Every finding isisd names: the FADs', the links', the SR data's.
  def isisd_findings
    fa = @lab.isisd("show.flex_algo")["levels"]["1"]["findings"]
    node = s1_node
    sr = @lab.isisd("show.segment_routing").dig("levels", "1", "findings")
    (fa + Array(node && node["link_findings"]) + sr).map { _1["name"] }
  end

  def s1_node = @lab.isisd("show.topology", "level" => 1)["nodes"].find { _1["id"] == "#{S1}.00" }

  FIXED = %w[id metric style interface_address neighbor_address adj_sids].freeze

  def isisd_reading(name, base)
    algo = @lab.isisd("show.flex_algo")["levels"]["1"]["algorithms"].find { _1["algorithm"] == K }
    w = algo && algo["winner"]
    fad = w && w["origin"] == S1 ? { priority: w["priority"], exclude: w["exclude_any"] || [], taking_part: algo["participating"] } : nil
    got = { taken: true, fad: fad, added: isisd_labels - base }
    if name.to_s.match?(/\Aasla|\Aadmin_group/)
      link = s1_node["neighbors"].find { _1["interface_address"] == "10.0.0.1" }
      got[:link] = link&.except(*FIXED)&.transform_keys(&:to_sym) || {}
    end
    got[:finding] = (isisd_findings & [name.to_s]).first
    got
  end

  # FRR's: the FAD it elects, from text; what it prints of the entry's
  # link or prefix in s1's LSP; the labels added.
  def frr_reading(name, base, taken)
    got = { taken: taken }
    if name.to_s.start_with?("fad")
      text = @lab.vtysh("show isis flex-algo #{K}")
      got[:fad] = if text.include?("Source: #{S1}")
                    { priority: Integer(text[/Priority: (\d+)/, 1]),
                      exclude: text[/Exclude-any admin-group:.*\n\s*Bit positions: ([\d, ]+)/, 1].to_s.split(",").map(&:to_i),
                      taking_part: text[/Local state: (.*?)\s*$/, 1] == "enabled" }
                  end
    else
      got[:printed] = frr_printed(name)
    end
    got[:added] = frr_labels - base
    got
  end

  # What FRR prints of the entry in s1's LSP: each ASLA of the second
  # link, its L flag and values; or a FAPM of the entry's prefix.
  def frr_printed(name)
    detail = @lab.vtysh("show isis database detail s1.00-00")
    if name.to_s.start_with?("fapm", "prefix")
      block = detail[/^  Extended IP Reachability: 10\.255\.250\..*?(?=^  \S|\z)/m].to_s
      fapm = block.lines.grep(/Flex-Algo|FAPM|Prefix Metric/i).map(&:strip)
      return fapm.empty? ? nil : fapm.join("; ")
    end
    link = detail[/Remote Interface IP Address\(es\): 10\.0\.0\.2\n(.*?)(?=^  \S|\z)/m, 1] or return nil
    aslas = link.split("Application Specific Link Attributes:").drop(1).map do |a|
      words = [a.include?("L flag: 1") ? "an ASLA with L" : "an ASLA"]
      words << "TE metric #{$1}" if a =~ /Traffic Engineering Metric: (\d+)/
      words << "Admin Group #{$1.strip}" if a =~ /\n\s*Admin Group: .*\n\s*Bit positions: ([\d, ]+)/
      words << "Ext Admin Group #{$1.strip}" if a =~ /Ext Admin Group: .*\n\s*Bit positions: ([\d, ]+)/
      words.join(", ")
    end
    aslas.empty? ? nil : aslas.join("; ")
  end

  def test_each_entry_to_isisd_and_frr
    @lab = SrFaultLab.new("ff#{Process.pid % 1000}", flex: true).start
    # Both hold s1's LSP and have label routes toward each other and r.
    assert @lab.wait_for(90) {
      s = sequences
      s[0] && s.uniq.size == 1 && ([16_002, 16_005] - isisd_labels).empty? && ([18_001, 18_005] - frr_labels).empty?
    }, "both receivers hold s1's LSP and their label routes\n#{@lab.report}"
    sleep 3
    base = { isisd: isisd_labels, frr: frr_labels }
    check_frr = frr_version == FRR_VERSION
    ISIS::Fault.flex_algo_catalog.each do |e|
      name = e[:name]
      answer = @lab.sim("/api/fault", "case" => name.to_s, "router" => "s1")
      index = answer.dig("context", "index") or flunk "#{name}: #{answer}"
      taken = nil
      assert @lab.wait_for(40) { !(taken = isisd_learned_and_frr_taken?).nil? }, "#{name}: isisd learns s1's LSP\n#{@lab.report}"
      mine = isisd_reading(name, base[:isisd])
      cell = FaultMatrix.flex_data_cell(name, mine, first: SrFaultLab::ISISD_SRGB + index)
      FaultMatrix.record(:flex, name, :isisd, cell)
      refute_equal false, cell[:agrees], "isisd, #{name}: #{cell[:text]}"
      assert_equal name.to_s, mine[:finding], "isisd names #{name}: #{cell[:text]}"
      theirs = frr_reading(name, base[:frr], taken)
      FaultMatrix.record(:flex, name, :frr, FaultMatrix.flex_data_cell(name, theirs, first: SrFaultLab::FRR_SRGB + index))
      assert_equal FRR.fetch(name), theirs, "FRR, #{name}, as recorded" if check_frr
      @lab.sim("/api/fault.clear", "router" => "s1")
      assert @lab.wait_for(30) { s = sequences; s[0] == s[1] && isisd_findings.empty? }, "#{name} cleared"
      sleep 6
    end
  end

  def test_every_entry_is_recorded_for_frr
    assert_equal ISIS::Fault.flex_algo_names, FRR.keys
  end
end
