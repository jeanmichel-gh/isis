# frozen_string_literal: true

require "json"
require "fileutils"

# The fault matrix (routescope docs/design/ti-lfa.md, step 6e1): what
# isisd and FRR's isisd do with each entry of the fault catalog, beside
# what the RFC expects, as bfd4r's and vtep4r's docs/fault-matrix.md.
#
# The interop tests measure; with ISIS_MATRIX_OUT set to a directory,
# each also records what it measured there, one JSON line per cell
# (FaultMatrix.record). `rake fault_matrix` runs them so and writes
# docs/fault-matrix.md from the lines (FaultMatrix.render). Nothing is
# measured twice: the matrix is what the interop tests found.
#
# Five groups, as the catalog's: SR data (frr_sr_fault_test.rb), the
# topologies (frr_ti_lfa_test.rb), the packets at the PLR
# (kernel_ti_lfa_test.rb), flex-algo's data (frr_flex_fault_test.rb)
# and flex-algo's topologies (frr_flex_algo_topology_test.rb). The behaviours act over time and
# are not in it.
module FaultMatrix
  RECEIVERS = { isisd: "isisd", frr: "FRR isisd" }.freeze
  GROUPS = %i[sr topology packet flex flex_topology].freeze

  module_function

  # Writes one cell, when ISIS_MATRIX_OUT names a directory.
  def record(group, name, receiver, cell)
    dir = ENV.fetch("ISIS_MATRIX_OUT", nil) or return
    FileUtils.mkdir_p(dir)
    line = JSON.generate(group: group, name: name, receiver: receiver, text: cell[:text], agrees: cell[:agrees])
    File.open(File.join(dir, "cells.jsonl"), "a") { |f| f.puts(line) }
  end

  # The cells in +dir+: { [group, name, receiver] => { text:, agrees: } },
  # the last of each.
  def load(dir)
    File.readlines(File.join(dir, "cells.jsonl")).to_h do |l|
      c = JSON.parse(l, symbolize_names: true)
      [[c[:group].to_sym, c[:name].to_sym, c[:receiver].to_sym], { text: c[:text], agrees: c[:agrees] }]
    end
  end

  # A cell: its words, and whether it does what the RFC expects (true,
  # false, or nil where the RFC leaves it open or isis4r has a gap).
  def cell(text, agrees) = { text: text, agrees: agrees }

  def shown(cell)
    return "not run" unless cell

    cell[:agrees] == false ? "**#{cell[:text]}**" : cell[:text]
  end

  # --- The SR data group ---------------------------------------------

  # What the RFC expects a receiver to show, by entry: :no_label_to_next_hop
  # when the next hop's SRGB is ignored (RFC 8660 2.10.1); :first_srgb when
  # the first SR-Capabilities is used; :no_label when the Prefix-SID is
  # ignored; :record where the RFC leaves it open (8660 2.5's tie-break is
  # RECOMMENDED) or isis4r has no code (the gaps channel).
  SR_OUTCOME = {
    srgb_range_zero: :no_label_to_next_hop, srgb_overlap: :no_label_to_next_hop,
    srgb_reserved: :no_label_to_next_hop, sr_capabilities_twice: :first_srgb,
    prefix_sid_vl_invalid: :no_label, algorithm_not_advertised: :no_label,
    prefix_sid_label: :record, prefix_sid_duplicate: :record
  }.freeze

  # +got+: { route: the out label toward r through s1, or nil; added: the
  # in-labels the fault added; dropped: those it took away; finding: }.
  # +own+ is the label the fault's index takes in the receiver's SRGB,
  # +first+ the label r's route takes in s1's first block.
  # +taken+ false: the receiver discarded s1's new LSP and kept the
  # previous, where the RFC ignores only the faulty part.
  def sr_cell(name, got, own:, first:)
    if got[:taken] == false
      return cell("discards s1's LSP, keeps the one before; label #{got[:route] || 'none'} toward r", false)
    end

    route = got[:route] ? "label #{got[:route]} toward r" : "no label toward r"
    parts = [route]
    parts << "adds #{got[:added].join(', ')}" unless got[:added].empty?
    parts << "drops #{got[:dropped].join(', ')}" unless got[:dropped].empty?
    parts << "finding #{got[:finding]}" if got[:finding]
    agrees = case SR_OUTCOME.fetch(name)
             when :no_label_to_next_hop then got[:route].nil?
             when :first_srgb then got[:route] == first
             when :no_label then !got[:added].include?(own)
             end
    cell(parts.join("; "), agrees)
  end

  # --- The topologies --------------------------------------------------

  # A repair as TopologyLab#plr_repair reads it, in words.
  def repair_text(r)
    return "none" if r.nil?
    return "no backup" if r[:none]
    return "unprotected, #{r[:unprotected]}" if r[:unprotected]
    return "ECMP" if r[:ecmp]

    segs = r[:segments].map { |k, *n| k == :node ? "Node-SID(#{n[0]})" : k == :adj ? "Adj-SID(#{n.join('-')})" : "label #{n[0]}" }
    text = "via #{r[:first_hop]}: #{segs.empty? ? 'no label' : segs.join(', ')}"
    text += " (#{r[:segments].size} labels)" if r[:segments].size > 6
    text = "link fallback, #{text}" if r[:fallback]
    text
  end

  # Whether +got+ is +expected+, the RFC's repair with 7.1's last label:
  # for no repair or ECMP, no backup also agrees.
  # isisd's link fallback for a node repair too deep is its own choice
  # (docs/ti-lfa.md), not judged.
  def topology_cell(got, expected)
    agrees = if got&.dig(:fallback) then nil
             elsif expected[:unprotected] || expected[:ecmp]
               got == expected || got == { none: true }
             else
               got&.slice(:first_hop, :segments) == expected.slice(:first_hop, :segments)
             end
    cell(repair_text(got), agrees)
  end

  # --- The packets -----------------------------------------------------

  # +got+: { at_a: { segments:, ttl: } or nil, back: [[type, code], name] or nil }.
  def packet_text(got)
    a = got[:at_a]
    text = a ? "reaches A: #{repair_text(first_hop: 'A', segments: a[:segments]).delete_prefix('via A: ')}, TTL #{a[:ttl]}" : "dropped"
    got[:back] ? "#{text}; ICMP #{got[:back][0].join('/')} back" : text
  end

  def packet_cell(entry, got, repair)
    agrees = entry[:expect] == :repair ? got[:at_a] == { segments: repair, ttl: 63 } : nil
    cell(packet_text(got), agrees)
  end

  # --- Flex-algo's data -------------------------------------------------

  # What RFC 9350, RFC 9479 and RFC 7308 expect a receiver to read of each
  # flex-algo entry, by its rfc action: s1's link's attributes for
  # flex-algo, as Spf::LinkAttributes gives them; s1's FAD for 128, or
  # none; or the label routes the entry added. :record where isisd does
  # not read the entry yet: a FAPM waits for the M flag (docs/design/
  # flex-algo.md, decision 2).
  FLEX_OUTCOME = {
    asla_mask_too_long: { link: {} }, asla_l_flag_values: { link: { asla_legacy: true } },
    asla_l_flag_mixed: { link: { asla_legacy: true } }, asla_conflict: { link: { te_metric: 100 } },
    asla_srlg_no_link_id: { link: { te_metric: 100 } }, admin_group_mismatch: { link: { affinity: [1] } },
    fad_algorithm_range: { fad: nil }, fad_subtlv_twice: { fad: nil },
    fad_split_differs: { fad: { priority: 100, exclude: [], taking_part: true } },
    fad_split_subtlv_twice: { fad: { priority: 0, exclude: [1], taking_part: true } },
    fad_s_bit: { fad: nil }, fad_eag_length: { fad: nil },
    fad_unsupported: { fad: { priority: 0, exclude: [], taking_part: false } },
    fapm_algorithm_range: :record, fapm_twice: :record,
    prefix_sid_algorithm_twice: { labels: :first }
  }.freeze

  # A receiver's reading, in words.
  def flex_data_text(name, got)
    return "discards s1's LSP, keeps the one before" if got[:taken] == false

    parts = []
    case name.to_s
    when /\Aasla|admin_group/
      parts << (got[:link] ? "link #{link_text(got[:link])}" : "prints #{got[:printed] || 'nothing for the link'}")
    when /\Afad/
      parts << fad_text(got[:fad])
    when /\Afapm/
      parts << if got[:printed] then "prints #{got[:printed]}"
               elsif got.key?(:printed) then "prints no FAPM"
               else "no FAPM read"
               end
    else
      parts << (got[:added].empty? ? "no label added" : "adds #{got[:added].join(', ')}")
    end
    parts << "finding #{got[:finding]}" if got[:finding]
    parts.join("; ")
  end

  def link_text(link)
    return "with no attributes" if link.empty?

    link.map { |k, v| k == :asla_legacy ? "from the legacy sub-TLVs (L set)" : "#{k.to_s.tr('_', ' ')} #{Array(v).join(', ')}" }
        .join(", ")
  end

  def fad_text(fad)
    return "no FAD, not taking part" unless fad

    text = "s1's FAD, priority #{fad[:priority]}"
    text += ", exclude #{fad[:exclude].join(', ')}" unless fad[:exclude].empty?
    text + (fad[:taking_part] ? ", taking part" : ", not taking part")
  end

  # +got+: { taken:, link:, fad:, added:, finding:, printed: } as the
  # receiver showed it; +first+ the label the entry's first Prefix-SID
  # takes. Only what the receiver shows it uses is judged: FRR prints a
  # link's attributes without saying which it uses.
  def flex_data_cell(name, got, first: nil)
    want = FLEX_OUTCOME.fetch(name)
    agrees = if got[:taken] == false then false
             elsif want == :record then nil
             elsif want.key?(:link) then got.key?(:link) ? got[:link] == want[:link] : nil
             elsif want.key?(:fad) then got[:fad] == want[:fad]
             else got[:added] == [first]
             end
    cell(flex_data_text(name, got), agrees)
  end

  # --- Flex-algo's topologies ------------------------------------------

  # What RFC 9350 expects of S in a flex-algo topology entry, as
  # FlexTopologyLab#flex_reading reads S: not taking part; or the
  # winner, and D's route or none; and a repair, its first hop and
  # segments.
  def flex_expected(entry)
    e = entry[:expect]
    return { taking_part: false } if e[:taking_part] == false

    out = { winner: e[:winner] }
    if e[:unreachable] then out[:unreachable] = true
    else out.merge!(first_hops: e[:first_hops], metric: e[:metric])
    end
    if (r = e[:repair])
      q = r.fetch(:q, r[:first_hop])
      last = q == "D" ? [] : [[:node, "D"]]
      out[:repair] = { first_hop: r[:first_hop], segments: r[:segments] + last }
    end
    out
  end

  def flex_topology_text(r)
    return "none" if r.nil?
    return r[:frr_text] if r[:frr_text]
    if r[:taking_part] == false
      return r[:state] ? "not taking part: winner #{r[:winner]}, #{r[:state]}" : "not taking part"
    end

    parts = ["winner #{r[:winner]}"]
    parts << (r[:unreachable] ? "D unreachable" : "by #{r[:first_hops].join(' and ')}, metric #{r[:metric]}")
    parts << "repair #{repair_text(r[:repair])}" if r.key?(:repair)
    parts.join("; ")
  end

  def flex_cell(got, expected)
    seen = got && got[:repair] ? got.merge(repair: got[:repair].slice(:first_hop, :segments)) : got
    cell(flex_topology_text(got), seen == expected)
  end

  def flex_expect_text(entry)
    rfc = entry[:rfc][/RFC (\d+) section ([\d.]+)/] && "RFC #{$1} #{$2}"
    "#{entry[:expect]} (#{rfc})"
  end

  # --- The document ----------------------------------------------------

  def expect_text(entry, group)
    case group
    when :sr
      rfc = entry[:rfc][/RFC (\d+) section ([\d.]+)/] && "RFC #{$1} #{$2}"
      entry[:channel] == :gaps ? "a gap of isis4r (#{rfc})" : "#{entry[:expect]} (#{rfc})"
    when :topology then repair_text(rfc_repair(entry))
    when :packet then entry[:expect] == :repair ? "the repair, then D's label in Q's SRGB" : "record"
    when :flex then flex_expect_text(entry)
    when :flex_topology then flex_topology_text(flex_expected(entry))
    end
  end

  # The RFC's repair for a topology entry, with 7.1's last label.
  def rfc_repair(entry)
    e = entry[:expect]
    return { unprotected: e[:unprotected] } if e[:unprotected]
    return { ecmp: true } if e[:ecmp]

    last = e[:q] == entry[:destination] ? [] : [[:node, entry[:destination]]]
    { first_hop: e[:first_hop], segments: e[:segments] + last }
  end

  def render(cells, versions:, date:, kernel:)
    rows = lambda do |group, entries, what|
      entries.map do |e|
        mine = RECEIVERS.keys.map { |r| shown(cells[[group, e[:name], r]]) }
        "| `#{e[:name]}` | #{what.call(e)} | #{expect_text(e, group)} | #{mine.join(' | ')} |"
      end
    end
    head = "| Entry | What | RFC expects | #{RECEIVERS.values.join(' | ')} |\n| --- | --- | --- | --- | --- |"
    differ = cells.select { |_, c| c[:agrees] == false }.keys.map { |g, n, r| "`#{n}` (#{RECEIVERS[r]})" }
    <<~DOC
      # The fault matrix

      What isisd and FRR's isisd do with each entry of the fault catalog
      (`ISIS::Fault`, `docs/protocol-testing.md`), beside what the RFC
      expects. As bfd4r's and vtep4r's `docs/fault-matrix.md`.

      **Generated** by `rake fault_matrix` on #{date}, Linux #{kernel},
      #{versions}. Do not edit it by hand; run again, as root:

      ```sh
      sudo env "PATH=$PATH" ISIS_FRR=1 rake fault_matrix
      ```

      It runs the interop tests that measure each group, in network
      namespaces, and writes what they found. A cell in bold differs from
      what the RFC expects. isisd is held to the RFC by those tests, FRR
      to what it did on its recorded version.

      ## SR data

      `test/interop/frr_sr_fault_test.rb`. An isis4r-sim, s1, faces isisd
      and FRR at once, with one simulated system, r, behind it. Each entry
      goes in s1's own LSP, so s1 is the next hop whose SR data is at
      fault. A cell says the receiver's label toward r's loopback, the
      label routes the entry added or took away, and isisd's finding.

      #{head}
      #{rows.call(:sr, ISIS::Fault.catalog, ->(e) { e[:description] }).join("\n")}

      `prefix_sid_label` is a gap: isis4r has no code for a Prefix-SID
      carried as a label. `prefix_sid_duplicate` is recorded: RFC 8660 2.5
      recommends a tie-break that keeps one of the colliding prefixes,
      which isis4r does not build, so it leaves both out.

      ## Topologies

      `test/interop/frr_ti_lfa_test.rb`, on real routers in network
      namespaces: isisd at every system, the PLR isisd or FRR. A repair is
      read as the routers forward it, from the first hop. `ti_lfa_one_way`
      stays a unit test: two real routers report a link both ways or
      neither.

      #{head}
      #{rows.call(:topology, ISIS::Fault.topologies - [ISIS::Fault.topology(:ti_lfa_one_way)], ->(e) { e[:description] }).join("\n")}

      isisd's node repair on `ti_lfa_too_deep` falls back to the link's,
      as its node protection does (`docs/ti-lfa.md`). FRR shows no backup
      where there is no repair, or another primary next hop.

      ## Flex-algo data

      `test/interop/frr_flex_fault_test.rb`. The same s1 as for SR data,
      with isisd and FRR each taking part in algorithm #{ISIS::Fault::FLEX_ALGO} and advertising
      no FAD, so a FAD in s1's LSP is the only one. A link entry is a second
      link from s1 toward FRR, 10.0.0.1 to 10.0.0.2. A cell says what the
      receiver reads of it: isisd the attributes it uses, FRR what it
      prints, which does not say which it uses; s1's FAD as the receiver
      elects it; or the label routes it added.

      #{head}
      #{rows.call(:flex, ISIS::Fault.flex_algo_catalog, ->(e) { e[:description] }).join("\n")}

      isisd reads no FAPM: FAPMs wait for the M flag (`docs/design/flex-algo.md`,
      decision 2). It uses the first of two Prefix-SIDs for one algorithm,
      and names no finding for it: `Spf::PrefixMetrics`, which makes the
      FAPM and Prefix-SID findings, is not called by isisd yet.

      ## Flex-algo topologies

      `test/interop/frr_flex_algo_topology_test.rb`, on real routers in
      network namespaces, as the topologies above: isisd at every system,
      S isisd or FRR. Every system takes part in algorithm #{ISIS::Fault::FLEX_ALGO} but those
      the entry leaves out. A cell says the FAD S selects, and S's route
      to D in #{ISIS::Fault::FLEX_ALGO}: its first hops and metric.

      #{head}
      #{rows.call(:flex_topology, ISIS::Fault.flex_topologies, ->(e) { e[:description] }).join("\n")}

      ## Packets at the PLR

      `test/interop/kernel_ti_lfa_test.rb`, on `ti_lfa_pq_node`. The PLR's
      daemons are stopped before the link to F loses carrier, so what
      follows is the kernel's alone, under the routes each PLR installed.
      H sends each packet; A and H capture. `packet_prefix_sid` is a
      known gap of isisd: a label route has no backup in the kernel
      (routescope `docs/design/ti-lfa.md`, step 2c).

      #{head}
      #{rows.call(:packet, ISIS::Fault.packets, ->(e) { e[:description] }).join("\n")}

      ## Behaviours

      The catalog's behaviours act over time and are not in the matrix.
      `test/unit/sim/behaviour_test.rb` runs each against a PLR.

      #{differ.empty? ? 'Every receiver does what the RFC expects in every case it was given.' : "Differs from the RFC: #{differ.join(', ')}."}
    DOC
  end
end
