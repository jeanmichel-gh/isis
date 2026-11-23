# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/fault_matrix"

# docs/fault-matrix.md is written by `rake fault_matrix`, which needs
# root and FRR. This needs neither: it fails when the catalog gains or
# loses an entry the document does not show, so a new entry cannot go in
# without the matrix being run again. As bfd4r's and vtep4r's.
class TestFaultMatrixDoc < Minitest::Test
  DOC = File.read(File.expand_path("../../docs/fault-matrix.md", __dir__))

  # Each section's rows: { entry => its cells }.
  def rows(heading)
    section = DOC[/^## #{heading}\n(.*?)(?=^## |\z)/m, 1] or flunk "no section #{heading}"
    section.lines.grep(/\A\| `/).to_h { |l| [l[/\A\| `([^`]+)`/, 1].to_sym, l.split("|").map(&:strip)] }
  end

  def test_every_sr_entry
    assert_equal ISIS::Fault.names, rows("SR data").keys
  end

  def test_every_topology_on_real_routers
    assert_equal ISIS::Fault.topology_names - [:ti_lfa_one_way], rows("Topologies").keys
  end

  def test_every_packet
    assert_equal ISIS::Fault.packet_names, rows("Packets at the PLR").keys
  end

  def test_each_row_says_what_the_rfc_expects_as_the_catalog_does
    ISIS::Fault.catalog.each { |e| assert_equal FaultMatrix.expect_text(e, :sr), rows("SR data")[e[:name]][3] }
    t = rows("Topologies")
    t.each_key { |n| assert_equal FaultMatrix.expect_text(ISIS::Fault.topology(n), :topology), t[n][3], n }
    ISIS::Fault.packets.each { |e| assert_equal FaultMatrix.expect_text(e, :packet), rows("Packets at the PLR")[e[:name]][3] }
  end

  def test_two_receivers
    assert_equal ["isisd", "FRR isisd"], DOC[/^\| Entry .*$/].split("|").map(&:strip)[4..]
  end

  def test_every_cell_was_measured
    %w[SR\ data Topologies Packets\ at\ the\ PLR].each do |s|
      rows(s).each { |n, cells| refute_includes cells[4..5], "not run", "#{s}: #{n}" }
    end
  end

  def test_it_says_it_is_generated
    assert_match(/\*\*Generated\*\* by `rake fault_matrix` on \d{4}-\d\d-\d\d, Linux \S+,/, DOC)
  end

  # The words a cell is made of.
  def test_cells
    assert_equal({ text: "no label toward r; adds 25999", agrees: true },
                 FaultMatrix.sr_cell(:srgb_overlap, { route: nil, added: [25_999], dropped: [] }, own: 25_999, first: 17_005))
    assert_equal false, FaultMatrix.sr_cell(:algorithm_not_advertised, { route: 17_005, added: [25_993], dropped: [] },
                                            own: 25_993, first: 17_005)[:agrees]
    assert_equal false, FaultMatrix.sr_cell(:prefix_sid_vl_invalid, { taken: false, route: 17_005, added: [], dropped: [] },
                                            own: 1, first: 17_005)[:agrees]
    assert_nil FaultMatrix.sr_cell(:prefix_sid_duplicate, { route: 17_005, added: [1], dropped: [] }, own: 1, first: 1)[:agrees]
    entry = ISIS::Fault.topology(:ti_lfa_pq_node)
    rfc = FaultMatrix.rfc_repair(entry)
    assert FaultMatrix.topology_cell(rfc.merge(case: :pq_node), rfc)[:agrees]
    assert FaultMatrix.topology_cell({ none: true }, { unprotected: :no_path })[:agrees]
    assert_equal "**dropped**", FaultMatrix.shown(FaultMatrix.cell("dropped", false))
    assert_equal "dropped; ICMP 3/0 back", FaultMatrix.packet_text(at_a: nil, back: [[3, 0], :packet_ip])
  end
end
