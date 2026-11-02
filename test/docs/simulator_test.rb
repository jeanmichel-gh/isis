# frozen_string_literal: true

require_relative "../test_helper"

# docs/simulator.md lists every key the topology file takes, section by
# section, and no key the loader does not take. The lists come from the
# loader, so a new key fails here until the guide has it.
class TestDocsSimulator < Minitest::Test
  DOC = File.read(File.expand_path("../../docs/simulator.md", __dir__))

  # The keys in the table under "### HEADING", or "### Sections".
  def documented(heading)
    DOC[/^### #{Regexp.escape(heading)}\n(.*?)(?=\n###|\n## |\z)/m, 1].scan(/^\| `([a-z_]+)` \|/).flatten
  end

  def check(heading, keys)
    assert_equal keys.sort, documented(heading).sort, "docs/simulator.md, ### #{heading}"
  end

  T = ISIS::Sim::Topology

  def test_sections = check("Sections", T::TOP_KEYS)
  def test_grid = check("grid", T::GRID_KEYS)
  def test_routers = check("routers", T::ROUTER_KEYS)
  def test_prefixes = check("prefixes and externals", T::PREFIX_KEYS)
  def test_links = check("links", T::LINK_KEYS)

  def test_actions
    documented = DOC[/^## Actions\n(.*?)(?=\n## )/m, 1].scan(/^\| `([a-z.]+)` \|/).flatten
    assert_equal ISIS::Sim::Simulator::ACTIONS.keys.sort, documented.sort
    ISIS::Sim::Simulator::ACTIONS.each_value { |m| assert ISIS::Sim::Simulator.method_defined?(m), m }
  end

  # The example in the guide loads.
  def test_the_example_loads
    yaml = DOC[/```yaml\n(.*?)```/m, 1]
    t = T.from_hash(ISIS::ConfigFile.parse(yaml))
    assert_equal 17, t.systems.size
    assert_equal [], t.warnings
  end
end
