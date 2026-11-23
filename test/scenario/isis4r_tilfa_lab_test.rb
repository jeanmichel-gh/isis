# frozen_string_literal: true

require_relative "../test_helper"
require "yaml"

# The isis4r-tilfa lab (routescope/labs/isis4r-tilfa), from its own files:
# the links of its clab file, each router's metrics and Adj-SIDs from its
# isisd.yml, FRR's and the simulator's from theirs. Spf::TiLfa computes
# the repairs its ABOUT.md and its scenarios rely on, so a change to a
# file that moves one fails here before it fails in the lab.
class TestIsis4rTiLfaLab < Minitest::Test
  LAB = File.expand_path("../../routescope/labs/isis4r-tilfa", __dir__)

  # { [a, b] => metric } one way, and the adjacencies that carry an
  # Adj-SID, read from the lab's files.
  def self.read_lab
    clab = YAML.load_file(File.join(LAB, "isis4r-tilfa.clab.yml")).fetch("topology")
    ends = clab.fetch("links").map { |l| l.fetch("endpoints").map { |e| e.split(":") } }
    metric = {}
    adj = {}
    ends.each do |pair|
      pair.permutation.each do |(a, ifa), (b, _)|
        metric[[a, b]], adj[[a, b]] = interface(a, ifa)
      end
    end
    sim = YAML.load_file(File.join(LAB, "s1", "sim.yml"))
    sim.fetch("links").each do |l|
      metric[[l["from"], l["to"]]] = metric[[l["to"], l["from"]]] = l.fetch("metric")
      adj[[l["from"], l["to"]]] = adj[[l["to"], l["from"]]] = true
    end
    [metric, adj.select { |_, v| v }.to_h { |k, _| [k, 1] }]
  end

  # A node's metric and whether it gives an Adj-SID, on one interface.
  def self.interface(node, name)
    case node
    when "f1"
      conf = File.read(File.join(LAB, "f1", "frr.conf"))
      block = conf[/^interface #{name}\n(.*?)^exit/m, 1] or raise "f1 has no #{name}"
      [block[/isis metric (\d+)/, 1].to_i, true]
    when "s1"
      i = YAML.load_file(File.join(LAB, "s1", "sim.yml")).dig("simulator", "interfaces").find { |x| x["name"] == name }
      [i.fetch("metric"), true]
    else
      i = YAML.load_file(File.join(LAB, node, "isisd.yml")).fetch("interfaces").find { |x| x["name"] == name }
      [i.fetch("metric"), i["adj_sid"] != false]
    end
  end

  METRIC, ADJ = read_lab
  GRAPH = ISIS::Spf::Graph.new(METRIC, node_sids: METRIC.keys.flatten.uniq.to_h { |n| [n, 1] }, adj_sids: ADJ)

  def repairs(root, neighbor, kind)
    t = ISIS::Spf::TiLfa.new(GRAPH, root: root)
    t.protect(t.send(kind, neighbor))
  end

  def segments(repair)
    repair.segments.map { |s| s[:node] ? [:node, s[:node]] : [:adj, *s[:adj]] }
  end

  def test_the_ring_and_its_chord
    assert_equal 1000, METRIC[%w[r4 r5]]
    assert_equal 1000, METRIC[%w[r5 r6]]
    assert_equal 10, METRIC[%w[r2 r5]]
    assert_equal 10, METRIC[%w[f1 r6]]
  end

  # RFC 9855 5.4: with r2 down, P is r6 and Q is r4, through f1.
  def test_r1s_node_repair_to_r3_has_p_and_q_apart
    r = repairs("r1", "r2", :node).fetch("r3")
    assert_equal :p_and_q_apart, r.case
    assert_equal "f1", r.first_hop
    assert_equal %w[r6 r4], [r.p, r.q]
    assert_equal [[:node, "r6"], [:adj, "r6", "r5"], [:adj, "r5", "r4"]], segments(r)
  end

  def test_r1_protects_t1_and_r5_and_not_r2_itself
    got = repairs("r1", "r2", :node)
    assert_equal [[:node, "r6"], [:adj, "r6", "r5"], [:adj, "r5", "r4"]], segments(got.fetch("t1"))
    assert_equal [[:node, "r6"], [:adj, "r6", "r5"]], segments(got.fetch("r5"))
    assert_equal :neighbor, got.fetch("r2").reason
  end

  def test_r1s_link_repair_to_r3_ends_at_r5
    r = repairs("r1", "r2", :link).fetch("r3")
    assert_equal [[:node, "r6"], [:adj, "r6", "r5"]], segments(r)
    assert_equal "r5", r.q
  end

  def test_r2s_link_repair_to_r1_goes_by_the_chord
    r = repairs("r2", "r1", :link).fetch("r1")
    assert_equal "r5", r.first_hop
    assert_equal [[:adj, "r5", "r6"]], segments(r)
  end

  # r5's link to r2 and r6's to f1 carry no Adj-SID, so the lab's Adj-SID
  # labels hold on every start (ABOUT.md).
  def test_two_adjacencies_have_no_adj_sid
    refute ADJ.key?(%w[r5 r2])
    refute ADJ.key?(%w[r6 f1])
    assert ADJ.key?(%w[r6 r5])
  end
end
