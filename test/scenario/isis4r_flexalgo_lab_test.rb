# frozen_string_literal: true

require_relative "../test_helper"
require "yaml"

# The isis4r-flexalgo lab (routescope/labs/isis4r-flexalgo), from its own
# files: each link's metric, delay and colors at both its ends, the FADs,
# the SRGBs and Prefix-SIDs. From them, each algorithm's path from r1 to
# r4 by RFC 9350 section 13's rules, and the labels its scenarios read, so
# a change to a file that moves one fails here before it fails in the lab.
class TestIsis4rFlexAlgoLab < Minitest::Test
  LAB = File.expand_path("../../routescope/labs/isis4r-flexalgo", __dir__)
  ROUTERS = %w[r1 r2 r3 r4].freeze

  def self.isisd(name) = YAML.load_file(File.join(LAB, name, "isisd.yml"))
  def self.frr = File.read(File.join(LAB, "f1", "frr.conf"))

  # { "eth1" => { metric:, delay:, red: } } of f1, from its frr.conf.
  def self.frr_interfaces
    frr.scan(/^interface (eth\d)\n(.*?)^exit/m).to_h do |name, block|
      [name, { metric: block[/isis metric (\d+)/, 1].to_i, delay: block[/delay (\d+) min/, 1].to_i,
               red: block.include?("affinity red") }]
    end
  end

  # Each link [a, b] => { metric:, delay:, red: } as a's end gives it.
  def self.read_links
    clab = YAML.load_file(File.join(LAB, "isis4r-flexalgo.clab.yml")).fetch("topology").fetch("links")
    ends = clab.map { |l| l.fetch("endpoints").map { _1.split(":") } }
    ends.flat_map { _1.permutation.to_a }.to_h do |(a, ifa), (b, _)|
      [[a, b], interface(a, ifa)]
    end
  end

  def self.interface(node, name)
    case node
    when "f1" then frr_interfaces.fetch(name)
    when "s1"
      i = YAML.load_file(File.join(LAB, "s1", "sim.yml")).dig("simulator", "interfaces").find { _1["name"] == name }
      { metric: i["metric"], delay: i["delay"], red: false }
    else
      i = isisd(node).fetch("interfaces").find { _1["name"] == name }
      { metric: i["metric"], delay: i["delay"], red: Array(i["affinity"]).include?("red") }
    end
  end

  LINKS = read_links

  # The shortest path from r1 to r4 in an algorithm: the systems it keeps,
  # the links it keeps, and the metric it reads; without the link +down+,
  # [a, b]. [cost, [hops]].
  def path(keep:, metric:, link: ->(_) { true }, down: nil)
    dist = { "r1" => [0, ["r1"]] }
    done = {}
    until dist.empty? || done.key?("r4")
      node, (cost, hops) = dist.reject { |n, _| done.key?(n) }.min_by { |_, (c, h)| [c, h] } || break
      done[node] = [cost, hops]
      LINKS.each do |(a, b), attrs|
        next unless a == node && keep.include?(b) && link.call(attrs) && !done.key?(b)
        next if down && [a, b].sort == down.sort

        c = cost + metric.call(attrs)
        dist[b] = [c, hops + [b]] if !dist.key?(b) || c < dist[b][0]
      end
    end
    done["r4"]
  end

  def test_each_link_is_the_same_at_both_ends
    LINKS.each do |(a, b), attrs|
      assert_equal attrs, LINKS.fetch([b, a]), "#{a}-#{b}"
    end
  end

  # Algorithm 0 over the top, 128 the delay over the bottom with f1 pruned,
  # 129 excluding red through f1.
  def test_three_algorithms_three_paths
    everyone = ROUTERS + %w[f1]
    assert_equal [20, %w[r1 r2 r4]], path(keep: everyone, metric: ->(l) { l[:metric] })
    assert_equal [4_000, %w[r1 r3 r4]], path(keep: ROUTERS, metric: ->(l) { l[:delay] })
    assert_equal [30, %w[r1 f1 r4]], path(keep: everyone, metric: ->(l) { l[:metric] }, link: ->(l) { !l[:red] })
  end

  # failover's moves: 128 over the top without the bottom, since f1 is
  # pruned from it; 129 over the bottom without f1, never the red top;
  # algorithm 0 through f1 without the top.
  def test_where_each_algorithm_goes_when_r1_loses_a_link
    everyone = ROUTERS + %w[f1]
    assert_equal %w[r1 r2 r4], path(keep: ROUTERS, metric: ->(l) { l[:delay] }, down: %w[r1 r3])[1]
    assert_equal %w[r1 r3 r4], path(keep: everyone, metric: ->(l) { l[:metric] }, link: ->(l) { !l[:red] }, down: %w[r1 f1])[1]
    assert_equal %w[r1 f1 r4], path(keep: everyone, metric: ->(l) { l[:metric] }, down: %w[r1 r2])[1]
  end

  def test_the_fads
    r4 = self.class.isisd("r4").fetch("flex_algo")
    assert_equal [{ "algorithm" => 128, "metric_type" => "delay", "priority" => 0 }, { "algorithm" => 129, "priority" => 100 }], r4
    (ROUTERS - %w[r4]).each do |n|
      assert_equal [128, 129], self.class.isisd(n).fetch("flex_algo").map { _1["algorithm"] }, n
      assert(self.class.isisd(n).fetch("flex_algo").none? { _1.fetch("advertise", true) }, "#{n} advertises no FAD")
    end
    conf = self.class.frr
    assert_match(/flex-algo 129\n  dataplane sr-mpls\n  advertise-definition\n  priority 200\n  affinity exclude-any red/, conf)
    assert_match(/flex-algo 128\n  dataplane sr-mpls\n exit/, conf)
  end

  # The labels the scenarios read: rN's SRGB at 20000 + 1000 N, index N,
  # 100 + N for 128, 200 + N for 129; f1's at 16000.
  def test_the_sids
    ROUTERS.each do |n|
      c = self.class.isisd(n)
      k = n[1].to_i
      assert_equal 20_000 + (1_000 * k), c.dig("segment_routing", "srgb", 0, "start"), n
      p = c.fetch("prefixes").first
      assert_equal [k, { "128" => 100 + k, "129" => 200 + k }], [p["sid"], p["algorithm_sids"].transform_keys(&:to_s)], n
    end
    conf = self.class.frr
    assert_includes conf, "segment-routing global-block 16000 16999"
    assert_includes conf, "segment-routing prefix 10.255.0.7/32 algorithm 129 index 207"
  end
end
