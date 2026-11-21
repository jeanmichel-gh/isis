# frozen_string_literal: true

require_relative "../../test_helper"
require "tmpdir"

# The simulated area's file: what it expands to, and what it refuses.
class TestSimTopology < Minitest::Test
  SIM = { "system_id" => "0000.0000.0009", "hostname" => "s1", "areas" => ["49.0001"], "level" => 1,
          "interfaces" => [{ "name" => "eth1", "ip_addresses" => ["10.0.14.2"] }] }.freeze

  def topo(h = {})
    ISIS::Sim::Topology.from_hash({ "simulator" => SIM }.merge(h))
  end

  def refused(h)
    e = assert_raises(ISIS::Sim::Topology::Error) { ISIS::Sim::Topology.from_hash(h) }
    e.message
  end

  def grid(extra = {})
    topo({ "grid" => { "columns" => 3, "rows" => 2, "metric" => 10, "system_id_base" => "0000.0001.0000",
                       "loopbacks" => "10.200.0.0/24" },
           "links" => [{ "from" => "s1", "to" => "r1c1" }] }.merge(extra))
  end

  def test_the_simulator
    t = topo
    s = t.simulator
    assert_equal ["s1", "0000.0000.0009", [1], ["49.0001"], true], [s.name, s.system_id, s.levels, s.areas, s.simulator?]
    assert_same s, t.system("sim")
    assert_equal [{ name: "eth1", ip_addresses: ["10.0.14.2"], network: "point-to-point" }], t.router_config[:interfaces]
    assert_equal ISIS::Database::MAX_AGE, t.lsp_lifetime
    assert_equal :wide, t.metric_style
  end

  # Row by row: r1c1 is the base plus 0x0101, r2c3 plus 0x0203; a loopback
  # each from the block, in the same order; links right and down.
  def test_grid
    t = grid
    assert_equal %w[r1c1 r1c2 r1c3 r2c1 r2c2 r2c3], t.systems.map(&:name)
    assert_equal ["0000.0001.0101", "0000.0001.0203"], [t.system("r1c1"), t.system("r2c3")].map(&:system_id)
    assert_equal ["10.200.0.1/32", "10.200.0.6/32"], [t.system("r1c1"), t.system("r2c3")].map(&:loopback)
    assert_equal [{ prefix: "10.200.0.6/32", metric: 0 }], t.system("r2c3").prefixes.map(&:to_h)
    assert_equal %w[r1c1--r1c2 r1c1--r2c1 r1c2--r1c3 r1c2--r2c2 r1c3--r2c3 r2c1--r2c2 r2c2--r2c3 s1--r1c1],
                 t.links.map(&:name).sort
    assert(t.links.all? { |l| l.metric == 10 && l.levels == [1] && l.up? })
    assert_equal [2, 1], t.system("r2c1").grid
    assert_equal({ systems: 6, links: 8, prefixes: 6, externals: 0 }, t.counts)
  end

  def test_a_block_too_small_for_the_grid
    assert_includes refused("simulator" => SIM, "grid" => { "rows" => 3, "columns" => 3, "loopbacks" => "10.0.0.0/29" }),
                    "grid.loopbacks: 10.0.0.0/29 holds fewer than the 9 the grid needs"
  end

  # A router named for a grid system adds to it; any other is new.
  def test_routers_add_to_the_grid_or_join_it
    t = grid("routers" => [
               { "name" => "r2c3", "prefixes" => [{ "prefix" => "30.0.0.0/24", "count" => 3, "metric" => 5 }],
                 "overload" => true },
               { "name" => "edge", "system_id" => "0000.0000.0100", "level" => "1-2", "attached" => true,
                 "loopback" => "10.255.1.1", "externals" => [{ "prefix" => "50.0.0.0/24", "count" => 2, "metric" => 20 }] }
             ],
             "links" => [{ "from" => "s1", "to" => "r1c1" }, { "from" => "r2c3", "to" => "edge", "metric" => 5 }])
    r = t.system("r2c3")
    assert_equal %w[10.200.0.6/32 30.0.0.0/24 30.0.1.0/24 30.0.2.0/24], r.prefixes.map(&:prefix)
    assert_equal [0, 5, 5, 5], r.prefixes.map(&:metric)
    assert_equal ["30.0.0.0/24"] * 3, r.prefixes.drop(1).map(&:group)
    assert r.overload
    e = t.system("edge")
    assert_equal [[1, 2], true, "10.255.1.1/32"], [e.levels, e.attached, e.loopback]
    assert_equal %w[50.0.0.0/24 50.0.1.0/24], e.externals.map(&:prefix)
    assert_equal [1], t.link("r2c3--edge").levels
  end

  def test_ipv6_prefixes_expand_too
    t = topo("routers" => [{ "name" => "x", "system_id" => "0000.0000.0100",
                             "prefixes" => [{ "prefix" => "2001:db8::/64", "count" => 2 }] }])
    assert_equal ["2001:db8::/64", "2001:db8:0:1::/64"], t.system("x").prefixes.map(&:prefix)
    assert_equal [10, 10], t.system("x").prefixes.map(&:metric)
  end

  def test_links_by_name_either_way_or_number
    t = grid
    assert_same t.link("r1c1--r1c2"), t.link("r1c2--r1c1")
    assert_same t.links.first, t.link(1)
    assert_same t.links.first, t.link("1")
    assert_nil t.link("r1c1--r2c3")
  end

  def test_one_way_and_down_are_kept
    t = topo("routers" => [{ "name" => "x", "system_id" => "0000.0000.0100" }],
             "links" => [{ "from" => "s1", "to" => "x", "one_way" => true, "state" => "down" }])
    l = t.link("s1--x")
    assert_equal [true, false], [l.one_way, l.up?]
  end

  # A link at the levels both ends run, Level 1 only with an area in
  # common; none at all is refused.
  def test_link_levels
    t = topo("simulator" => SIM.merge("level" => "1-2"),
             "routers" => [{ "name" => "a", "system_id" => "0000.0000.0101", "level" => "1-2", "areas" => ["49.0002"] },
                           { "name" => "b", "system_id" => "0000.0000.0102", "level" => 2 }],
             "links" => [{ "from" => "s1", "to" => "a" }, { "from" => "s1", "to" => "b" }])
    assert_equal [[2], [2]], [t.link("s1--a").levels, t.link("s1--b").levels]
    m = refused("simulator" => SIM,
                "routers" => [{ "name" => "a", "system_id" => "0000.0000.0101", "areas" => ["49.0002"] },
                              { "name" => "b", "system_id" => "0000.0000.0102", "level" => 2 }],
                "links" => [{ "from" => "s1", "to" => "a" }, { "from" => "s1", "to" => "b" }])
    assert_includes m, "links[0]: s1--a: no level in common (Level 1 needs an area in common)"
    assert_includes m, "links[1]: s1--b: no level in common"
  end

  # The simulator's own interfaces are isisd's, so a key isisd does not
  # know is refused here too, with where it is.
  def test_an_unknown_interface_key
    m = refused("simulator" => SIM.merge("interfaces" => [{ "name" => "eth1", "bdf" => true }]),
                "routers" => [{ "name" => "x", "system_id" => "0000.0000.0100" }],
                "links" => [{ "from" => "s1", "to" => "x" }])
    assert_includes m, "simulator: interface eth1: unknown key bdf;"
  end

  # What a metric style cannot carry is refused, with the limit; what it
  # can carry, however odd, is kept.
  def test_metric_limits
    t = topo("routers" => [{ "name" => "x", "system_id" => "0000.0000.0100",
                             "prefixes" => [{ "prefix" => "10.1.0.0/16", "metric" => 0xFFFFFFFF }] }],
             "links" => [{ "from" => "s1", "to" => "x", "metric" => 0xFFFFFF }])
    assert_equal [0xFFFFFF, 0xFFFFFFFF], [t.link(1).metric, t.system("x").prefixes.first.metric]
    m = refused("simulator" => SIM.merge("metric_style" => "narrow"),
                "routers" => [{ "name" => "x", "system_id" => "0000.0000.0100",
                                "prefixes" => [{ "prefix" => "10.1.0.0/16", "metric" => 64 }] }],
                "links" => [{ "from" => "s1", "to" => "x", "metric" => 64 }])
    assert_includes m, "routers[0].prefixes[0].metric: is a whole number, 0 to 63 (the most narrow metrics carry is 63)"
    assert_includes m, "links[0].metric: is a whole number, 0 to 63 (the most narrow metrics carry is 63)"
    assert_includes refused("simulator" => SIM, "links" => [], "routers" => [{ "name" => "x", "system_id" => "0000.0000.0100" }],
                            "grid" => { "rows" => 1, "columns" => 2, "metric" => 0x1000000 }),
                    "grid.metric: is a whole number, 0 to 16777215 (the most wide metrics carry is 16777215)"
  end

  # Every problem at once, each with where it is.
  def test_every_problem_is_reported
    m = refused("simulator" => SIM.merge("lsp_lifetime" => 70_000), "grids" => {},
                "routers" => [{ "name" => "x", "system_id" => "0000.0000.0009" },
                              { "name" => "y", "system_id" => "1234", "colour" => "red" },
                              { "name" => "z", "system_id" => "0000.0000.0102",
                                "prefixes" => [{ "prefix" => "10.1.1.1/24" }, { "prefix" => "255.255.255.0/24", "count" => 2 }] }],
                "links" => [{ "from" => "s1", "to" => "nobody" }, { "from" => "z", "to" => "z" },
                            { "from" => "s1", "to" => "z" }, { "from" => "z", "to" => "s1" }])
    assert_match(/\A.*: 10 problems\n/, m)
    ["top level: unknown key grids; one of simulator, grid, routers, links",
     "simulator.lsp_lifetime: is a whole number, 1 to 65535",
     "routers[1]: unknown key colour",
     "routers[1].system_id: 1234 is 2 octets; a System ID here is 6",
     "routers[2].prefixes[0].prefix: 10.1.1.1/24 has host bits set; the network is 10.1.1.0/24",
     "routers[2].prefixes[1].count: 2 blocks from 255.255.255.0/24 run past the address space",
     "routers: System ID 0000.0000.0009 is given to s1 and x",
     "links[0].to: no system named nobody",
     "links[1]: z to itself",
     "links[3]: z--s1 is there already; a parallel link would share its name"].each { |e| assert_includes m, e }
  end

  def test_a_grid_system_keeps_its_id
    assert_includes refused("simulator" => SIM, "grid" => { "rows" => 1, "columns" => 1 },
                            "routers" => [{ "name" => "r1c1", "system_id" => "0000.0000.0100" }]),
                    "routers[0].system_id: r1c1 is a grid system, whose System ID the grid gives"
  end

  def test_the_simulator_is_needed
    assert_includes refused("grid" => { "rows" => 1, "columns" => 1 }), "simulator: is needed"
    assert_includes refused("simulator" => SIM.merge("level" => 3)), "simulator: level is 1, 2 or 1-2, not 3"
    assert_includes refused("simulator" => SIM.except("system_id")), "simulator.system_id: is needed"
  end

  def test_systems_no_link_reaches_are_a_warning
    t = topo("routers" => [{ "name" => "a", "system_id" => "0000.0000.0101" },
                           { "name" => "b", "system_id" => "0000.0000.0102" }],
             "links" => [{ "from" => "s1", "to" => "a" }])
    assert_equal ["1 system no link joins to s1: b"], t.warnings
    assert_equal [], grid.warnings
  end

  # to_h writes every system and link out; it builds the same area again.
  def test_to_h_builds_the_same_area
    t = grid("routers" => [{ "name" => "r2c3", "externals" => [{ "prefix" => "50.0.0.0/24", "count" => 2 }] }],
             "links" => [{ "from" => "s1", "to" => "r1c1", "one_way" => true }])
    again = ISIS::Sim::Topology.from_hash(t.to_h)
    assert_equal t.systems.map { [_1.name, _1.system_id, _1.levels, _1.prefixes.map(&:to_h), _1.externals.map(&:to_h)] },
                 again.systems.map { [_1.name, _1.system_id, _1.levels, _1.prefixes.map(&:to_h), _1.externals.map(&:to_h)] }
    assert_equal t.links.map(&:to_h), again.links.map(&:to_h)
    assert_equal t.lsp_lifetime, again.lsp_lifetime
  end

  # From a file: the areas as written, so 49.0010 stays 49.0010.
  def test_load_keeps_areas_as_written
    Dir.mktmpdir do |dir|
      path = File.join(dir, "sim.yml")
      File.write(path, <<~YAML)
        simulator:
          system_id: 0000.0000.0009
          areas: [49.0010]
          interfaces: [eth1]
        routers:
          - { name: x, system_id: 0000.0000.0100, areas: [49.0010, 49.0002] }
        links:
          - { from: sim, to: x }
      YAML
      t = ISIS::Sim::Topology.load(path)
      assert_equal [["49.0010"], %w[49.0010 49.0002]], [t.simulator.areas, t.system("x").areas]
      assert_equal "sim--x", t.links.first.name
    end
  end

  def test_load_names_the_file
    e = assert_raises(ISIS::Sim::Topology::Error) { ISIS::Sim::Topology.load("/nonexistent/sim.yml") }
    assert_match(%r{/nonexistent/sim.yml|No such file}, e.message)
  end

  # --- segment routing

  # The grid's sids run row by row from r1c1, on each loopback; a router
  # may set its own sid and srgb.
  def test_sids_and_srgbs
    t = grid("segment_routing" => {}, "grid" => { "columns" => 3, "rows" => 2, "loopbacks" => "10.200.0.0/24", "sids" => 101 },
             "routers" => [{ "name" => "r2c3", "sid" => 7, "srgb" => [{ "start" => 20_000, "size" => 100 }] }])
    assert_equal({ srgb: [[16_000, 8_000]], srlb: [15_000, 1_000] }, t.segment_routing)
    assert_equal [101, 102, 103, 104, 105, 7], t.systems.map(&:sid)
    assert_equal({ prefix: "10.200.0.1/32", metric: 0, sid: 101 }, t.system("r1c1").prefixes.first.to_h)
    assert_equal [[20_000, 100]], t.system("r2c3").srgb
  end

  # Without segment_routing nothing changes, and the prefixes carry no sid.
  def test_no_segment_routing
    assert_nil grid.segment_routing
    assert_equal [nil], grid.systems.map(&:sid).uniq
    assert_equal({ prefix: "10.200.0.1/32", metric: 0 }, grid.system("r1c1").prefixes.first.to_h)
  end

  # What cannot be advertised is refused, every problem at once.
  def test_segment_routing_refusals
    base = { "simulator" => SIM, "links" => [{ "from" => "s1", "to" => "a" }] }
    m = refused(base.merge("routers" => [{ "name" => "a", "system_id" => "0000.0000.0001", "loopback" => "10.1.1.1", "sid" => 1 }]))
    assert_match(/a.sid: needs a segment_routing section/, m)
    m = refused(base.merge("segment_routing" => {}, "routers" => [{ "name" => "a", "system_id" => "0000.0000.0001", "sid" => 1 }]))
    assert_match(/a.sid: needs an IPv4 loopback/, m)
    m = refused(base.merge("segment_routing" => { "srgb" => [{ "start" => 15_500, "size" => 100 }] }))
    assert_match(/segment_routing: label blocks .* overlap/, m)
    m = refused(base.merge("segment_routing" => {}, "grid" => { "rows" => 1, "columns" => 2, "sids" => 1 }))
    assert_match(/grid.sids: needs grid.loopbacks/, m)
    m = refused(base.merge("segment_routing" => {}, "routers" => [{ "name" => "a", "system_id" => "0000.0000.0001",
                                                                    "srgb" => [{ "start" => 15_000, "size" => 10 }] }]))
    assert_match(/routers\[0\].srgb: label blocks/, m)
  end

  # One index on two systems is sendable, so it is kept, and warned of.
  def test_an_index_twice_is_warned_of
    t = grid("segment_routing" => {}, "routers" => [{ "name" => "r1c1", "sid" => 9 }, { "name" => "r1c2", "sid" => 9 }])
    assert_includes t.warnings, "index 9 is the Prefix-SID of r1c1 and r1c2"
  end

  # to_h writes the SR keys, so the file reads again the same.
  def test_to_h_keeps_segment_routing
    t = grid("segment_routing" => { "srlb" => { "start" => 30_000, "size" => 10 } },
             "grid" => { "columns" => 2, "rows" => 1, "loopbacks" => "10.200.0.0/24", "sids" => 1 },
             "routers" => [{ "name" => "r1c2", "srgb" => [{ "start" => 20_000, "size" => 50 }] }])
    again = ISIS::Sim::Topology.from_hash(t.to_h)
    assert_equal t.segment_routing, again.segment_routing
    assert_equal t.systems.map { [_1.sid, _1.srgb, _1.loopback, _1.prefixes.map(&:to_h)] },
                 again.systems.map { [_1.sid, _1.srgb, _1.loopback, _1.prefixes.map(&:to_h)] }
  end
end
