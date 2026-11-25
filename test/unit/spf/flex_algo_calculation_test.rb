# frozen_string_literal: true

require_relative "../../test_helper"

# A flex-algo's calculation and label table (docs/design/flex-algo.md,
# step 5), on hand-built databases: the catalog's topologies
# (ISIS::Fault::FLEX_ALGO_TOPOLOGIES), each with the path RFC 9350
# expects, then the rules' order, a LAN, the label table, and a
# property: an IGP-metric FAD with no constraints, every system taking
# part, gives algorithm 0's routes.
class TestFlexAlgoCalculation < Minitest::Test
  K = ISIS::Fault::FLEX_ALGO

  def setup
    @clock = ISIS::Runtime::ManualClock.new
    @db = ISIS::Database.new(level: 1, clock: @clock)
    @log = ISIS::Runtime::Log.new(clock: @clock)
  end

  # System +name+'s number, as the catalog numbers them.
  def n(name) = @numbers.fetch(name)
  def system_id(name) = format("0000.0000.%04d", n(name))
  def node(name) = (ISIS::Pdu.dotted_octets(system_id(name)) + "\x00".b).b
  def loopback(name) = "10.255.0.#{n(name)}/32"
  def srgb(name) = 16_000 + (1_000 * n(name))

  # An ASLA sub-TLV Hash with X for +attrs+, or nil.
  def asla(attrs)
    subs = []
    subs << { extended_admin_group: { groups: attrs[:affinity] } } if attrs[:affinity]
    subs << { te_default_metric: { metric: attrs[:te_metric] } } if attrs[:te_metric]
    subs += [{ link_delay: { delay: attrs[:delay] } }, { min_max_link_delay: { min: attrs[:delay], max: attrs[:delay] } }] if attrs[:delay]
    subs.empty? ? nil : { asla: { applications: %w[X], subtlvs: subs } }
  end

  # Store the topology's LSPs: each system's links with their attributes
  # and SRLGs, its SR capabilities and FADs, its loopback with a
  # Prefix-SID for 0 and for K.
  def build(links, not_taking_part: [], fads: {}, lan: nil)
    @numbers = {}
    links.each { |a, b, *| [a, b].each { @numbers[_1] ||= @numbers.size + 1 } }
    reports = Hash.new { |h, k| h[k] = [] }
    links.each_with_index do |(a, b, igp, attrs, back), i|
      attrs ||= {}
      back ||= attrs
      reports[a] << [node(b), igp, attrs, "10.0.#{i}.1", "10.0.#{i}.2"]
      reports[b] << [node(a), igp, back, "10.0.#{i}.2", "10.0.#{i}.1"] unless attrs[:one_way]
    end
    lan&.each { |name, list| reports[name].concat(list) }
    @numbers.each_key { store(_1, reports[_1], !not_taking_part.include?(_1), fads[_1]) }
  end

  def store(name, links, taking_part, fad)
    tlvs = []
    unless links.empty?
      tlvs << ISIS::Tlv::ExtendedIsReachability.new(links.map do |id, igp, attrs, local, remote|
        subs = local ? [{ ipv4_interface_address: local }, { ipv4_neighbor_address: remote }] : []
        subs << asla(attrs) if asla(attrs)
        { neighbor: neighbor_text(id), metric: igp, subtlvs: subs }
      end)
    end
    links.each do |id, _, attrs, local, remote|
      next unless attrs[:srlg]

      tlvs << ISIS::Tlv::AslaSrlg.new(neighbor: neighbor_text(id), applications: %w[X], srlgs: attrs[:srlg],
                                      links: [{ ipv4_interface_address: local }, { ipv4_neighbor_address: remote }])
    end
    caps = [ISIS::SubTlv::SrCapabilities.new(flags: %w[I], descriptors: [{ range: 1_000, label: srgb(name) }]),
            ISIS::SubTlv::SrAlgorithm.new(*(taking_part ? [0, K] : [0]))]
    caps << ISIS::SubTlv::Fad.new(**fad) if fad
    tlvs << ISIS::Tlv::RouterCapability.new(router_id: "10.255.0.#{n(name)}", subtlvs: caps)
    tlvs << ISIS::Tlv::ExtendedIpReachability.new({ prefix: loopback(name), metric: 0,
                                                    subtlvs: [{ prefix_sid: { flags: %w[N], algorithm: 0, index: n(name) } },
                                                              { prefix_sid: { flags: %w[N], algorithm: K, index: 100 + n(name) } }] })
    id = "#{system_id(name)}.00-00"
    @db.entry(ISIS::Pdu.lsp_id_octets(id)).store(ISIS::Pdu::Lsp.new(level: 1, lsp_id: id, lifetime: 1200, sequence: 1,
                                                                      tlvs: tlvs))
  end

  def neighbor_text(id)
    hex = id.unpack1("H*")
    "#{hex[0, 12].scan(/.{4}/).join('.')}.#{hex[12, 2]}"
  end

  # S's adjacencies, one per link it reports, at the IGP metric.
  def adjacencies(links)
    links.each_with_index.filter_map do |(a, b, igp), i|
      next unless a == "S"

      adj = ISIS::Spf::Adjacency.new(circuit: "S-#{b}", neighbor: node(b).byteslice(0, 6), circuit_id: 1,
                                     address: "10.0.#{i}.2")
      [node(b), igp, adj]
    end
  end

  def select
    config = ISIS::FlexAlgoConfig.new([{ algorithm: K, advertise: false }], affinity_map: {}, segment_routing: true)
    ISIS::Spf::FlexAlgo.new(level: 1, system_id: system_id("S"), database: @db, config: config, log: @log)
  end

  def calc(links, definition, adjacencies: adjacencies(links), broadcast: [], algorithm: K)
    ISIS::Spf::Calculation.new(database: @db, system_id: system_id("S"), adjacencies: adjacencies,
                               broadcast: broadcast, algorithm: algorithm, definition: definition).run
  end

  def own_sr
    ISIS::SegmentRouting.new(router_id: "10.255.0.1", srgb: [[srgb("S"), 1_000]])
  end

  def labels(calc, algorithm: K, taken: {})
    ISIS::Spf::Labels.new(own: own_sr, database: @db, paths: calc.paths, algorithm: algorithm)
                     .build(calc.routes, [], taken: taken)
  end

  ISIS::Fault.flex_topologies.each do |t|
    define_method("test_#{t[:name]}") do
      build(t[:links], not_taking_part: t[:not_taking_part], fads: t[:fads])
      expect = t[:expect]
      status = select.statuses[K]
      if expect[:taking_part] == false
        refute status.participating, t[:description]
        next
      end
      assert status.participating, t[:description]
      assert_equal system_id(expect[:winner]), status.origin, t[:description]
      c = calc(t[:links], status.winner)
      route = c.routes[loopback("D")]
      table = labels(c)
      in_label = srgb("S") + 100 + n("D")
      if expect[:unreachable]
        assert_nil route, t[:description]
        refute table.entries.key?(in_label), "#{t[:description]}: no label route"
        next
      end
      assert_equal expect[:first_hops].map { node(_1).byteslice(0, 6) }, route.adjacencies.map(&:neighbor), t[:description]
      assert_equal expect[:metric], route.metric, t[:description]
      # The label table: D's index for K, in S's SRGB, swapped to the
      # same index in the first hop's.
      e = table.entries.fetch(in_label)
      assert_equal [K, :swap, loopback("D")], [e.algorithm, e.op, e.fec]
      assert_equal expect[:first_hops].map { srgb(_1) + 100 + n("D") }, e.hops.map(&:last)
    end
  end

  # Section 13's rules apply in order: a link both red and without a
  # delay is pruned by the first, exclude.
  def test_rules_in_order
    links = [["S", "A", 1, { delay: 1 }], ["A", "D", 1, { affinity: [1] }], ["S", "B", 5, { delay: 1 }],
             ["B", "D", 5, { delay: 1 }]]
    build(links, fads: { "D" => { algorithm: K, metric_type: "delay", subtlvs: [{ fad_exclude_admin_group: { groups: [1] } }] } })
    c = calc(links, select.statuses[K].winner)
    pruned = c.pruned.map { |a, b, rule| [ISIS::SystemId.from_bytes(a.byteslice(0, 6)).to_s, b == node("D") ? "D" : "", rule] }
    assert_includes pruned, [system_id("A"), "D", :exclude_any]
    assert_equal [node("B").byteslice(0, 6)], c.routes[loopback("D")].adjacencies.map(&:neighbor)
  end

  # An IGP metric of 2^24 - 1 is still not used (RFC 5305 section 3), as
  # for algorithm 0; a delay of 2^24 - 1 is (fa_last_resort).
  def test_max_igp_metric_not_used
    links = [["S", "A", 1, {}], ["A", "D", 0xFFFFFF, {}]]
    build(links, fads: { "D" => { algorithm: K } })
    c = calc(links, select.statuses[K].winner)
    assert_nil c.routes[loopback("D")]
    assert_includes c.pruned.map(&:last), :max_metric
  end

  # A LAN: S, B and C on B's pseudonode, D behind C, on delay. S's first
  # hop to C is its link to the pseudonode, 1 ms, not the circuit's
  # metric; the pseudonode's links carry no delay and are taken at 0.
  def test_a_lan
    @numbers = { "S" => 1, "B" => 2, "C" => 3, "D" => 4 }
    pseudonode = (node("B").byteslice(0, 6) + "\x01".b).b
    to_lan = [pseudonode, 10, { delay: 1_000 }, nil, nil]
    store("S", [to_lan], true, nil)
    store("B", [to_lan], true, nil)
    store("C", [to_lan, [node("D"), 10, { delay: 2_000 }, "10.0.0.1", "10.0.0.2"]], true, nil)
    store("D", [[node("C"), 10, { delay: 2_000 }, "10.0.0.2", "10.0.0.1"]], true, { algorithm: K, metric_type: "delay" })
    id = "#{neighbor_text(pseudonode)}-00"
    members = ISIS::Tlv::ExtendedIsReachability.new(%w[S B C].map { { neighbor: neighbor_text(node(_1)), metric: 0 } })
    @db.entry(ISIS::Pdu.lsp_id_octets(id))
       .store(ISIS::Pdu::Lsp.new(level: 1, lsp_id: id, lifetime: 1200, sequence: 1, tlvs: [members]))
    adj = ->(x) { ISIS::Spf::Adjacency.new(circuit: "lan", neighbor: node(x).byteslice(0, 6), circuit_id: 1, lan_address: x) }
    c = calc([], select.statuses[K].winner, adjacencies: [[node("B"), 10, adj.("B")], [node("C"), 10, adj.("C")]],
                                            broadcast: [[pseudonode, 10, adj.("B")]])
    route = c.routes.fetch(loopback("D"))
    assert_equal 3_000, route.metric
    assert_equal [node("C").byteslice(0, 6)], route.adjacencies.map(&:neighbor)
  end

  # An index another table already uses is a finding, and that table
  # keeps it: algorithm 0's Prefix-SID of D and K's of A share index 5.
  def test_an_index_taken_by_algorithm_0
    links = [["S", "A", 1, {}], ["A", "D", 1, {}]]
    build(links, fads: { "D" => { algorithm: K } })
    c = calc(links, select.statuses[K].winner)
    table = labels(c, taken: { 100 + n("D") => ["10.255.9.9/32", 0] })
    refute table.entries.key?(srgb("S") + 100 + n("D"))
    f = table.findings.find { _1.name == :prefix_sid_duplicate }
    assert_equal "index 103", f.subject
    assert_match(/10.255.0.3\/32 \(algorithm 128\) left out\z/, f.detail)
  end

  # A Prefix-SID for K from a system that does not list K is not used
  # (RFC 8667 section 2.1): that system is pruned anyway, so its prefix
  # has no route in K.
  def test_a_system_not_taking_part_has_no_route
    links = [["S", "A", 1, {}], ["A", "D", 1, {}]]
    build(links, not_taking_part: ["D"], fads: { "A" => { algorithm: K } })
    c = calc(links, select.statuses[K].winner)
    assert_nil c.routes[loopback("D")]
    assert c.routes[loopback("A")]
  end

  # A connected graph of +size+ systems S, N2, N3 ...: a random tree,
  # then more links, each with a random IGP metric.
  def random_links(rng, size)
    names = ["S"] + (2..size).map { "N#{_1}" }
    links = names.each_with_index.drop(1).map { |name, i| [names[rng.rand(i)], name, rng.rand(1..20), {}] }
    rng.rand(0..size).times do
      a, b = names.sample(2, random: rng)
      links << [a, b, rng.rand(1..20), {}] unless links.any? { |x, y| [x, y].sort == [a, b].sort }
    end
    links
  end

  # The design's property: on 300 random topologies, an IGP-metric FAD
  # with no constraints, every system taking part, gives the same routes
  # as algorithm 0: metrics and next hops.
  def test_property_same_as_algorithm_0
    rng = Random.new(9350)
    300.times do
      @db = ISIS::Database.new(level: 1, clock: @clock)
      links = random_links(rng, rng.rand(3..12))
      build(links)
      definition = ISIS::Spf::Definitions::Definition.new(algorithm: K, metric_type: 0, calc_type: 0, priority: 0,
                                                          exclude_any: [], include_any: [], include_all: [],
                                                          flags: [], exclude_srlg: [], unknown: [])
      base = ISIS::Spf::Calculation.new(database: @db, system_id: system_id("S"), adjacencies: adjacencies(links)).run
      flex = calc(links, definition)
      want = base.routes.transform_values { [_1.metric, _1.adjacencies.map(&:neighbor)] }
      got = flex.routes.transform_values { [_1.metric, _1.adjacencies.map(&:neighbor)] }
      assert_equal want, got, links.inspect
    end
  end
end
