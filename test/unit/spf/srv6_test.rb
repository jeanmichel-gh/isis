# frozen_string_literal: true

require_relative "../../test_helper"

# Spf::Srv6, what one level's LSPs say about SRv6 (docs/design/srv6.md,
# step 3), and the locator routes the calculation reads from TLV 27.
#
# A computes, in a line a ---- b ---- c, each link at 10; c is an SRv6
# system as ISIS::Fault builds one: SRv6 Capabilities, its locator
# fc00:0:c::/48 in TLV 236 and TLV 27, an End SID and an End.X SID to b.
class TestSpfSrv6 < Minitest::Test
  F = ISIS::Fault
  C = { system_id: "0000.0000.000c", neighbors: { "0000.0000.000b" => 10 } }.freeze

  def setup
    @clock = ISIS::Runtime::ManualClock.new
  end

  def id(letter) = (ISIS::Pdu.dotted_octets("0000.0000.000#{letter}") + "\x00".b).b

  def store(db, pdu) = db.entry(pdu.lsp_id.to_s.b).store(pdu)

  # The database with c's TLVs +c+, F.srv6's by default, and b's +b+.
  def database(c: F.srv6(F.context(**C)), b: [])
    db = ISIS::Database.new(level: 1, clock: @clock)
    store(db, F.lsp([], system_id: "0000.0000.000a", neighbors: { "0000.0000.000b" => 10 }))
    store(db, F.lsp(b, system_id: "0000.0000.000b", neighbors: { "0000.0000.000a" => 10, "0000.0000.000c" => 10 }))
    store(db, F.lsp(c, **C))
    db
  end

  def adjacency
    ISIS::Spf::Adjacency.new(circuit: "eth-b", neighbor: ISIS::Pdu.dotted_octets("0000.0000.000b"), circuit_id: 1,
                             address6: "fe80::b")
  end

  def calc(db, srv6: :rfc)
    ISIS::Spf::Calculation.new(database: db, system_id: "0000.0000.000a", adjacencies: [[id("b"), 10, adjacency]],
                               srv6: srv6).run
  end

  def table(db, policy: :rfc)
    c = calc(db, srv6: policy)
    ISIS::Spf::Srv6.new(local: nil, database: db, paths: c.paths, routes: c.routes, adjacencies: [adjacency],
                        policy: policy).build
  end

  # c's locator comes in TLV 236 and TLV 27: the TLV 236 entry is the
  # route, marked as a locator (RFC 9352 section 5), at 20 plus its
  # metric 0, through b.
  def test_a_locator_in_both
    r = calc(database).routes["fc00:0:c::/48"]
    assert_equal [20, ["fe80::b"]], [r.metric, r.adjacencies.map(&:address6)]
    assert_equal "fc00:0:c::/48", r.locator.prefix
    assert_nil r.locator_only
    assert_equal id("c"), r.origin
  end

  # In TLV 27 alone, the locator is still routed, from TLV 27, at its
  # metric, D as the up/down bit.
  def test_a_locator_in_tlv_27_alone
    tlvs = F.srv6(F.context(**C), locator: { metric: 5, flags: %w[D] }).reject { _1.is_a?(ISIS::Tlv::Ipv6Reachability) }
    r = calc(database(c: tlvs)).routes["fc00:0:c::/48"]
    assert_equal [25, true, true], [r.metric, r.up_down, r.locator_only]
  end

  # Without srv6, TLV 27 is not read: a router that does not run SRv6
  # routes TLV 236's copy alone, and nothing from TLV 27.
  def test_not_read_without_srv6
    r = calc(database, srv6: nil).routes["fc00:0:c::/48"]
    assert_nil r.locator
    tlvs = F.srv6(F.context(**C)).reject { _1.is_a?(ISIS::Tlv::Ipv6Reachability) }
    assert_nil calc(database(c: tlvs), srv6: nil).routes["fc00:0:c::/48"]
  end

  # A locator the rules ignore is not routed from TLV 27.
  def test_an_ignored_locator_is_not_routed
    tlvs = F.srv6(F.context(**C), more: [{ algorithm: 128 }]).reject { _1.is_a?(ISIS::Tlv::Ipv6Reachability) }
    assert_nil calc(database(c: tlvs)).routes["fc00:0:c::/48"]
    assert calc(database(c: tlvs), srv6: :lenient).routes["fc00:0:c::/48"]
  end

  # A locator of another algorithm is not an algorithm 0 route (the
  # design's step 8 routes it from its own tree).
  def test_a_flex_algo_locator_is_not_routed_here
    tlvs = F.srv6(F.context(**C), locator: { algorithm: 128 }).reject { _1.is_a?(ISIS::Tlv::Ipv6Reachability) }
    assert_nil calc(database(c: tlvs)).routes["fc00:0:c::/48"]
  end

  # What the table reads of c: its capability, locator, End SID with its
  # structure, and End.X SID to b.
  def test_the_table
    t = table(database)
    assert_empty t.findings
    n = t.node(id("c"))
    assert_equal({ o: false }, n.capabilities)
    assert_equal [0], n.algorithms
    loc = n.locators.first
    assert_equal({ prefix: "fc00:0:c::/48", algorithm: 0, metric: 0, up_down: false, flags: [],
                   end_sids: [{ sid: "fc00:0:c::", behavior: "End", structure: [32, 16, 16, 0] }] }, loc.to_hash)
    assert_equal [{ sid: "fc00:0:c:1::", behavior: "End.X", algorithm: 0, weight: 0, flags: [],
                    neighbor: "0000.0000.000b.00", lan: false, structure: [32, 16, 16, 0] }],
                 n.end_x_sids.map(&:to_hash)
    assert_nil t.node(id("b")), "b sends no SRv6"
  end

  # FRR 10.7.1's LSPs read with no finding: a classic End SID, and a
  # uSID one, End with NEXT-CSID, which goes where End goes (RFC 9352
  # Table 1, as this library reads RFC 9800).
  def test_frrs_lsps
    %w[frr-10.7.1-l2-lsp-srv6 frr-10.7.1-l2-lsp-srv6-usid].each do |name|
      lsp = ISIS::Pdu.factory(ISIS::Octets.new([File.read(fixture("#{name}.hex")).strip].pack("H*")))
      n = ISIS::Spf::Srv6.read([lsp])
      assert_empty n.findings, name
      assert_equal 1, n.locators.first.end_sids.size, name
      assert_equal 1, n.end_x_sids.size, name
    end
  end

  def fixture(name) = File.expand_path("../../fixtures/#{name}", __dir__)

  # The policies on one finding each: rfc does what the clause says,
  # strict refuses the system's SRv6, lenient uses what it can.
  def test_the_policies
    read = ->(name, policy) { ISIS::Spf::Srv6.read([F.srv6_build(name)], policy: policy) }
    rfc = read[:end_sid_outside_locator, :rfc]
    assert_equal [[], 1], [rfc.locators.first.end_sids, rfc.end_x_sids.size]
    strict = read[:end_sid_outside_locator, :strict]
    assert_equal [true, [], []], [strict.ignored, strict.locators, strict.end_x_sids]
    assert_equal ["fc00:0:99::"], read[:end_sid_outside_locator, :lenient].locators.first.end_sids.map(&:sid)

    assert_equal %w[A], read[:anycast_and_node, :rfc].locators.first.flags, "N ignored"
    assert_empty read[:anycast_and_node, :strict].locators
    assert_empty read[:x_flag_mismatch, :rfc].locators.first.flags, "TLV 236's X preferred"
    assert_equal %w[X], read[:x_flag_mismatch, :lenient].locators.first.flags
    # The behaviour this library has no code for is ignored under all.
    %i[rfc strict lenient].each { |p| assert_empty read[:behavior_unknown, p].locators.first.end_sids, p }
  end

  # Section 5's longest match: a TLV 236 prefix from b inside c's locator
  # takes c's End SID elsewhere. Reported, inconclusive; nothing changes.
  def test_a_longer_match
    b = [ISIS::Tlv::Ipv6Reachability.new([{ prefix: "fc00:0:c::/64", metric: 0 }])]
    t = table(database(b: b))
    assert_equal [:locator_not_longest], t.findings.map(&:name)
    assert_equal :inconclusive, t.findings.first.channel
    assert_match(/SID fc00:0:c:: of locator fc00:0:c::\/48: fc00:0:c::\/64 is a longer match/, t.findings.first.to_s)
    assert_equal 1, t.node(id("c")).locators.first.end_sids.size
  end

  # A locator propagated to the other level carries only the End SIDs the
  # rules let through.
  def test_usable_entry
    loc = ISIS::Spf::Srv6.read([F.srv6_build(:behavior_unknown)]).locators.first
    h = loc.usable_entry
    assert_equal [{ prefix_attribute_flags: {} }], h[:subtlvs]
    assert_equal "fc00:0:3::/48", ISIS::Tlv::Srv6Locator::Entry.new(**h).locator
  end
end
