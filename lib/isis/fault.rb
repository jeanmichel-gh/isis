# frozen_string_literal: true

module ISIS
  # The catalog of crafted inputs, as bgp4r's BGP::Fault, vtep4r's
  # VXLAN::Fault and bfd4r's BFD::Fault (routescope
  # docs/design/protocol-conventions.md, part 3). A test, or later the
  # injector, sends an entry to a router and checks what it did against
  # what the RFC expects.
  #
  # Two groups. Segment routing's (CATALOG): an LSP with one wrong thing in
  # its SR data. TI-LFA's topologies (TOPOLOGIES): well formed, each with
  # the repair RFC 9855 expects.
  #
  # The first entries are segment routing's: an LSP with one wrong thing
  # in its SR data, everything else what a correct system sends. Each
  # makes one finding of ISIS::Validation, named in the entry, so the
  # catalog and the rules are tested together (docs/protocol-testing.md).
  # Building never validates: what an entry builds is wrong on purpose.
  module Fault
    # The system an entry is built for unless told otherwise: its SRGB,
    # index and loopback.
    SRGB = [20_000, 8_000].freeze
    INDEX = 3

    # Each entry: [name, the Validation finding it makes, description, a
    # block that gives the entry's TLVs from a context (Fault.context)].
    # What the RFC expects and its section are the finding's
    # (Validation::RULES).
    CATALOG = [
      [:srgb_range_zero, :srgb_range_zero, "an SRGB descriptor with a range of 0",
       ->(c) { Fault.sr(c, srgbs: [[[c[:srgb][0], 0]]]) }],
      [:srgb_overlap, :srgb_overlap, "two SRGB ranges that overlap by half",
       ->(c) { Fault.sr(c, srgbs: [[[c[:srgb][0], 1_000], [c[:srgb][0] + 500, 1_000]]]) }],
      [:srgb_reserved, :srgb_reserved, "an SRGB from label 8, among the reserved labels 0 to 15",
       ->(c) { Fault.sr(c, srgbs: [[[8, 100]]]) }],
      [:sr_capabilities_twice, :sr_capabilities_twice, "two SR-Capabilities sub-TLVs in one Router Capability",
       ->(c) { Fault.sr(c, srgbs: [[c[:srgb]], [[c[:srgb][0] + 10_000, c[:srgb][1]]]]) }],
      [:prefix_sid_vl_invalid, :prefix_sid_vl_invalid, "a Prefix-SID with V set and L clear",
       ->(c) { Fault.sr(c, sid: { flags: %w[N V], algorithm: 0, index: c[:index] }) }],
      [:prefix_sid_label, :prefix_sid_label, "a Prefix-SID carried as a label, V and L set",
       ->(c) { Fault.sr(c, sid: { flags: %w[N V L], algorithm: 0, label: c[:srgb][0] + c[:index] }) }],
      [:algorithm_not_advertised, :algorithm_not_advertised,
       "a Prefix-SID for algorithm 0 from a system whose SR-Algorithm lists 1 only",
       ->(c) { Fault.sr(c, algorithms: [1]) }],
      [:prefix_sid_duplicate, :prefix_sid_duplicate, "one index on the loopback and on a second prefix",
       ->(c) { Fault.sr(c, more: [[c[:second], { flags: [], algorithm: 0, index: c[:index] }]]) }]
    ].freeze

    # The second group: topologies, well formed but hard for TI-LFA (RFC
    # 9855), each with the RFC section it tests. Each entry: [name,
    # description, rfc, the topology, the point of local repair (PLR),
    # the failure as [:link or :node, the PLR's neighbor], the
    # destination, and what RFC 9855 expects]. A topology is links
    # [a, b, metric], both ways unless one_way, and the systems
    # overloaded. expect is the repair: its case (5.1 to 5.4), its first
    # hop, P and Q, and its segments, [:node, X] for X's Node-SID and
    # [:adj, X, Y] for X's Adj-SID to Y; or { unprotected: reason }; or
    # { ecmp: [the other first hops] }. Written by hand from the RFC,
    # never computed.
    #
    # Every system gets a loopback 10.255.0.N/32 with Prefix-SID index N,
    # and an SRGB of its own, 16000 + 1000 N, so a label from the wrong
    # block shows (Fault.topology_file).
    # A0 to A30. P is A0, the first hop, so no Node-SID: 30 Adj-SIDs and
    # D's label, 31 labels, past the kernel's 30.
    TOO_DEEP_CHAIN = 30

    TOPOLOGIES = [
      [:ti_lfa_neighbor, "the neighbor on the post-convergence path is in P and Q: no segment", "RFC 9855 5.1",
       { links: [%w[S F 1], %w[F D 1], %w[S N 2], %w[N D 1]] }, "S", [:link, "F"], "D",
       { case: :neighbor, first_hop: "N", p: "N", q: "N", segments: [] }],
      [:ti_lfa_pq_node, "B is in A's P-space and in Q(D): B's Node-SID", "RFC 9855 5.2",
       { links: [%w[S F 1], %w[F D 1], %w[S A 1], %w[A B 1], %w[B D 3]] }, "S", [:link, "F"], "D",
       { case: :pq_node, first_hop: "A", p: "B", q: "B", segments: [[:node, "B"]] }],
      [:ti_lfa_p_and_q_adjacent, "P is B, Q is D, adjacent: B's Node-SID then B's Adj-SID to D", "RFC 9855 5.3",
       { links: [%w[S F 1], %w[F D 1], %w[S A 1], %w[A B 1], %w[B D 5]] }, "S", [:link, "F"], "D",
       { case: :p_and_q_adjacent, first_hop: "A", p: "B", q: "D", segments: [[:node, "B"], [:adj, "B", "D"]] }],
      [:ti_lfa_figure_1, "RFC 9855 Figure 1, node N1 fails: P R1 and Q R3 apart", "RFC 9855 5.4",
       { links: [%w[S N1 1], %w[N1 D 1], %w[S N2 1], %w[S N3 1000], %w[N1 R1 1], %w[N1 R2 1], %w[D R3 1],
                 %w[N2 R1 1], %w[R1 R2 1000], %w[R2 R3 1000], %w[N3 R1 1000]] }, "S", [:node, "N1"], "D",
       { case: :p_and_q_apart, first_hop: "N2", p: "R1", q: "R3",
         segments: [[:node, "R1"], [:adj, "R1", "R2"], [:adj, "R2", "R3"]] }],
      [:ti_lfa_figure_2, "RFC 9855 Figure 2, R2 protects against node R3: Adj-SIDs R7-R8 and R8-R4",
       "RFC 9855 9",
       { links: [%w[S R2 1], %w[R2 R3 1], %w[R3 R4 1], %w[R4 R5 1], %w[R5 D 1], %w[R2 R7 1000], %w[R3 R7 1],
                 %w[R3 R8 1], %w[R7 R8 1000], %w[R8 R4 1000], %w[R7 R9 1000], %w[R8 R10 1], %w[R9 R10 1]] },
       "R2", [:node, "R3"], "D",
       { case: :p_and_q_apart, first_hop: "R7", p: "R7", q: "R4", segments: [[:adj, "R7", "R8"], [:adj, "R8", "R4"]] }],
      [:ti_lfa_no_path, "the failure cuts the destination off", "RFC 9855 5",
       { links: [%w[S F 1], %w[F D 1]] }, "S", [:link, "F"], "D", { unprotected: :no_path }],
      [:ti_lfa_ecmp, "another primary first hop survives: no repair list", "RFC 9855 5",
       { links: [%w[S F 1], %w[F D 1], %w[S A 1], %w[A D 1]] }, "S", [:link, "F"], "D", { ecmp: ["A"] }],
      [:ti_lfa_overload, "the only other path crosses B, overloaded: no transit, so no repair",
       "RFC 9855 5",
       { links: [%w[S F 1], %w[F D 1], %w[S A 1], %w[A B 1], %w[B D 5]], overloaded: ["B"] }, "S", [:link, "F"], "D",
       { unprotected: :no_path }],
      [:ti_lfa_one_way, "the only other path has a link only A reports: it does not count, so no repair",
       "RFC 9855 5",
       { links: [%w[S F 1], %w[F D 1], %w[S A 1], %w[A B 1 one_way], %w[B D 3]] }, "S", [:link, "F"], "D",
       { unprotected: :no_path }],
      [:ti_lfa_too_deep, "P and Q #{TOO_DEEP_CHAIN} hops apart: #{TOO_DEEP_CHAIN + 1} labels, past the kernel's 30",
       "RFC 9855 5.4",
       { links: [%w[S F 1], %w[F D 1], %w[S A0 1], ["A#{TOO_DEEP_CHAIN}", "D", "1"]] +
                (0..TOO_DEEP_CHAIN).map { |i| ["A#{i}", "F", "1"] } +
                (0...TOO_DEEP_CHAIN).map { |i| ["A#{i}", "A#{i + 1}", "1000"] } },
       "S", [:node, "F"], "D", { unprotected: :too_deep }]
    ].freeze

    module_function

    def names
      CATALOG.map(&:first)
    end

    # The entries, as Hashes: the finding's channel, what the RFC expects
    # of a receiver (the finding's :rfc action) and the clause beside
    # each.
    def catalog
      CATALOG.map do |name, finding, description, build|
        rule = Validation.rule(finding)
        { name: name, finding: finding, description: description, channel: rule.channel,
          expect: rule.actions.fetch(:rfc), rfc: rule.clause, build: build }
      end
    end

    def entry(name)
      catalog.find { |e| e[:name] == name } or
        raise ArgumentError, "unknown fault #{name.inspect}; the faults are #{names.join(', ')}"
    end

    # What an entry is built for: the system, its loopback and index, its
    # Router ID (the loopback's address unless given), its SRGB as
    # [first, size], a second prefix, and its neighbors with their
    # metrics, as { "0000.0000.0002" => 10 }, so SPF reaches it.
    def context(system_id: "0000.0000.0003", loopback: "10.255.0.3/32", index: INDEX, srgb: SRGB,
                second: "10.255.9.3/32", neighbors: {}, router_id: nil)
      { system_id: system_id, loopback: loopback, router_id: router_id || loopback.split("/").first, index: index,
        srgb: srgb, second: second, neighbors: neighbors }
    end

    # The entry's TLVs: a Router Capability and the reachability of its
    # prefixes. An injector adds them to the LSP of the system it plays.
    def tlvs(name, **ctx)
      entry(name)[:build].call(context(**ctx))
    end

    # The entry as a whole LSP, number 0 of the system, at +level+, with
    # its neighbors.
    def build(name, level: 1, sequence: 1, lifetime: 1200, **ctx)
      lsp(tlvs(name, **ctx), level: level, sequence: sequence, lifetime: lifetime, **ctx)
    end

    # LSP number 0 of the context's system, its neighbors first, then
    # +tlvs+: an entry's, or a correct system's from #sr.
    def lsp(tlvs, level: 1, sequence: 1, lifetime: 1200, **ctx)
      c = context(**ctx)
      lsp_id = Octets.new(Pdu.dotted_octets(c[:system_id]) + "\x00\x00".b)
      reach = Tlv::ExtendedIsReachability.new(c[:neighbors].map do |id, metric|
        Tlv::ExtendedIsReachability::Entry.new(neighbor: (Pdu.dotted_octets(id) + "\x00".b).b, metric: metric)
      end)
      Pdu::Lsp.new(level: level, lsp_id: lsp_id, lifetime: lifetime, sequence: sequence, tlvs: [reach] + tlvs)
    end

    # The same, as octets.
    def wire(name, **opts)
      build(name, **opts).encode
    end

    def topology_names = TOPOLOGIES.map(&:first)

    # The topology entries, as Hashes.
    def topologies
      TOPOLOGIES.map do |name, description, rfc, topology, plr, failure, destination, expect|
        { name: name, description: description, rfc: rfc, links: topology[:links],
          overloaded: topology.fetch(:overloaded, []), plr: plr, failure: failure, destination: destination,
          expect: expect }
      end
    end

    def topology(name)
      topologies.find { |e| e[:name] == name } or
        raise ArgumentError, "unknown topology #{name.inspect}; the topologies are #{topology_names.join(', ')}"
    end

    # The systems of a topology entry, in the order they are numbered:
    # system N is 0000.0000.NNNN (N in hex), its loopback 10.255.0.N/32
    # with Prefix-SID index N, its SRGB 16000 + 1000 N.
    def topology_systems(name)
      topology(name)[:links].flat_map { |a, b,| [a, b] }.uniq
    end

    # A topology entry as an isis4r-sim file (docs/simulator.md), every
    # system simulated at Level 1. The simulator's own system stands
    # apart, linked to none, so a test reads the LSPs from its database.
    def topology_file(name, simulator: { "system_id" => "0000.0000.ff00", "hostname" => "sim", "areas" => ["49.0001"],
                                          "level" => 1, "interfaces" => [] })
      t = topology(name)
      routers = topology_systems(name).each_with_index.map do |n, i|
        r = { "name" => n, "system_id" => format("0000.0000.%04x", i + 1), "loopback" => "10.255.0.#{i + 1}",
              "sid" => i + 1, "srgb" => [{ "start" => 16_000 + (1_000 * (i + 1)), "size" => 1_000 }] }
        t[:overloaded].include?(n) ? r.merge("overload" => true) : r
      end
      links = t[:links].map do |a, b, metric, way|
        l = { "from" => a, "to" => b, "metric" => Integer(metric) }
        way == "one_way" ? l.merge("one_way" => true) : l
      end
      { "simulator" => simulator, "segment_routing" => {}, "routers" => routers, "links" => links }
    end

    # A system's SR TLVs, correct unless told: one SR-Capabilities per
    # entry of +srgbs+ (each a list of [first, size]), SR-Algorithm
    # +algorithms+, the loopback with Prefix-SID +sid+ (N set, the
    # context's index, by default), and +more+ prefixes, each
    # [prefix, Prefix-SID hash].
    def sr(ctx, srgbs: [[ctx[:srgb]]], algorithms: [0], sid: nil, more: [])
      sid ||= { flags: %w[N], algorithm: 0, index: ctx[:index] }
      caps = srgbs.map do |blocks|
        SubTlv::SrCapabilities.new(flags: %w[I], descriptors: blocks.map { |first, size| { range: size, label: first } })
      end
      capability = Tlv::RouterCapability.new(router_id: ctx[:router_id],
                                             subtlvs: caps + [SubTlv::SrAlgorithm.new(*algorithms)])
      prefixes = [[ctx[:loopback], sid]] + more
      reach = Tlv::ExtendedIpReachability.new(prefixes.map do |prefix, s|
        { prefix: prefix, metric: 0, subtlvs: [{ prefix_sid: s }] }
      end)
      [capability, reach]
    end
  end
end
