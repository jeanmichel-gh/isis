# frozen_string_literal: true

module ISIS
  # The catalog of crafted inputs, as bgp4r's BGP::Fault, vtep4r's
  # VXLAN::Fault and bfd4r's BFD::Fault (routescope
  # docs/design/protocol-conventions.md, part 3). A test, or later the
  # injector, sends an entry to a router and checks what it did against
  # what the RFC expects.
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
    # SRGB as [first, size], a second prefix, and its neighbors with
    # their metrics, as { "0000.0000.0002" => 10 }, so SPF reaches it.
    def context(system_id: "0000.0000.0003", loopback: "10.255.0.3/32", index: INDEX, srgb: SRGB,
                second: "10.255.9.3/32", neighbors: {})
      { system_id: system_id, loopback: loopback, router_id: loopback.split("/").first, index: index,
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
