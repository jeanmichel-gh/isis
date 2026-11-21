# frozen_string_literal: true

module ISIS
  # What was received, checked against the clauses it must meet. The one
  # place a receive rule lives (CLAUDE.md, "Validation"). It decides
  # nothing: a rule says what its clause asks, and the caller acts on it
  # under a receive policy.
  #
  # Each rule is a named finding on one of three channels:
  #
  # * errors: the sender broke a clause, quoted with its section.
  # * gaps: isis4r has no code for something valid.
  # * inconclusive: what arrived cannot support a verdict.
  #
  # And for each receive policy, the action:
  #
  # * :rfc, the default: what the clause asks.
  # * :strict: refuse on any finding.
  # * :lenient: use what arrived where it can be used, to watch what a
  #   sender sends.
  #
  # These are the segment routing rules (RFC 8667, RFC 8660), the first
  # ones here. They run on the decoded LSP database, not on octets: each
  # needs several sub-TLVs, or the LSPs of several systems, which one PDU
  # cannot answer. Spf::Labels runs them after each SPF.
  # routescope docs/design/protocol-conventions.md part 2, and
  # docs/design/ti-lfa.md, "Built to the conventions".
  module Validation
    CHANNELS = %i[errors gaps inconclusive].freeze
    POLICIES = %i[rfc strict lenient].freeze

    # One rule. +actions+ maps each policy to what the caller does:
    #
    #   :ignore_srgb  the node is treated as if it has no SRGB
    #   :ignore_node  the node's SR data is not used at all
    #   :use_first    the first SR-Capabilities, in the lowest-numbered LSP
    #   :ignore_sid   that Prefix-SID is not used
    #   :drop_both    neither of the prefixes is given a label
    #   :use          used as it arrived
    Rule = Struct.new(:name, :channel, :clause, :description, :actions, keyword_init: true)

    # One finding: the rule's name, channel and clause, what it is about
    # (+subject+, a system or a prefix) and what was seen (+detail+).
    Finding = Struct.new(:name, :channel, :clause, :subject, :detail) do
      def to_s
        "#{subject}: #{detail} (#{clause})"
      end

      def to_hash
        { name: name.to_s, channel: channel.to_s, clause: clause, subject: subject, detail: detail }
      end
    end

    RULES = [
      Rule.new(name: :srgb_range_zero, channel: :errors,
               clause: 'RFC 8667 section 3.1: "The range value MUST be higher than 0"',
               description: "an SRGB descriptor with a range of 0",
               actions: { rfc: :ignore_srgb, strict: :ignore_node, lenient: :use }),
      Rule.new(name: :srgb_overlap, channel: :errors,
               clause: 'RFC 8660 section 2.3: "The list of ranges comprising the SRGB MUST NOT overlap"',
               description: "two SRGB ranges that overlap",
               actions: { rfc: :ignore_srgb, strict: :ignore_node, lenient: :use }),
      # Lenient too: a label outside 16 to 1048575 cannot be installed.
      Rule.new(name: :srgb_reserved, channel: :errors,
               clause: "RFC 8660 section 2.3: a range \"MUST NOT cover or overlap with a reserved label value\"",
               description: "an SRGB range below 16 or past 1048575",
               actions: { rfc: :ignore_srgb, strict: :ignore_node, lenient: :ignore_srgb }),
      Rule.new(name: :sr_capabilities_twice, channel: :errors,
               clause: 'RFC 8667 section 3.1: "a router MUST NOT advertise more than one SR-Capabilities sub-TLV"',
               description: "more than one SR-Capabilities from one system",
               actions: { rfc: :use_first, strict: :ignore_node, lenient: :use_first }),
      Rule.new(name: :prefix_sid_vl_invalid, channel: :errors,
               clause: "RFC 8667 section 2.1.1.1: a SID \"received with an invalid setting for the V-Flag and " \
                       "L-Flag MUST be ignored\"",
               description: "a Prefix-SID with V set and L clear, or L set and V clear",
               actions: { rfc: :ignore_sid, strict: :ignore_sid, lenient: :ignore_sid }),
      Rule.new(name: :algorithm_not_advertised, channel: :errors,
               clause: "RFC 8667 section 2.1: a Prefix-SID with an algorithm its node has not advertised " \
                       "\"MUST ignore the Prefix-SID sub-TLV\"",
               description: "a Prefix-SID for an algorithm its origin does not run",
               actions: { rfc: :ignore_sid, strict: :ignore_sid, lenient: :use }),
      # RFC 8660 section 2.5 says which one wins; isis4r has no code for it
      # yet, so no policy can pick one.
      Rule.new(name: :prefix_sid_duplicate, channel: :errors,
               clause: 'RFC 8667 section 2.1: "The \'Prefix-SID\' MUST be unique within a given IGP domain"',
               description: "one index on two prefixes",
               actions: { rfc: :drop_both, strict: :drop_both, lenient: :drop_both }),
      Rule.new(name: :prefix_sid_label, channel: :gaps,
               clause: "isis4r has no code for a Prefix-SID carried as a label, V and L set " \
                       "(RFC 8667 section 2.1.1.1)",
               description: "a Prefix-SID that is a label, not an index",
               actions: { rfc: :ignore_sid, strict: :ignore_sid, lenient: :ignore_sid })
    ].to_h { [_1.name, _1] }.freeze

    module_function

    def rule(name)
      RULES.fetch(name) { raise ArgumentError, "no rule #{name.inspect}; the rules are #{RULES.keys.join(', ')}" }
    end

    def policy(name)
      name = (name || :rfc).to_sym
      return name if POLICIES.include?(name)

      raise ArgumentError, "receive_policy is #{POLICIES.join(', ')}, not #{name}"
    end

    def finding(name, subject, detail)
      r = rule(name)
      Finding.new(name, r.channel, r.clause, subject, detail)
    end

    # What +policy+ does about +finding+.
    def action(finding, policy)
      rule(finding.name).actions.fetch(policy)
    end

    # The findings on one system's SRGB, +ranges+ as [first, last] pairs
    # (a range of 0 gives last = first - 1).
    def srgb(ranges, subject)
      list = []
      ranges.each do |first, last|
        list << finding(:srgb_range_zero, subject, "range at #{first} is empty") if last < first
      end
      real = ranges.reject { |first, last| last < first }
      real.each do |first, last|
        next unless first < 16 || last > 0xfffff

        list << finding(:srgb_reserved, subject, "range #{first}-#{last} is outside 16-1048575")
      end
      real.combination(2).each do |(a, b), (c, d)|
        list << finding(:srgb_overlap, subject, "ranges #{a}-#{b} and #{c}-#{d} overlap") if a <= d && c <= b
      end
      list
    end

    # The findings on one system's count of SR-Capabilities sub-TLVs.
    def sr_capabilities(count, subject)
      return [] if count <= 1

      [finding(:sr_capabilities_twice, subject, "#{count} SR-Capabilities sub-TLVs; the first is used")]
    end

    # The findings on one Prefix-SID: its V and L flags, and its algorithm
    # against the ones its origin runs (+algorithms+, nil when the origin
    # is not known).
    def prefix_sid(sid, algorithms, subject)
      v = sid.flag?("V")
      l = sid.flag?("L")
      return [finding(:prefix_sid_vl_invalid, subject, "V #{v ? 'set' : 'clear'}, L #{l ? 'set' : 'clear'}")] if v != l
      return [finding(:prefix_sid_label, subject, "label #{sid.label}")] if v && l
      if algorithms && !algorithms.include?(sid.algorithm)
        return [finding(:algorithm_not_advertised, subject,
                        "algorithm #{sid.algorithm}, its origin runs #{algorithms.join(', ')}")]
      end

      []
    end

    # The finding on +prefixes+, two or more, sharing +index+.
    def prefix_sid_duplicate(index, prefixes)
      finding(:prefix_sid_duplicate, "index #{index}", "the Prefix-SID of #{prefixes.sort.join(' and ')}; both left out")
    end
  end
end
