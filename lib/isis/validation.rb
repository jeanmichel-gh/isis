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
    #
    # And for the link attribute rules (RFC 9479, RFC 7308), each about one
    # link's attributes for flex-algo, the X bit (Spf::LinkAttributes):
    #
    #   :ignore_subtlv    that ASLA sub-TLV is not used
    #   :ignore_values    its values are not used
    #   :legacy           the L flag is taken as set: the legacy sub-TLVs
    #   :ignore_attribute the attribute is not used from any sub-TLV
    #   :ignore_tlv       that TLV 238 is not used
    #   :use_ag           the Admin Group for groups 0 to 31, the EAG past
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
               actions: { rfc: :ignore_sid, strict: :ignore_sid, lenient: :ignore_sid }),
      # The link attribute rules, docs/design/flex-algo.md, "2. Validation
      # on receive".
      Rule.new(name: :asla_mask_too_long, channel: :errors,
               clause: "RFC 9479 section 4.2: \"If the SABM Length or UDABM Length in the Application Identifier " \
                       "Bit Mask is greater than 8, the entire sub-TLV MUST be ignored\"",
               description: "an ASLA sub-TLV with a SABM or UDABM longer than 8 octets",
               actions: { rfc: :ignore_subtlv, strict: :ignore_subtlv, lenient: :use }),
      Rule.new(name: :asla_l_flag_values, channel: :errors,
               clause: "RFC 9479 section 4.2: with the L-flag set, the sub-sub-TLVs \"MUST NOT be advertised\" " \
                       "and \"MUST be ignored on receipt\"",
               description: "an ASLA sub-TLV with the L flag set that carries values",
               actions: { rfc: :ignore_values, strict: :ignore_values, lenient: :use }),
      Rule.new(name: :asla_l_flag_mixed, channel: :errors,
               clause: "RFC 9479 section 4.2: \"For a given application, the setting of the L-flag MUST be the " \
                       "same in all sub-TLVs for a given link. In cases where this constraint is violated, the " \
                       "L-flag MUST be considered set for this application.\"",
               description: "the L flag set in one ASLA sub-TLV for flex-algo on a link and clear in another",
               actions: { rfc: :legacy, strict: :legacy, lenient: :use }),
      Rule.new(name: :asla_conflict, channel: :errors,
               clause: "RFC 9479 section 4.2: for conflicting values \"the first advertisement received in the " \
                       "lowest-numbered Link State Protocol Data Unit (LSP) MUST be used\"",
               description: "two values of one attribute for flex-algo on one link",
               actions: { rfc: :use_first, strict: :ignore_attribute, lenient: :use_first }),
      Rule.new(name: :asla_srlg_no_link_id, channel: :errors,
               clause: "RFC 9479 section 4.3: \"At least one set of link identifiers (IPv4, IPv6, or Link " \
                       "Local/Remote) MUST be present. Multiple occurrences of the same identifier type MUST NOT " \
                       "be present. TLVs that do not meet this requirement MUST be ignored.\"",
               description: "a TLV 238 with no link identifier, or one type twice",
               actions: { rfc: :ignore_tlv, strict: :ignore_tlv, lenient: :ignore_tlv }),
      Rule.new(name: :admin_group_mismatch, channel: :errors,
               clause: "RFC 7308 section 2.3.1: \"the first 32 bits of the EAG MUST be identical to the " \
                       "advertised AG\"; the receiver uses the AG for bits 0-31 and \"SHOULD report this " \
                       "mismatch\"",
               description: "an Admin Group and an Extended Admin Group that differ in groups 0 to 31",
               actions: { rfc: :use_ag, strict: :ignore_attribute, lenient: :use_ag })
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

    # The findings on one ASLA sub-TLV or TLV 238 on its own, +mask+ its
    # Application Identifier Bit Mask and +values+ the values it carries,
    # as text: the mask's lengths, and values beside the L flag.
    def asla(mask, values, subject)
      if mask.sabm_length > 8 || mask.udabm_length > 8
        return [finding(:asla_mask_too_long, subject,
                        "SABM #{mask.sabm_length} octets, UDABM #{mask.udabm_length}; at most 8")]
      end
      return [finding(:asla_l_flag_values, subject, "L set, with #{values.join('; ')}")] if mask.legacy? && !values.empty?

      []
    end

    # The findings on one TLV 238's link identifiers, +links+ its
    # sub-TLVs. Only the identifiers of section 4.3's Table 2 count.
    def asla_srlg(links, subject)
      types = links.map { _1.class::TYPE if Tlv::AslaSrlg::LINK_IDENTIFIERS.include?(_1.class) }.compact
      return [finding(:asla_srlg_no_link_id, subject, "no link identifier")] if types.empty?

      twice = types.tally.select { |_, n| n > 1 }.keys
      return [finding(:asla_srlg_no_link_id, subject, "sub-TLV #{twice.join(', ')} more than once")] unless twice.empty?

      []
    end

    # The finding on a link's Admin Group, groups 0 to 31, against the
    # first 32 bits of its Extended Admin Group.
    def admin_groups(ag, eag, subject)
      low = eag.select { _1 < 32 }
      return [] if ag.sort == low.sort

      [finding(:admin_group_mismatch, subject,
               "Admin Group #{ag.join(', ').then { _1.empty? ? 'none' : _1 }}, " \
               "EAG #{low.join(', ').then { _1.empty? ? 'none' : _1 }} in 0 to 31; the Admin Group is used")]
    end

    # The finding on +prefixes+, two or more, sharing +index+.
    def prefix_sid_duplicate(index, prefixes)
      finding(:prefix_sid_duplicate, "index #{index}", "the Prefix-SID of #{prefixes.sort.join(' and ')}; both left out")
    end
  end
end
