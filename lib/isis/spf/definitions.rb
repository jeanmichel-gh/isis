# frozen_string_literal: true

module ISIS
  module Spf
    # One system's Flexible Algorithm Definitions, from its LSPs, LSP
    # Number 0 first (RFC 9350 sections 5 and 6; docs/design/flex-algo.md,
    # "Selection", its first step). The FADs of each algorithm are merged
    # into one Definition, as section 6 asks of a FAD split across
    # sub-TLVs:
    #
    # * the fixed part, the first in the lowest-numbered LSP;
    # * the admin group rules and the flags, the first occurrence;
    # * the excluded SRLGs, the union of all.
    #
    # What breaks RFC 9350 is a finding of Validation, acted on under
    # +policy+. A Definition isis4r cannot run keeps the reason, so that
    # selection (step 4) can stop taking part in it.
    class Definitions
      Definition = Struct.new(:algorithm, :metric_type, :calc_type, :priority, :exclude_any, :include_any,
                              :include_all, :flags, :exclude_srlg, :unknown, :unsupported, keyword_init: true) do
        def supported? = unsupported.nil?

        # The metric type by name, or its number.
        def metric_name = SubTlv::Fad::METRIC_TYPES.fetch(metric_type, metric_type)

        def to_hash
          h = { algorithm: algorithm, metric_type: metric_name, calc_type: calc_type, priority: priority }
          { exclude_any: exclude_any, include_any: include_any, include_all: include_all, flags: flags,
            exclude_srlg: exclude_srlg, unknown_subtlvs: unknown }.each { |k, v| h[k] = v unless v.empty? }
          h[:unsupported] = unsupported if unsupported
          h
        end
      end

      RULES = { SubTlv::FadExcludeAdminGroup => :exclude_any, SubTlv::FadIncludeAnyAdminGroup => :include_any,
                SubTlv::FadIncludeAllAdminGroup => :include_all }.freeze

      attr_reader :definitions, :findings

      def initialize(lsps, policy: :rfc, subject: nil)
        @policy = Validation.policy(policy)
        @subject = subject || "system"
        @findings = []
        fads = read_fads(lsps)
        @definitions = fads.group_by(&:algorithm).filter_map { |a, list| (d = build(list)) && [a, d] }.to_h
      end

      # The Definition of +algorithm+, or nil.
      def [](algorithm) = @definitions[algorithm]

      private

      def act?(found, *actions) = found.any? { actions.include?(Validation.action(_1, @policy)) }

      # The FADs that can be used, in order, with the findings on each.
      def read_fads(lsps)
        lsps.flat_map { _1.tlvs.to_a.grep(Tlv::RouterCapability) }.flat_map do |cap|
          next [] if cap.router_id.nil?

          s = Validation.fad_s_bit(cap, @subject)
          @findings.concat(s)
          next [] if act?(s, :ignore_fad)

          cap.subtlvs.to_a.grep(SubTlv::Fad).reject(&:short).select do |fad|
            found = Validation.fad(fad, @subject)
            @findings.concat(found)
            !act?(found, :ignore_fad)
          end
        end
      end

      # One algorithm's FADs as one Definition, or nil when the policy
      # ignores them.
      def build(fads)
        found = Validation.fad_split(fads, @subject)
        @findings.concat(found)
        return nil if act?(found, :ignore_fad)

        algorithm, metric_type, calc_type, priority = fads.first.fixed
        d = Definition.new(algorithm: algorithm, metric_type: metric_type, calc_type: calc_type, priority: priority,
                           exclude_any: [], include_any: [], include_all: [], flags: [], exclude_srlg: [],
                           unknown: [])
        taken = {}
        fads.flat_map { _1.subtlvs.to_a }.each do |s|
          case s
          when SubTlv::FadExcludeAdminGroup
            # Its two subclasses are matched here too, each by its own
            # class: the first of each is used.
            next if taken[s.class]

            taken[s.class] = true
            d[RULES.fetch(s.class)] = s.groups
          when SubTlv::FadFlags
            next if taken[s.class]

            taken[s.class] = true
            d.flags = s.bits
          when SubTlv::FadExcludeSrlg
            d.exclude_srlg |= s.srlgs
          else
            d.unknown |= [s.type]
          end
        end
        gap = Validation.fad_unsupported(algorithm, metric_type: metric_type, calc_type: calc_type, flags: d.flags,
                                                    unknown: d.unknown, subject: @subject)
        @findings.concat(gap)
        d.unsupported = gap.first&.detail
        d
      end
    end
  end
end
