# frozen_string_literal: true

module ISIS
  module Spf
    # One system's Flexible Algorithm Prefix Metrics (RFC 9350 section 8),
    # from TLVs 135 and 236 of its LSPs, LSP Number 0 first: for each
    # prefix, each algorithm's metric. The first FAPM for an algorithm
    # counts; one outside 128 to 255 does not. A prefix's Prefix-SIDs are
    # checked here too, one per algorithm (RFC 8402 section 3.1).
    #
    # The FAPM is used only between levels, with the M flag (section 13.1),
    # which is built after the lab; until then this only reads and checks.
    # A metric past MAX_PATH_METRIC, or a FAPM on an intra-level prefix, is
    # not a finding: no clause forbids sending one; the calculation leaves
    # the prefix out, or the FAPM unused.
    class PrefixMetrics
      attr_reader :metrics, :findings

      def initialize(lsps, policy: :rfc, subject: nil)
        @policy = Validation.policy(policy)
        @subject = subject
        @findings = []
        @metrics = {}
        lsps.flat_map { _1.tlvs.to_a }.each do |tlv|
          next unless tlv.is_a?(Tlv::ExtendedIpReachability) || tlv.is_a?(Tlv::Ipv6Reachability)

          tlv.entries.each { |e| read(e) }
        end
      end

      private

      def read(entry)
        subs = Array(entry.subtlvs).to_a
        prefix = entry.prefix.to_s
        found = Validation.prefix_subtlvs(subs, [@subject, prefix].compact.join(" "))
        @findings.concat(found)
        twice = found.any? { _1.name == :fapm_twice && Validation.action(_1, @policy) == :ignore_fapm }
        subs.grep(SubTlv::Fapm).reject(&:short).each do |f|
          next unless (128..255).cover?(f.algorithm)

          m = (@metrics[prefix] ||= {})
          if m.key?(f.algorithm)
            m[f.algorithm] = nil if twice
          else
            m[f.algorithm] = f.metric
          end
        end
        @metrics[prefix]&.compact!
        @metrics.delete(prefix) if @metrics[prefix] && @metrics[prefix].empty?
      end
    end
  end
end
