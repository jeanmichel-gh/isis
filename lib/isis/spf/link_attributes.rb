# frozen_string_literal: true

require "ipaddr"

module ISIS
  module Spf
    # One node's link attributes for flex-algo, from its LSPs, LSP Number 0
    # first (docs/design/flex-algo.md, "Calculation"). RFC 9350 section 12:
    # flex-algo "MUST use" the ASLA sub-TLVs with the X bit, "unless ... the
    # L-flag is set", and then the legacy sub-TLVs. RFC 9479 section 4.2
    # gives the order this reads them in, for each link:
    #
    # 1. ASLA sub-TLVs (16) with X and the L flag clear: their values.
    # 2. With the L flag set for X: the link's legacy sub-TLVs, 3, 14, 18,
    #    33 and 34, and its TLV 138.
    # 3. Otherwise, for an attribute no ASLA with X gives: the ASLA
    #    sub-TLVs with a zero-length mask.
    # 4. Otherwise none. A metric is never taken as 0 (9350 section 13).
    #
    # SRLGs come the same way from TLV 238 (9479 section 4.3): those with
    # X, else the zero-length ones; with L set in those with X, TLV 138.
    #
    # A link is a TLV 22 entry, keyed by its neighbour and its first IPv4
    # interface and neighbour addresses, link identifiers and IPv6
    # interface address. Entries with one key, in several LSPs, are one
    # link, the lowest LSP Number first. Parallel links to one neighbour
    # are told apart by their addresses.
    #
    # What breaks RFC 9479 or RFC 7308 is a finding of Validation, acted on
    # under +policy+.
    class LinkAttributes
      # One link: what identifies it, and its attributes for flex-algo.
      # +affinity+ is the groups set, +delay+ a Hash of :min, :max and
      # :average in microseconds, those given. Nil is not advertised.
      Link = Struct.new(:neighbor, :interface, :remote, :local_id, :interface6, :affinity, :te_metric, :delay,
                        :srlg, :legacy, keyword_init: true) do
        # The attributes as show.topology gives them: only those present.
        def to_hash
          h = {}
          h[:affinity] = affinity if affinity
          h[:te_metric] = te_metric if te_metric
          h[:delay] = delay if delay
          h[:srlg] = srlg if srlg
          h[:asla_legacy] = true if legacy
          h
        end

        # The minimum delay, the metric RFC 9350's metric type 1 reads.
        def min_delay = delay&.fetch(:min, nil)
      end

      # The attributes and the classes they come from.
      ATTRIBUTES = [SubTlv::AdminGroup, SubTlv::ExtendedAdminGroup, SubTlv::TeDefaultMetric, SubTlv::LinkDelay,
                    SubTlv::MinMaxLinkDelay].freeze

      attr_reader :links, :findings, :policy

      def initialize(lsps, policy: :rfc, subject: nil)
        @policy = Validation.policy(policy)
        @subject = subject
        @findings = []
        tlvs = lsps.flat_map { _1.tlvs.to_a }
        @links = read_links(tlvs)
        read_srlgs(tlvs)
      end

      # The link for a TLV 22 entry, or nil.
      def for(entry)
        @by_key[self.class.key(entry)]
      end

      # The key of a TLV 22 entry: its neighbour, then its first sub-TLVs
      # 6, 8, 4 and 12.
      def self.key(entry)
        subs = Array(entry.subtlvs)
        [entry.neighbor.b, first(subs, SubTlv::Ipv4InterfaceAddress)&.address&.to_s,
         first(subs, SubTlv::Ipv4NeighborAddress)&.address&.to_s, first(subs, SubTlv::LinkIdentifiers)&.local,
         first(subs, SubTlv::Ipv6InterfaceAddress)&.address&.to_s]
      end

      def self.first(subs, klass) = subs.find { _1.instance_of?(klass) }

      private

      def read_links(tlvs)
        grouped = {}
        tlvs.grep(Tlv::ExtendedIsReachability).flat_map(&:entries).each do |e|
          (grouped[self.class.key(e)] ||= []).concat(Array(e.subtlvs).to_a)
        end
        @by_key = grouped.to_h do |key, subs|
          neighbor, interface, remote, local_id, interface6 = key
          link = Link.new(neighbor: neighbor, interface: interface, remote: remote, local_id: local_id,
                          interface6: interface6)
          read_link(link, subs)
          [key, link]
        end
        @by_key.values
      end

      def subject(link)
        hex = link.neighbor.unpack1("H*")
        name = "#{hex[0, 12].scan(/.{4}/).join('.')}.#{hex[12, 2]}"
        via = link.interface || link.interface6 || link.local_id
        text = via ? "link to #{name} via #{via}" : "link to #{name}"
        @subject ? "#{@subject} #{text}" : text
      end

      # The link's attributes from its sub-TLVs +subs+, in order.
      def read_link(link, subs)
        aslas = usable(subs.grep(SubTlv::Asla), subject(link))
        x = aslas.select { _1.application?("X") }
        link.legacy = legacy?(x, subject(link))
        values = if link.legacy
                   { legacy: subs.reject { _1.is_a?(SubTlv::Asla) } }
                 else
                   { x: x.reject { l_flag?(_1) }.flat_map { _1.subtlvs.to_a },
                     zero: aslas.select { zero_mask?(_1) && !l_flag?(_1) }.flat_map { _1.subtlvs.to_a } }
                 end
        found = ATTRIBUTES.to_h { |klass| [klass, attribute(values, klass, link)] }
        link.affinity = affinity(found[SubTlv::AdminGroup], found[SubTlv::ExtendedAdminGroup], link)
        link.te_metric = found[SubTlv::TeDefaultMetric]&.metric
        delay = {}
        if (mm = found[SubTlv::MinMaxLinkDelay])
          delay[:min] = mm.min
          delay[:max] = mm.max
        end
        delay[:average] = found[SubTlv::LinkDelay].delay if found[SubTlv::LinkDelay]
        link.delay = delay unless delay.empty?
      end

      # The ASLA sub-TLVs that can be read, with the findings on each.
      def usable(list, subject)
        list.select do |a|
          next false if a.short

          f = Validation.asla(a, a.subtlvs.map(&:to_s), subject)
          @findings.concat(f)
          f.none? { Validation.action(_1, @policy) == :ignore_subtlv }
        end
      end

      def zero_mask?(mask) = mask.sabm_length.zero? && mask.udabm_length.zero?

      # Whether the L flag of an ASLA sub-TLV or a TLV 238 counts: set,
      # and not on values the policy uses beside it (asla_l_flag_values,
      # lenient).
      def l_flag?(mask)
        return false unless mask.legacy?

        values = mask.is_a?(Tlv::AslaSrlg) ? mask.srlgs : mask.subtlvs.to_a
        values.empty? || Validation.rule(:asla_l_flag_values).actions.fetch(@policy) != :use
      end

      # Whether X takes the legacy advertisements: the L flag the same in
      # every sub-TLV with X, or, when it differs, as the policy says.
      def legacy?(x, subject)
        flags = x.map { l_flag?(_1) }.uniq
        return flags == [true] if flags.size < 2

        f = Validation.finding(:asla_l_flag_mixed, subject, "L set in #{x.count { l_flag?(_1) }} of #{x.size}")
        @findings << f
        Validation.action(f, @policy) == :legacy
      end

      # The first value of +klass+: from the X sub-TLVs, else the
      # zero-length ones; or the legacy sub-TLVs. Two values that differ,
      # among the X sub-TLVs or among the zero-length ones, are a conflict.
      def attribute(values, klass, link)
        return values[:legacy].find { _1.instance_of?(klass) } if values.key?(:legacy)

        %i[x zero].each do |source|
          list = values[source].select { _1.instance_of?(klass) }
          next if list.empty?

          return list.first if list.map(&:encode).uniq.size == 1

          f = Validation.finding(:asla_conflict, subject(link),
                                 "#{list.size} #{klass.name.split('::').last} values: " \
                                 "#{list.map(&:to_s).join('; ')}; the first is used")
          @findings << f
          return Validation.action(f, @policy) == :use_first ? list.first : nil
        end
        nil
      end

      # The groups from an Admin Group and an Extended Admin Group, either
      # nil. RFC 7308 section 2.3.1: with both, the AG gives 0 to 31 and the
      # EAG the rest.
      def affinity(ag, eag, link)
        return nil unless ag || eag
        return (ag || eag).groups unless ag && eag

        found = Validation.admin_groups(ag.groups, eag.groups, subject(link))
        @findings.concat(found)
        return nil if found.any? { Validation.action(_1, @policy) == :ignore_attribute }

        (ag.groups + eag.groups.select { _1 >= 32 }).sort
      end

      # The SRLGs of each link: TLV 238 with X, else with a zero-length
      # mask; with L set in those with X, TLV 138. The ASLA sub-TLV's L
      # flag does not reach SRLGs: they are not among its sub-sub-TLVs.
      def read_srlgs(tlvs)
        x = Hash.new { |h, k| h[k] = [] }.compare_by_identity
        zero = Hash.new { |h, k| h[k] = [] }.compare_by_identity
        tlvs.grep(Tlv::AslaSrlg).each do |t|
          next if t.short

          link = asla_srlg_link(t)
          next unless link

          if t.application?("X")
            x[link] << t
          elsif zero_mask?(t) && !l_flag?(t)
            zero[link] << t
          end
        end
        @links.each do |link|
          list = x[link]
          values = if list.empty?
                     zero[link]
                   elsif legacy?(list, subject(link))
                     next link.srlg = legacy_srlgs(tlvs, link)
                   else
                     list.reject { l_flag?(_1) }
                   end
          link.srlg = values.flat_map(&:srlgs).uniq unless values.empty?
        end
      end

      # The link a TLV 238 names, after its checks, or nil.
      def asla_srlg_link(tlv)
        subject = "#{@subject} TLV 238 to #{tlv.neighbor_s}".strip
        found = Validation.asla(tlv, tlv.srlgs.map { "SRLG #{_1}" }, subject) +
                Validation.asla_srlg(tlv.links.to_a, subject)
        @findings.concat(found)
        return nil if found.any? { %i[ignore_subtlv ignore_tlv].include?(Validation.action(_1, @policy)) }

        ids = tlv.links.to_a
        @links.find do |l|
          next false unless l.neighbor == tlv.neighbor

          ids.any? do |s|
            case s
            when SubTlv::Ipv4InterfaceAddress then l.interface && s.address&.to_s == l.interface
            when SubTlv::Ipv4NeighborAddress then l.remote && s.address&.to_s == l.remote
            when SubTlv::LinkIdentifiers then l.local_id && s.local == l.local_id
            when SubTlv::Ipv6InterfaceAddress then l.interface6 && s.address.to_s == l.interface6
            else false
            end
          end
        end
      end

      # TLV 138's SRLGs for +link+: the same neighbour, and its local
      # address, or its link local identifier when unnumbered.
      def legacy_srlgs(tlvs, link)
        list = tlvs.grep(Tlv::Srlg).reject(&:short).select do |t|
          next false unless t.neighbor == link.neighbor

          if t.numbered?
            link.interface && t.local == IPAddr.new(link.interface).to_i
          else
            link.local_id && t.local == link.local_id
          end
        end
        list.empty? ? nil : list.flat_map(&:srlgs).uniq
      end
    end
  end
end
