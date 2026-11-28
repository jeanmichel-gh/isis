# frozen_string_literal: true

require "ipaddr"

module ISIS
  module Srv6
    # One locator of this system (RFC 9352 section 5: "a covering prefix
    # for all SIDs provisioned on that node that have the matching
    # topology/algorithm"), with its SID structure (RFC 8986 section 3.1:
    # LOC:FUNCT:ARG, the locator being the block and the node).
    class Locator
      attr_reader :name, :prefix, :length, :algorithm, :block, :node, :function, :argument

      def initialize(name:, prefix:, algorithm:, block:, node:, function:, argument:)
        @name = name
        @prefix = prefix
        @length = Integer(prefix.split("/").last)
        @algorithm = algorithm
        @block = block
        @node = node
        @function = function
        @argument = argument
      end

      # The SID with function +function+ and a zero argument, as
      # "fc00:0:1:2::".
      def sid(function)
        raise Error, "locator #{@name}: function #{function} does not fit in #{@function} bits" if function >= 1 << @function

        base = IPAddr.new(@prefix)
        IPAddr.new(base.to_i | (function << (128 - @length - @function)), Socket::AF_INET6).to_s
      end

      # The SID Structure sub-sub-TLV, as a sub-TLV list keys it.
      def structure = { sid_structure: { block: @block, node: @node, function: @function, argument: @argument } }

      def covers?(prefix)
        IPAddr.new(@prefix).include?(IPAddr.new(prefix.to_s))
      end

      def overlaps?(other)
        covers?(other.prefix) || other.covers?(@prefix)
      end

      def to_hash
        { name: @name, prefix: @prefix, algorithm: @algorithm,
          structure: { block: @block, node: @node, function: @function, argument: @argument } }
      end
    end

    # This system's SRv6 (RFC 9352), as its originators advertise it: its
    # locators, the SRv6 Capabilities sub-TLV, and the SIDs from each
    # locator, End and End.DT6 for the node and an End.X per adjacency.
    # docs/design/srv6.md is the design; nothing here installs a SID. One
    # instance serves both levels, so an adjacency at both levels of a
    # point to point circuit has one End.X SID.
    #
    # Functions, per locator (docs/design/srv6.md, "Origination"): 0 for
    # End, 1 for End.DT6, then 2 upwards for End.X. FRR 10.7.1 gives End.X
    # function 1, so the two are told apart in a capture. An adjacency's
    # function stays its own for as long as this process runs, as
    # SegmentRouting's Adj-SID labels do, which keeps it while the
    # adjacency is up, as the design asks, and after.
    class Local
      # The keys of the configuration's srv6 block, of a locator, and of a
      # locator's structure.
      KEYS = %i[locators interface decap receive_policy].freeze
      LOCATOR_KEYS = %i[name prefix algorithm structure].freeze
      STRUCTURE_KEYS = %i[block node function argument].freeze
      # The dummy device the End and End.DT6 SIDs sit on, FRR's default.
      INTERFACE = "sr0"
      END_FUNCTION = 0
      DECAP_FUNCTION = 1
      FIRST_END_X = 2

      attr_reader :locators, :interface, :decap, :receive_policy, :router_id

      # +locators+ is a list of Locator. +no_end_x+ lists circuit names
      # whose adjacencies get no End.X SID.
      def initialize(locators:, router_id:, interface: INTERFACE, decap: true, receive_policy: :rfc, no_end_x: [])
        raise ArgumentError, "srv6 needs a locator" if locators.empty?

        @locators = locators
        @router_id = router_id
        @interface = interface.to_s
        @decap = decap
        @receive_policy = Validation.policy(receive_policy)
        @no_end_x = no_end_x.map(&:to_s)
        @functions = Hash.new { |h, k| h[k] = {} }
      end

      # The configuration's srv6 block, or nil when there is none:
      #
      #   srv6:
      #     locators:
      #       - name: main
      #         prefix: fc00:0:1::/48
      #         algorithm: 0
      #         structure: { block: 32, node: 16, function: 16, argument: 0 }
      #     interface: sr0          the dummy the End and End.DT6 SIDs sit on
      #     decap: true             an End.DT6 SID per locator
      #     receive_policy: rfc     rfc, strict or lenient (Validation)
      #
      # Refused, each by name: an unknown key; srv6 without ipv6; a
      # locator that is not IPv6, whose length is not its block and node,
      # whose structure passes 128 bits (RFC 8986 section 3.1), that
      # overlaps another, or that is one of +ipv6_prefixes+, since the
      # locator goes in TLV 236 already. Algorithm 0 only: a flex-algo
      # locator is the design's step 8.
      #
      # +router_id+ is TLV 242's, as SegmentRouting reads it: the
      # configuration's, else the first IPv4 /32 among +prefixes+. TLV 242's
      # Router ID stays IPv4 (docs/design/srv6.md, "Wire format").
      def self.from_config(srv6, ipv6:, router_id:, prefixes:, ipv6_prefixes: [], no_end_x: [])
        return nil if srv6.nil?

        srv6 = {} if srv6 == true
        raise ArgumentError, "srv6 is a map of #{KEYS.join(', ')}" unless srv6.is_a?(Hash)

        unknown(srv6, KEYS, "srv6")
        raise ArgumentError, "srv6 needs ipv6: true" unless ipv6

        router_id ||= prefixes.map { |p| p[:prefix].to_s }.find { |p| p.end_with?("/32") && !p.include?(":") }&.split("/")&.first
        raise ArgumentError, "srv6 needs a router_id for TLV 242, or an IPv4 /32 among the prefixes" unless router_id

        list = Array(srv6[:locators]).each_with_index.map { |l, i| locator(l, i) }
        raise ArgumentError, "srv6 needs at least one locator" if list.empty?

        list.combination(2).each do |a, b|
          raise ArgumentError, "srv6: locators #{a.name} (#{a.prefix}) and #{b.name} (#{b.prefix}) overlap" if a.overlaps?(b)
        end
        names = list.map(&:name)
        raise ArgumentError, "srv6: two locators are named #{names.find { names.count(_1) > 1 }}" if names.uniq.size < names.size

        Array(ipv6_prefixes).each do |p|
          l = list.find { _1.prefix == canonical(p[:prefix]) } or next
          raise ArgumentError, "srv6: locator #{l.name} is also in ipv6_prefixes; the locator goes in TLV 236 already"
        end
        decap = srv6.fetch(:decap, true)
        raise ArgumentError, "srv6: decap is true or false, not #{decap.inspect}" unless [true, false].include?(decap)

        new(locators: list, router_id: router_id, interface: srv6.fetch(:interface, INTERFACE), decap: decap,
            receive_policy: srv6[:receive_policy] || :rfc, no_end_x: no_end_x)
      end

      def self.unknown(hash, keys, where)
        extra = hash.keys.map(&:to_sym) - keys
        return if extra.empty?

        raise ArgumentError, "#{where}: unknown #{extra.size == 1 ? 'key' : 'keys'} #{extra.join(', ')}; " \
                             "the keys are #{keys.join(', ')}"
      end

      def self.canonical(text)
        a = IPAddr.new(text.to_s)
        "#{a}/#{a.prefix}"
      rescue IPAddr::Error
        text.to_s
      end

      def self.locator(l, index)
        raise ArgumentError, "srv6: a locator is a map of #{LOCATOR_KEYS.join(', ')}" unless l.is_a?(Hash)

        name = (l[:name] || "locator#{index}").to_s
        where = "srv6 locator #{name}"
        unknown(l, LOCATOR_KEYS, where)
        text = l.fetch(:prefix) { raise ArgumentError, "#{where}: a prefix is needed" }.to_s
        a = begin
          IPAddr.new(text)
        rescue IPAddr::Error
          raise ArgumentError, "#{where}: #{text} is not an IPv6 prefix"
        end
        raise ArgumentError, "#{where}: #{text} is not an IPv6 prefix" unless a.ipv6? && text.include?("/")
        raise ArgumentError, "#{where}: #{text} has bits set past /#{a.prefix}" unless IPAddr.new(text.split("/").first).to_i == a.to_i

        algorithm = l.fetch(:algorithm, 0)
        unless algorithm.zero?
          raise ArgumentError, "#{where}: algorithm 0 only; a flex-algo locator is docs/design/srv6.md's step 8"
        end

        s = l.fetch(:structure) { raise ArgumentError, "#{where}: a structure is needed, { block:, node:, function:, argument: }" }
        raise ArgumentError, "#{where}: structure is a map of #{STRUCTURE_KEYS.join(', ')}" unless s.is_a?(Hash)

        unknown(s, STRUCTURE_KEYS, "#{where} structure")
        bits = STRUCTURE_KEYS.to_h do |k|
          v = s.fetch(k, k == :argument ? 0 : nil)
          raise ArgumentError, "#{where}: structure #{k} is a number of bits, 0 to 128, not #{v.inspect}" \
            unless v.is_a?(Integer) && v.between?(0, 128)

          [k, v]
        end
        unless bits[:block] + bits[:node] == a.prefix
          raise ArgumentError, "#{where}: block #{bits[:block]} and node #{bits[:node]} are #{bits[:block] + bits[:node]} bits, " \
                               "the locator /#{a.prefix}"
        end
        raise ArgumentError, "#{where}: function #{bits[:function]} gives no room for a SID" if bits[:function].zero?
        if bits.values.sum > 128
          raise ArgumentError, "#{where}: the structure is #{bits.values.sum} bits, past 128 (RFC 8986 section 3.1)"
        end

        Locator.new(name: name, prefix: "#{a}/#{a.prefix}", algorithm: algorithm, **bits)
      end

      # The SRv6 Capabilities sub-TLV, O clear: isisd does not process the
      # O-bit (RFC 9259; out of scope).
      def capability_subtlv = SubTlv::Srv6Capabilities.new

      # The locator that End.X SIDs of algorithm 0 come from: the first of
      # algorithm 0.
      def adjacency_locator = @locators.find { _1.algorithm.zero? }

      # TLV 27's entries for this system's own locators (RFC 9352 section
      # 7.1): metric 0, as FRR 10.7.1 sends its own; D clear; the locator's
      # algorithm; then the Prefix Attribute Flags, which 7.1 says "SHOULD
      # be included", none set; then the End SID and, with decap, the
      # End.DT6 SID, each with its SID Structure.
      def locator_entries
        @locators.map do |l|
          subs = [{ prefix_attribute_flags: {} }, end_sid(l, "End", END_FUNCTION)]
          subs << end_sid(l, "End.DT6", DECAP_FUNCTION) if @decap
          Tlv::Srv6Locator::Entry.new(locator: l.prefix, metric: 0, algorithm: l.algorithm, subtlvs: subs)
        end
      end

      # The locators of algorithm 0 for TLV 236, at the same metric. RFC
      # 9352 section 5: locators of algorithms 0 and 1 "SHOULD also be
      # advertised in a Prefix Reachability TLV (236 or 237)". Section 6:
      # "it SHOULD advertise the Prefix Attribute Flags sub-TLV, if used, in
      # both TLVs and use the same flags."
      def locator_prefixes
        @locators.select { _1.algorithm.zero? }.map do |l|
          { prefix: l.prefix, metric: 0, subtlvs: [{ prefix_attribute_flags: {} }] }
        end
      end

      # The End.X SID sub-TLV for a point to point adjacency, +key+ naming
      # it: behaviour End.X, algorithm 0, weight 0, B and P clear (RFC 9352
      # section 8.1).
      def end_x_sids(circuit, key)
        return [] if @no_end_x.include?(circuit.to_s)

        l = adjacency_locator or return []
        [{ end_x_sid: { behavior: "End.X", algorithm: l.algorithm, sid: l.sid(function(l, [circuit.to_s, key])),
                        subtlvs: [l.structure] } }]
      end

      # The LAN End.X SID sub-TLVs for a LAN circuit's neighbours, System
      # IDs as octets: one per neighbour, in the TLV 22 entry to the DIS
      # (section 8.2).
      def lan_end_x_sids(circuit, neighbors)
        return [] if @no_end_x.include?(circuit.to_s)

        l = adjacency_locator or return []
        neighbors.map do |n|
          { lan_end_x_sid: { neighbor: SystemId.from_bytes(n).to_s, behavior: "End.X", algorithm: l.algorithm,
                             sid: l.sid(function(l, [circuit.to_s, n.b])), subtlvs: [l.structure] } }
        end
      end

      # The SIDs given out, as { sid:, behavior:, locator:, adjacency: }:
      # each locator's End and End.DT6, then each End.X.
      def sids
        node = @locators.flat_map do |l|
          list = [{ sid: l.sid(END_FUNCTION), behavior: "End", locator: l.name }]
          list << { sid: l.sid(DECAP_FUNCTION), behavior: "End.DT6", locator: l.name } if @decap
          list
        end
        node + @locators.flat_map do |l|
          @functions[l.name].map { |key, f| { sid: l.sid(f), behavior: "End.X", locator: l.name, adjacency: key } }
        end
      end

      # A locator entry from the other level, as RFC 9352 section 7.1 and
      # RFC 7794 section 2.1 have it propagated: the metric, the algorithm
      # and the SIDs kept; D set going down, from Level 2 into Level 1
      # (RFC 5305 section 4.1's up/down bit), and kept going up; and Prefix
      # Attribute Flags with R, "Set when the prefix has been leaked from
      # one level to another", the other flags kept ("MUST be preserved
      # when leaked between levels"). Section 7.1: the sub-TLV "MUST be
      # included in the Locator TLV when it is leaked upwards". +entry+ is
      # a Tlv::Srv6Locator::Entry or its hash; +metric+ the route's.
      def self.propagated(entry, down:, metric: nil)
        h = entry.is_a?(Hash) ? entry.dup : entry.to_hash
        h[:metric] = metric if metric
        h[:flags] = (Array(h[:flags]) | (down ? %w[D] : [])) & Tlv::Srv6Locator::Entry::FLAGS
        h.delete(:flags) if h[:flags].empty?
        subs = Array(h[:subtlvs])
        paf = subs.find { _1.key?(:prefix_attribute_flags) }
        flags = paf ? Array(paf[:prefix_attribute_flags][:flags]) : []
        new_paf = { prefix_attribute_flags: (paf ? paf[:prefix_attribute_flags] : {}).merge(flags: SubTlv::PrefixAttributeFlags::FLAGS & (flags | %w[R])) }
        h[:subtlvs] = paf ? subs.map { _1.equal?(paf) ? new_paf : _1 } : [new_paf] + subs
        Tlv::Srv6Locator::Entry.new(**h)
      end

      private

      def end_sid(locator, behavior, function)
        { end_sid: { behavior: behavior, sid: locator.sid(function), subtlvs: [locator.structure] } }
      end

      # The lowest function from FIRST_END_X not given out in +locator+, the
      # same one for a key every time.
      def function(locator, key)
        given = @functions[locator.name]
        given[key] ||= begin
          used = given.values
          f = (FIRST_END_X...(1 << locator.function)).find { !used.include?(_1) }
          raise Error, "locator #{locator.name}: its #{locator.function} function bits are used up" unless f

          f
        end
      end
    end
  end
end
