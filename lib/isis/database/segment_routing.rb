# frozen_string_literal: true

require "ipaddr"

module ISIS
  # This system's segment routing over MPLS (RFC 8667), as its originators
  # advertise it: the SRGB and SRLB, the Router ID TLV 242 carries, the
  # Prefix-SID of each configured prefix, and an Adj-SID label for each
  # adjacency. docs/design/sr-mpls.md is the design. Nothing here computes
  # or installs a label; that is the Decision Process's, later.
  #
  # One instance serves both levels, so an adjacency at both levels of a
  # point to point circuit has one Adj-SID label.
  class SegmentRouting
    # The defaults when the configuration names no block.
    SRGB = [[16_000, 8_000]].freeze
    SRLB = [15_000, 1_000].freeze
    # RFC 3032 section 6: "Label values 0-15 inclusive have special
    # meaning". A label is 20 bits.
    FIRST_LABEL = 16
    LAST_LABEL = 0xfffff

    attr_reader :srgb, :srlb, :router_id, :ipv6, :receive_policy

    # The keys of the configuration's segment_routing block.
    KEYS = %i[srgb srlb receive_policy].freeze

    # +srgb+ is a list of [first label, size], in the order advertised;
    # +srlb+ one [first label, size]. +no_adj_sid+ lists circuit names
    # whose adjacencies get no Adj-SID.
    def initialize(router_id:, srgb: SRGB, srlb: SRLB, ipv6: false, no_adj_sid: [], receive_policy: :rfc)
      @srgb = srgb.map { |first, size| [Integer(first), Integer(size)] }
      @srlb = [Integer(srlb[0]), Integer(srlb[1])]
      self.class.check_blocks(@srgb + [@srlb])
      @router_id = IPAddr.new(router_id.to_s)
      raise ArgumentError, "router_id #{router_id} is not an IPv4 address" unless @router_id.ipv4? && @router_id.prefix == 32

      @ipv6 = ipv6
      @no_adj_sid = no_adj_sid.map(&:to_s)
      @adj_labels = {}
      @receive_policy = Validation.policy(receive_policy)
    end

    # The blocks must not overlap and must stay inside 16 to 2^20 - 1.
    # RFC 8667 section 3.1: "The originating router MUST NOT advertise
    # overlapping ranges"; RFC 8660 section 2.3: a range "MUST NOT cover or
    # overlap with a reserved label value". Refusing here keeps a wrong
    # configuration off the wire; a test that wants one builds the TLV.
    def self.check_blocks(blocks)
      blocks.each do |first, size|
        raise ArgumentError, "a label block of size #{size} is empty" unless size.positive?
        raise ArgumentError, "labels #{first} to #{first + size - 1} are not in #{FIRST_LABEL} to #{LAST_LABEL}" \
          unless first >= FIRST_LABEL && first + size - 1 <= LAST_LABEL
      end
      blocks.combination(2).each do |(a, as), (b, bs)|
        raise ArgumentError, "label blocks #{a}-#{a + as - 1} and #{b}-#{b + bs - 1} overlap" if a < b + bs && b < a + as
      end
    end

    # The configuration's segment_routing block, or nil when there is none:
    #
    #   segment_routing:
    #     srgb: [{ start: 16000, size: 8000 }]
    #     srlb: { start: 15000, size: 1000 }
    #     receive_policy: rfc     what a finding on SR data does (Validation):
    #                             rfc (the default), strict or lenient
    #
    # A key not in KEYS is refused.
    #
    # +router_id+ is the configuration's, else the first IPv4 /32 among
    # +prefixes+ (RFC 7981 section 3: the Router ID "SHOULD be identical to
    # an IP Interface Address [RFC1195] advertised by the originating IS").
    def self.from_config(sr, router_id:, prefixes:, ipv6:, no_adj_sid: [])
      return nil if sr.nil?

      sr = {} if sr == true
      unknown = sr.keys.map(&:to_sym) - KEYS
      unless unknown.empty?
        raise ArgumentError, "segment_routing: unknown #{unknown.size == 1 ? 'key' : 'keys'} " \
                             "#{unknown.join(', ')}; the keys are #{KEYS.join(', ')}"
      end
      router_id ||= prefixes.map { |p| p[:prefix].to_s }.find { |p| p.end_with?("/32") && !p.include?(":") }&.split("/")&.first
      raise ArgumentError, "segment_routing needs a router_id, or an IPv4 /32 among the prefixes" unless router_id

      srgb = sr[:srgb] ? Array(sr[:srgb]).map { |b| [b.fetch(:start), b.fetch(:size)] } : SRGB
      srlb = sr[:srlb] ? [sr[:srlb].fetch(:start), sr[:srlb].fetch(:size)] : SRLB
      new(router_id: router_id, srgb: srgb, srlb: srlb, ipv6: ipv6, no_adj_sid: no_adj_sid,
          receive_policy: sr[:receive_policy] || :rfc)
    end

    # TLV 242 for an LSP: S and D clear, since RFC 8667 section 3.1 says the
    # SR-Capabilities "MUST NOT be advertised across level boundaries" and
    # "the S-Flag in the Router Capability TLV [RFC7981] MUST be unset";
    # then SR-Capabilities with I, and V with IPv6; SR-Algorithm 0 (section
    # 3.2: "algorithm 0 MUST be present"); and the SRLB (section 3.3).
    def capability
      Tlv::RouterCapability.new(
        router_id: @router_id.to_s,
        subtlvs: [SubTlv::SrCapabilities.new(flags: @ipv6 ? %w[I V] : %w[I],
                                             descriptors: @srgb.map { |first, size| { range: size, label: first } }),
                  SubTlv::SrAlgorithm.new(0),
                  SubTlv::SrLocalBlock.new(descriptors: [{ range: @srlb[1], label: @srlb[0] }])]
      )
    end

    # The Prefix-SID sub-TLV hash for a configured prefix, or nil:
    #
    #   { prefix: 10.255.0.1/32, metric: 0, sid: 1 }     index 1
    #   ... no_php: true                                  P set
    #   ... explicit_null: true                           P and E set
    #
    # RFC 8667 section 2.1.1.2: a router "MAY set the N-Flag only if" the
    # prefix is local to it and "has a Prefix length of either /32 (IPv4)
    # or /128 (IPv6)". A configured prefix is this system's own, so a host
    # prefix gets N. Section 2.1.1.3: E only with P.
    def self.prefix_sid(p)
      return nil unless p.key?(:sid)

      host = p[:prefix].to_s.end_with?("/32", "/128")
      flags = []
      flags << "N" if host
      flags << "P" if p[:no_php] || p[:explicit_null]
      flags << "E" if p[:explicit_null]
      { prefix_sid: { flags: flags, algorithm: 0, index: Integer(p[:sid]) } }
    end

    # The Prefix-SID of a prefix taken from the other level, section
    # 2.1.2: it "MUST be included when the associated Prefix Reachability
    # TLV is propagated across level boundaries", with "the content (flags
    # and SID)" kept, except R set (2.1.1.2: propagation "Level-1 into
    # Level-2" or "Level-2 into Level-1") and "the router MUST set the
    # P-Flag and MUST clear the E-Flag" (2.1.1.3).
    # +sid+ is a PrefixSid or its hash; a route hands Leak and Summary its
    # hash, which compares by value.
    def self.propagated_sid(sid)
      return nil unless sid

      h = sid.is_a?(Hash) ? sid : sid.to_hash
      return nil if h.key?(:short)

      flags = (Array(h[:flags]) | %w[R P]) - %w[E]
      { prefix_sid: h.merge(flags: SubTlv::PrefixSid::FLAGS & flags) }
    end

    # The Adj-SID sub-TLVs for an adjacency, +key+ naming it (the circuit
    # and the neighbor): one for IPv4, and with IPv6 a second with F. Each
    # label comes from the SRLB and stays with its adjacency for as long as
    # this process runs: P is not set, which section 2.2.1 allows ("When
    # the P-Flag is not set, the Adj-SID MAY be persistent").
    def adj_sids(circuit, key)
      return [] if @no_adj_sid.include?(circuit.to_s)

      list = [{ adj_sid: { flags: %w[V L], label: adj_label([circuit, key, :ipv4]) } }]
      list << { adj_sid: { flags: %w[F V L], label: adj_label([circuit, key, :ipv6]) } } if @ipv6
      list
    end

    # The LAN-Adj-SID sub-TLVs for a LAN circuit's neighbors, System IDs
    # as octets (section 2.2.2).
    def lan_adj_sids(circuit, neighbors)
      return [] if @no_adj_sid.include?(circuit.to_s)

      neighbors.flat_map do |n|
        id = SystemId.from_bytes(n).to_s
        list = [{ lan_adj_sid: { neighbor: id, flags: %w[V L], label: adj_label([circuit, n, :ipv4]) } }]
        list << { lan_adj_sid: { neighbor: id, flags: %w[F V L], label: adj_label([circuit, n, :ipv6]) } } if @ipv6
        list
      end
    end

    # The highest label in the SRGB and SRLB, which the host's label table
    # must reach.
    def highest_label
      (@srgb + [@srlb]).map { |first, size| first + size - 1 }.max
    end

    # The adjacency labels given out, key => label.
    def adj_labels = @adj_labels.dup

    private

    # The lowest SRLB label not given out, the same one for a key every
    # time. Raises when the SRLB is used up.
    def adj_label(key)
      @adj_labels[key] ||= begin
        used = @adj_labels.values
        free = (@srlb[0]...(@srlb[0] + @srlb[1])).find { |l| !used.include?(l) }
        raise Error, "the SRLB #{@srlb[0]}-#{@srlb[0] + @srlb[1] - 1} is used up" unless free

        free
      end
    end
  end
end
