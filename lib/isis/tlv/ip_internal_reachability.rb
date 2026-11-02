# frozen_string_literal: true

require "ipaddr"

module ISIS
  class Tlv
    # TLV 128, IP Internal Reachability Information. RFC 1195 section 5.3.4:
    # "CODE - 128", a length that is a multiple of 12, and per entry
    #
    #   Default Metric    1 octet  \  NarrowMetrics. Only the default has
    #   Delay Metric      1 octet   | I/E, "the metric type ... for all four
    #   Expense Metric    1 octet   | TOS metrics"; bit 7 of the other three
    #   Error Metric      1 octet  /  is reserved.
    #   IP Address        "a 4-octet Internet address"
    #   Subnet Mask       "a 4 octet IP subnet mask"
    #
    # The address and mask are kept as they arrived. When the mask is
    # contiguous and the address has no bits outside it, the entry prints
    # and hashes as a prefix; otherwise as its address and mask, so any
    # entry replays. Octets that do not make a whole entry are kept as a
    # tail.
    class IpInternalReachability < Tlv
      TYPE = 128
      ENTRY = 12
      # Section 5.3.4: I/E only in the default metric octet.
      IE_OCTETS = [0].freeze

      class Entry
        attr_accessor :metrics, :address, :mask

        def initialize(metrics:, address:, mask:)
          @metrics = metrics
          @address = address.b
          @mask = mask.b
        end

        # The prefix length the mask is, or nil when its ones are not
        # contiguous from the left.
        def length
          bits = @mask.unpack1("B*")
          bits.match?(/\A1*0*\z/) ? bits.count("1") : nil
        end

        # "10.0.12.0/24", or nil when the mask is not contiguous or the
        # address has bits past it.
        def prefix
          n = length
          return nil if n.nil? || canonical_address(n) != @address

          "#{IPAddr.new_ntoh(@address)}/#{n}"
        end

        # The up/down bit, bit 8 of the default metric octet. RFC 5302
        # section 2: "L1L2 routers MUST set this bit to one for prefixes
        # that are derived from L2 routing and are advertised into L1
        # LSPs." RFC 1195 has it reserved, so it is read here and kept, and
        # building from field values leaves it clear.
        def up_down?
          @metrics.octets.getbyte(0) & NarrowMetrics::S != 0
        end

        def encode
          @metrics.octets + @address + @mask
        end

        def to_hash
          h = prefix ? { prefix: prefix } : { address: IPAddr.new_ntoh(@address).to_s, mask: IPAddr.new_ntoh(@mask).to_s }
          h.merge!(@metrics.fields)
          h[:metric_octets] = @metrics.octets.unpack1("H*") unless @metrics.canonical?(IE_OCTETS)
          h
        end

        def to_s
          where = prefix || "#{IPAddr.new_ntoh(@address)} mask #{IPAddr.new_ntoh(@mask)}"
          "#{where} #{@metrics}"
        end

        private

        def canonical_address(n)
          IPAddr.new_ntoh(@address).mask(n).hton
        end
      end

      attr_accessor :entries, :tail

      def to_hash
        list = @entries.map(&:to_hash)
        return list if @tail.empty? && !unusual_type

        h = { entries: list }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        note = @tail.empty? ? "" : ", tail of #{@tail.bytesize} octets"
        "IP Internal Reachability #{@entries.join('; ')}#{note}"
      end

      private

      def encode_value
        out = ISIS.buffer
        @entries.each { |e| out << e.encode }
        out << @tail
      end

      def parse(octets)
        value = read_frame(octets)
        whole = value.bytesize / ENTRY * ENTRY
        @entries = (0...whole).step(ENTRY).map do |i|
          Entry.new(metrics: NarrowMetrics.new(value.byteslice(i, 4)), address: value.byteslice(i + 4, 4),
                    mask: value.byteslice(i + 8, 4))
        end
        @tail = value.byteslice(whole..).b
      end

      # IpInternalReachability.new({ prefix: "10.0.12.0/24", metric: 10 }, ...),
      # or one array of them.
      def from_fields(*entries)
        entries = entries.first if entries.size == 1 && entries.first.is_a?(Array)
        @entries = entries.map { |e| entry(e) }
        @tail = "".b
      end

      def from_hash(hash)
        return from_fields(hash) unless hash.key?(:entries)

        from_fields(hash.fetch(:entries))
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end

      def entry(e)
        return e if e.is_a?(Entry)

        metrics =
          if e.key?(:metric_octets)
            NarrowMetrics.new([e.fetch(:metric_octets)].pack("H*"))
          else
            NarrowMetrics.build(**e.slice(:metric, :delay, :expense, :error, :external), ie_octets: IE_OCTETS)
          end
        address, mask =
          if e.key?(:prefix)
            a = IPAddr.new(e.fetch(:prefix).to_s)
            raise ArgumentError, "not an IPv4 prefix: #{e[:prefix].inspect}" unless a.ipv4?

            [a.hton, IPAddr.new("255.255.255.255").mask(a.prefix).hton]
          else
            [IPAddr.new(e.fetch(:address)).hton, IPAddr.new(e.fetch(:mask)).hton]
          end
        Entry.new(metrics: metrics, address: address, mask: mask)
      end
    end

    register(IpInternalReachability::TYPE, :ip_internal_reachability, IpInternalReachability)
  end
end
