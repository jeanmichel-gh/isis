# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 130, IP External Reachability Information. RFC 1195 section 5.3.5:
    # "CODE - 130", a length that is a multiple of 12, and entries laid out
    # as TLV 128's are: the four original metric octets, only the default
    # with I/E, then "a 4-octet Internet address" and "a 4 octet IP subnet
    # mask". So it is TLV 128's class with its own type and name.
    #
    # Section 5.3.5 has it "present in level 2 LSPs"; RFC 5302 section 2.2
    # relaxes that and allows it in Level 1 LSPs too. Each entry's I/E bit
    # says whether its metric is of the internal or the external type
    # (RFC 5302 section 3: "The metric-type is derived from the
    # internal/external metric-type bit in the Metric field (bit 7)").
    class IpExternalReachability < IpInternalReachability
      TYPE = 130

      def to_s
        super.sub("IP Internal Reachability", "IP External Reachability")
      end
    end

    register(IpExternalReachability::TYPE, :ip_external_reachability, IpExternalReachability)
  end
end
