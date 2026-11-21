# frozen_string_literal: true

# The to_hash catalog CLAUDE.md asks for ("to_hash, and the one thing to
# do differently from bgp4r", "The one hash contract"): one entry per
# class that includes ISIS::Node, saying whether its hash rebuilds it.
#
# Not a test. to_hash_catalog_test.rb measures every declaration here
# against the library on every run. **Every verdict is declared, not
# computed**: a verdict read off the library would agree with whatever the
# library did, and assert nothing (bgp4r's catalog says the same).
#
# A recipe is wire octets, so every field it sets arrives by parsing, the
# way a field that only the wire can carry does. **A recipe exercises
# every field its class carries**: flags and reserved bits, the label
# and the index forms, a tail. A thin recipe passes for the wrong reason.
#
# Started with the classes TI-LFA reads and writes (routescope
# docs/design/ti-lfa.md, step 0c). UNMEASURED holds the rest until each is
# measured; a class moves out of it into ROUND_TRIPS, or into GAPS with
# what its hash loses and what was decided. A new class goes in one of
# the three, or the suite fails. The rule is one way: a gap may stay a
# gap, a round trip must not stop working.
module ToHashCatalog
  # Class name => recipes, each a hex string of wire octets. Each one
  # parses, writes back the same octets, and its hash rebuilds an object
  # with the same octets and the same hash.
  ROUND_TRIPS = {
    # Index form with R, N, P, E and two reserved bits, algorithm 1, an
    # index past 16 bits, and a tail; then the label form with V and L
    # and the four bits above the label.
    "ISIS::SubTlv::PrefixSid" => %w[0307f30100011170ab 03050c00103e81],
    # Label form with every flag and a weight; then the index form.
    "ISIS::SubTlv::AdjSid" => %w[1f05fc07003a99 1f06400000000009],
    "ISIS::SubTlv::LanAdjSid" => %w[200b3001000000000002003a9a],
    # A label, then an index.
    "ISIS::SubTlv::SidLabel" => %w[0103003e80 010400000005],
    # I and V with a reserved bit, two descriptors, a tail.
    "ISIS::SubTlv::SrCapabilities" => %w[0212c1001f400103003e800000640103007530cd],
    "ISIS::SubTlv::SrLocalBlock" => %w[1609000003e80103003a98],
    "ISIS::SubTlv::SrAlgorithm" => %w[13020001],
    # S and D with a reserved bit, and the three SR sub-TLVs above.
    "ISIS::Tlv::RouterCapability" =>
      %w[f2280aff0001030212c1001f400103003e800000640103007530cd130200011609000003e80103003a98],
    # The up/down bit and a Prefix-SID on one entry, a plain second entry.
    "ISIS::Tlv::ExtendedIpReachability" => %w[871a00000000e00aff00010803064000000000010000000a180a0900],
    # Exp 5 and TTL 64 on the top entry, S and TTL 1 on the bottom.
    "ISIS::Mpls::LabelStack" => %w[03e85a4000003101]
  }.freeze

  # Class name => { loses:, recipe:, decision: }. None measured yet.
  GAPS = {}.freeze

  # Not measured yet.
  UNMEASURED = %w[
    ISIS::Capture
    ISIS::Pdu ISIS::Pdu::Csnp ISIS::Pdu::LanHello ISIS::Pdu::Layout ISIS::Pdu::Lsp ISIS::Pdu::Malformed
    ISIS::Pdu::P2pHello ISIS::Pdu::Psnp ISIS::Pdu::Truncated ISIS::Pdu::Unknown
    ISIS::SubTlv ISIS::SubTlv::Ipv4Address ISIS::SubTlv::Ipv4InterfaceAddress ISIS::SubTlv::Ipv4NeighborAddress
    ISIS::SubTlv::LabelBlock ISIS::SubTlv::List ISIS::SubTlv::Unknown
    ISIS::Tlv ISIS::Tlv::ExtendedIsReachability ISIS::Tlv::AreaAddresses ISIS::Tlv::Authentication
    ISIS::Tlv::BfdEnabled ISIS::Tlv::DynamicHostname ISIS::Tlv::IpInternalReachability
    ISIS::Tlv::IpExternalReachability ISIS::Tlv::IpInterfaceAddresses ISIS::Tlv::Ipv6InterfaceAddresses
    ISIS::Tlv::Ipv6Reachability ISIS::Tlv::IsReachability ISIS::Tlv::IsNeighbors ISIS::Tlv::List
    ISIS::Tlv::LspEntries ISIS::Tlv::Padding ISIS::Tlv::ProtocolsSupported ISIS::Tlv::ThreeWayAdjacency
    ISIS::Tlv::Unknown
  ].freeze
end
