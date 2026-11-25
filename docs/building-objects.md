# Building objects

Every node of a PDU tree, a PDU, a TLV list, a TLV or a sub-TLV, is built
the same four ways, and one constructor tells them apart. The order is the
same in every class, so a reader who learns one constructor has learned
all of them. The shared code is `ISIS::Node` in `lib/isis/common.rb`.

## The dispatch order

`new` looks at what it was handed, in this order:

1. **Wire octets**, an `ISIS::Octets`. The object parses them, consuming
   exactly its own octets and leaving the rest in the String it was given.
2. **Another instance of the same class.** The object parses that
   instance's `encode`. A copy constructor that also tests the encoder.
3. **A Hash**, as `to_hash` answered. The object rebuilds from it.
4. **Anything else** is field values, positional or keyword.

The first three apply only when `new` gets exactly one argument. Wire
octets may also come with keywords, and those are **parse-time inputs**:
facts the octets do not carry themselves. Today there is one, `id_width`,
the System ID width the PDU's ID Length gave, and only a class that needs
it accepts it. The other two take no keywords. Everything else is field
values.

```ruby
ISIS::Tlv::ThreeWayAdjacency.new(octets, id_width: 8)  # parses, 8 octet IDs
```

A copy made from another instance reads that instance's encoding back
with the inputs it was read with, so a copy of a TLV parsed with eight
octet IDs still reads eight.

## Why wire octets are marked

A binary String and a field value String are the same class in Ruby, so
the constructor cannot tell them apart by looking at them. Guessing from
the content works until a field value happens to look like octets, and
then it fails far from the cause. So wire octets carry a mark: they are an
`ISIS::Octets`, a String subclass. A plain String is always a field value.

bgp4r marks by adding `is_packed` to every String. A gem should not change
String for everyone who loads it, and a frozen string literal cannot carry
that mark, so isis4r uses the subclass.

```ruby
ISIS::Tlv::Unknown.new(ISIS::Octets.from_hex("c703616263"))  # parses
ISIS::Tlv::Unknown.new(199, "abc")                           # field values
```

## Classes that follow this contract

Every class that includes `ISIS::Node` is listed here. The suite discovers
them and fails if one is missing.

- `ISIS::Capture`
- `ISIS::Mpls::LabelStack`
- `ISIS::Pdu`
- `ISIS::Pdu::Csnp`
- `ISIS::Pdu::LanHello`
- `ISIS::Pdu::Layout`
- `ISIS::Pdu::Lsp`
- `ISIS::Pdu::Malformed`
- `ISIS::Pdu::P2pHello`
- `ISIS::Pdu::Psnp`
- `ISIS::Pdu::Truncated`
- `ISIS::Pdu::Unknown`
- `ISIS::SubTlv`
- `ISIS::SubTlv::AdjSid`
- `ISIS::SubTlv::AdminGroup`
- `ISIS::SubTlv::Asla`
- `ISIS::SubTlv::ExtendedAdminGroup`
- `ISIS::SubTlv::Fad`
- `ISIS::SubTlv::FadExcludeAdminGroup`
- `ISIS::SubTlv::FadExcludeSrlg`
- `ISIS::SubTlv::FadFlags`
- `ISIS::SubTlv::FadIncludeAllAdminGroup`
- `ISIS::SubTlv::FadIncludeAnyAdminGroup`
- `ISIS::SubTlv::Fapm`
- `ISIS::SubTlv::Ipv4Address`
- `ISIS::SubTlv::Ipv4InterfaceAddress`
- `ISIS::SubTlv::Ipv4NeighborAddress`
- `ISIS::SubTlv::Ipv6Address`
- `ISIS::SubTlv::Ipv6InterfaceAddress`
- `ISIS::SubTlv::Ipv6NeighborAddress`
- `ISIS::SubTlv::LabelBlock`
- `ISIS::SubTlv::LanAdjSid`
- `ISIS::SubTlv::LinkDelay`
- `ISIS::SubTlv::LinkIdentifiers`
- `ISIS::SubTlv::List`
- `ISIS::SubTlv::MinMaxLinkDelay`
- `ISIS::SubTlv::PrefixSid`
- `ISIS::SubTlv::SidLabel`
- `ISIS::SubTlv::SrAlgorithm`
- `ISIS::SubTlv::SrCapabilities`
- `ISIS::SubTlv::SrLocalBlock`
- `ISIS::SubTlv::TeDefaultMetric`
- `ISIS::SubTlv::Unknown`
- `ISIS::Tlv`
- `ISIS::Tlv::ExtendedIpReachability`
- `ISIS::Tlv::ExtendedIsReachability`
- `ISIS::Tlv::AreaAddresses`
- `ISIS::Tlv::Authentication`
- `ISIS::Tlv::BfdEnabled`
- `ISIS::Tlv::DynamicHostname`
- `ISIS::Tlv::IpInternalReachability`
- `ISIS::Tlv::IpExternalReachability`
- `ISIS::Tlv::IpInterfaceAddresses`
- `ISIS::Tlv::Ipv6InterfaceAddresses`
- `ISIS::Tlv::Ipv6Reachability`
- `ISIS::Tlv::IsReachability`
- `ISIS::Tlv::IsNeighbors`
- `ISIS::Tlv::List`
- `ISIS::Tlv::LspEntries`
- `ISIS::Tlv::Padding`
- `ISIS::Tlv::ProtocolsSupported`
- `ISIS::Tlv::RouterCapability`
- `ISIS::Tlv::Srlg`
- `ISIS::Tlv::AslaSrlg`
- `ISIS::Tlv::ThreeWayAdjacency`
- `ISIS::Tlv::Unknown`

## The to_hash catalog

`test/unit/to_hash_catalog.rb` says, class by class, whether a class's
`to_hash` rebuilds it, as CLAUDE.md's "The one hash contract" asks. A
class is in one of three lists: round trips, with wire recipes that set
every field it carries; gaps, with what its hash loses and the decision;
or not measured yet. `test/unit/to_hash_catalog_test.rb` measures each
declaration on every run, and fails when a class that includes
`ISIS::Node` is in none of them, or in two. The counts are the file's,
not written here.

## One class under two parents

A sub-TLV class may be registered under more than one parent. The ASLA
sub-TLV (RFC 9479 section 4.2) carries the link attributes "in the same
formats as the legacy sub-TLVs", under the same numbers (section 7.3).
So `SubTlv::AdminGroup`, `ExtendedAdminGroup`, `TeDefaultMetric`,
`LinkDelay` and `MinMaxLinkDelay` are registered twice: under TLV 22,
and under `SubTlv::Asla::REGISTRY`, the ASLA's own registry. TLV 238's
link identifiers are registered a third way, under 238. The class is the
same each time, with the same hash key; the parent decides which
registry a list is read from:

```ruby
asla = ISIS::SubTlv::Asla.new(applications: %w[X],
                              subtlvs: [{ te_default_metric: { metric: 100 } }])
asla.to_shex                                     # => "10080100101203000064"
asla.attribute(ISIS::SubTlv::TeDefaultMetric).metric   # => 100
```

The FAD sub-TLV (RFC 9350 section 6) has its own registry too,
`SubTlv::Fad::REGISTRY`, for its rules and flags. Its three admin group
rules are subclasses of `ExtendedAdminGroup`, each with its own type, so
they number groups the same way. The FAPM, sub-TLV 6, is registered
under TLVs 135 and 236, beside the Prefix-SID.

```ruby
fad = ISIS::SubTlv::Fad.new(algorithm: 128, metric_type: "delay", priority: 200,
                            subtlvs: [{ fad_exclude_admin_group: { groups: [1] } }])
fad.to_shex                                      # => "1a0a800100c8010400000002"
```
