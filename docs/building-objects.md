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
- `ISIS::SubTlv::List`
- `ISIS::SubTlv::Unknown`
- `ISIS::Tlv`
- `ISIS::Tlv::ExtendedIpReachability`
- `ISIS::Tlv::ExtendedIsReachability`
- `ISIS::Tlv::AreaAddresses`
- `ISIS::Tlv::IpInterfaceAddresses`
- `ISIS::Tlv::IsNeighbors`
- `ISIS::Tlv::List`
- `ISIS::Tlv::LspEntries`
- `ISIS::Tlv::Padding`
- `ISIS::Tlv::ProtocolsSupported`
- `ISIS::Tlv::ThreeWayAdjacency`
- `ISIS::Tlv::Unknown`
