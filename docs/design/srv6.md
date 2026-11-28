# SRv6 in isis4rd

Status: approved by the owner, 2026-11-25 ("approve the SRv6 spec,
isis #135"), with the answers in "Decisions", at the end. The owner gave
no separate answers, so each question takes this spec's recommended
answer, the default taken at approval. Step 1, the codec, is built (#152,
2026-11-28): the classes of "Wire format", the behaviour registry, FRR
10.7.1's two LSPs as fixtures, and the `SRV6` group's wire builders,
whose findings wait for step 3. Steps 2 to 9 are not started.

This is P6's IS-IS half in routescope's `docs/protocol-coverage.md`:
"IS-IS SRv6 locators and SIDs, BGP services over SRv6. The VM's kernel
has `seg6`." The order of the work there is P5, P9, P6, P7, P8. P9,
flex-algo, comes first, because SRv6 deployments lean on it; its spec
is `docs/design/flex-algo.md`, approved by the owner and merged on
2026-11-25 (#134). The BGP half, RFC 9252 in bgp4rd, is the
next spec, in bgp4r. It is not written here.

The RFCs are in `specs/rfc/`, a local folder that is not committed:
9352, 8986, 9800, 9855, 9350, 8491, 7794 and 7981 were read for it, and
every section cited below was read there. 9252, 8402 and 8754 are
fetched there too; no section of them is cited. What the kernel
and FRR do was measured on ospflab on 2026-11-25, and the commands and
their output are in "Measured in the kernel" and "Measured on FRR
10.7.1".

## The problem

isisd has SR-MPLS (RFC 8667, algorithm 0, label routes by netlink in
Ruby, `docs/design/sr-mpls.md`) and TI-LFA over it (RFC 9855, link and
node, `docs/ti-lfa.md`). It has IPv6 (RFC 5308): TLVs 232 and 236, IPv6
routes through the neighbour's link-local address. It has nothing for
SRv6. A search of `lib/` and `exe/` for `srv6`, `seg6`, `locator` and
`End.X` finds nothing (2026-11-25).

We want isisd to run SRv6 as RFC 9352 defines it for IS-IS:

- advertise its locators, its End SIDs and an End.X SID per adjacency;
- learn the other routers' locators and SIDs;
- install routes to their locators, and its own SIDs as `seg6local`
  routes, so a packet with a segment list crosses isisd and FRR;
- protect those routes with TI-LFA, the repair a segment list;
- interoperate with FRR, which does the same.

Phase 4's bar (CLAUDE.md, "Phase 4") applies: correct encoding, correct
state and calculation, correct forwarding, and interoperation with an
independent router. "Advertising an SRv6 locator alone is not SRv6
support."

## The terms, in short

From RFC 8986 and 9352. A reminder, not a definition.

- **SID**: a 128-bit IPv6 address that names an instruction. It is
  LOC:FUNCT:ARG, a locator, a function and an argument (8986 3.1).
- **Locator**: a prefix that covers all of one node's SIDs for one
  topology and algorithm (9352 section 5). Other routers route to the
  locator; they never install the SIDs (section 5: "MUST NOT be
  installed in the forwarding plane").
- **Behaviour**: what a SID does, named by a codepoint from the "SRv6
  Endpoint Behaviors" registry (8986 10.2). End is 1, End.X 5,
  End.DT6 18, End.DT46 20.
- **End SID**: a SID that needs no particular neighbour, carried in the
  Locator TLV. **End.X SID**: a SID for one adjacency, carried in TLV
  22, "L3 cross-connect" (8986 4.2).
- **H.Encaps**: the headend puts the packet in an outer IPv6 header
  with a Segment Routing Header (8986 5.1). H.Encaps.Red leaves the
  first SID out of the SRH (5.2).
- **Flavors**: PSP, USP and USD change what End, End.X and End.T do at
  the end of the list (8986 4.16). NEXT-CSID is RFC 9800's flavor for
  compressed SIDs, called uSID by vendors.

## What the RFCs ask

### RFC 9352, IS-IS for SRv6

- **Section 2, the SRv6 Capabilities sub-TLV**: type 25 under TLV 242,
  two octets of flags, O at bit 1, then optional sub-sub-TLVs, none
  defined. A node advertises it to say it is an SR Segment Endpoint
  Node.
- **Section 3**: algorithms are advertised in the SR-Algorithm sub-TLV
  of RFC 8667, the one isisd already sends.
- **Section 4, MSDs**: four types in RFC 8491's Node MSD sub-TLV (23
  under TLV 242) and Link MSD sub-TLV (15 under TLV 22): Max Segments
  Left 41, Max End Pop 42, Max H.Encaps 44, Max End D 45. For 41: "If
  no value is advertised, the supported value is 0."
- **Section 5, reachability**: locators "MUST be advertised in the
  SRv6 Locator TLV". Their forwarding entries "MUST be installed" by
  receiving SRv6-capable routers when they support the topology and
  algorithm, by the process of TLV 236. Locators of algorithms 0 and 1
  "SHOULD also be advertised in a Prefix Reachability TLV (236 or
  237)" for routers without SRv6. When the same prefix comes in both,
  "the Prefix Reachability advertisement MUST be preferred when
  installing entries". Flex-algo locators "SHOULD NOT be advertised in
  Prefix Reachability TLVs".
- **Section 6, anycast**: an A flag, bit 4 of RFC 7794's Prefix
  Attribute Flags sub-TLV (type 4). A and N both set: "the receiving
  routers MUST ignore the N-flag". The X flag in that sub-TLV is valid
  in the Locator TLV and "MUST match" the X bit of the same prefix in
  TLV 236; on a difference, the Prefix Reachability TLV's flags "MUST
  be preferred".
- **Section 7.1, the SRv6 Locator TLV**, type 27: R bits and a 12-bit
  MTID, then entries of a 4-octet metric, a flags octet (D, the
  up/down bit), an algorithm, Loc-Size in bits, the locator in the
  fewest octets, and sub-TLVs with a length octet. Loc-Size outside 1
  to 128: "The entire TLV MUST be ignored". The Prefix Attribute Flags
  sub-TLV "SHOULD be included", and "MUST be included" when the
  locator is leaked upwards or redistributed. Its sub-TLVs share the
  registry of TLVs 135, 235, 236 and 237 (section 11.1.2).
- **Section 7.2, the End SID sub-TLV**, type 5 under 27: flags, a
  2-octet behaviour, the 16-octet SID, sub-sub-TLVs. "Unsupported or
  unrecognized behavior values are ignored". The SID "MUST be
  allocated from its associated locator", and one that is not "MUST be
  ignored". The same MTID and locator in several TLVs with different
  algorithms: "all TLVs for that MTID/Locator MUST be ignored".
- **Section 8, End.X SIDs**: sub-TLVs 43 (point-to-point) and 44 (LAN)
  of TLV 22. A SID that is not "a subnet of a Locator with matching
  topology and algorithm that are advertised by the same node" "MUST
  be ignored". The algorithm is in each SID, not inherited.
- **Section 8.1, End.X**: flags (B, S, P), algorithm, weight, behaviour,
  SID, sub-sub-TLVs. **Section 8.2, LAN End.X**: the same after the
  neighbour's System ID.
- **Section 9, the SID Structure sub-sub-TLV**, type 1 under 5, 43 and
  44: four octets, the block, node, function and argument lengths in
  bits. Twice in one parent, or a sum over 128: "the parent sub-TLV
  MUST be ignored by the receiver". It "MUST NOT be used at a transit
  node ... for forwarding packets".
- **Section 10, Table 1**: which behaviours go where. End and its
  flavors (1 to 4, 28 to 31) and End.DT6, End.DT4, End.DT46 (18 to 20)
  in the End SID; End.X and its flavors (5 to 8, 32 to 35), End.DX6
  and End.DX4 (16, 17) in End.X and LAN End.X. A behaviour "MUST NOT
  be advertised" where the table says N. The receiver's action is not
  stated; see "Validation" below.

### RFC 8986, the behaviours isisd instantiates

isisd instantiates three behaviours and no flavor in the first
version:

- **End** (4.1): the node's End SID. It is what a repair list names to
  reach a node.
- **End.X** (4.2): one per adjacency. It is what a repair list names to
  cross a given link.
- **End.DT6** (4.6), bound to the main table: a decapsulating SID, one
  per node, for TI-LFA. See "TI-LFA over SRv6" for why a repair list
  must end in one.

8986 3.2 says the behaviour cannot be inferred from the function bits,
so each SID goes out with its codepoint. The service SIDs, End.DT4,
End.DT46 in a VRF and End.DX*, belong to the BGP half.

### RFC 9800, compressed SIDs

RFC 9800 adds the NEXT-CSID and REPLACE-CSID flavors. Its section 8
says CSID behaviours are advertised "in the same manner as their base
SRv6 endpoint behaviors", with the argument bits set to 0, and that
"Signaling the SRv6 SID Structure is REQUIRED for all the SIDs
introduced in this document". Its codepoints are 43 to 50 for End with
NEXT-CSID and 52 to 59 for End.X with NEXT-CSID (12.1). Section 4.1:
"Each CSID container for NEXT-CSID is independent", so one container
holding one CSID is a valid segment on its own.

**Decision: uSID is not in the first version. It comes after the labs,
in this spec's last step.** The mechanism:

- **Reading costs nothing.** The codec reads every behaviour codepoint
  into the same field, and the registry names RFC 9800's. A locator
  routes the same whatever its SIDs' flavor. So a uSID FRR is read, and
  routed to, from the first version. FRR 10.7.1 sends behaviour 43 and
  52 when its locator is uSID (measured below).
- **Naming a uSID SID in an uncompressed list works**, by section 4.1's
  independence: the container carries one CSID and the argument is
  zero. So TI-LFA repairs through a uSID FRR need no compression.
- **Instantiating and compressing is the cost.** isisd would instantiate
  uN and uA with `flavors next-csid`, which the kernel takes for End
  and End.X (measured). And a PLR that compresses its repair lists
  needs RFC 9800 section 6.2's algorithm on top of TI-LFA. That is a
  second change to TI-LFA's list building, after the first.
- **The kernel has limits we would meet at once.** Measured on 7.0:
  End.X takes `next-csid` but not `next-csid,psp`, and no behaviour
  takes `usd`. A uSID design has to work around them, and the first
  version is simpler without them.

The owner took this as the default at approval ("Decisions", 1).

### RFC 9855 section 7.2, TI-LFA over SRv6

"The TI-LFA path computation algorithm is the same as in the SR-MPLS
data plane." Adjacency SIDs "are typically globally routed", so there
is "no need for preceding an Adjacency SID with a Prefix-SID", and the
repair list is "likely shorter". At a transit node "an SRv6 SID list is
added on the packet", following "the head-end behaviors as specified in
Section 5 of [RFC8986]", that is H.Encaps or H.Encaps.Red.

### RFC 9350 section 14.2, flex-algo locators

"When the algorithm value advertised with a locator represents a
Flex-Algorithm, the paths to the locator prefix MUST be calculated
using the specified Flex-Algorithm". Locators of algorithms "in which
the node is not participating MUST NOT be installed". LFA paths "MUST
only use SRv6 SIDs advertised specifically for the given
Flex-Algorithm". Participation for SRv6 is the SR-Algorithm sub-TLV,
shared with SR-MPLS (11.1). Section 8: a FAPM sub-TLV in the Locator
TLV "MUST be ignored"; the locator's own metric is used instead.
Section 13.1: the M flag "is not applicable to prefixes advertised as
SRv6 locators".

## What exists

Measured from the code at master `5e9ee45`, 2026-11-25.

- **IPv6.** `ipv6: true` sends TLV 232 and TLV 236 (`router.rb`).
  `Spf::Calculation` reads TLV 236 into the same tree as TLV 135, and
  an IPv6 route goes through the neighbour's link-local address from
  its hellos (`spf/spf.rb`). TLV 236's X bit is not used in the
  calculation (its comment: "Not here yet: ... TLV 236's X bit"). One
  topology, no multi-topology: TLVs 222 and 237 have no class.
- **Router Capability.** TLV 242 with SR-Capabilities, SR-Algorithm
  `[0]` and the SRLB (`subtlv/router_capability.rb`). The Router ID is
  IPv4, the first IPv4 /32 among the prefixes when not given. Nothing
  for RFC 8491's MSDs or RFC 7794's Prefix Attribute Flags.
- **TLV 22's sub-TLVs**: 6, 8, 31 and 32. FRR's sub-TLV 13, the IPv6
  neighbour address, is kept as `Unknown`.
- **Adj-SIDs** are allocated per adjacency while it is up
  (`database/segment_routing.rb`), which End.X SIDs can follow.
- **Forwarding.** `Forwarding::Netlink` packs `RTM_NEWROUTE` in Ruby,
  with `RTA_ENCAP_TYPE` and `RTA_ENCAP` for MPLS encap, protocol 187.
  TI-LFA's IP backups go in at the route's priority plus 100, and
  `ignore_routes_with_linkdown` lets the kernel take them on carrier
  loss (`docs/ti-lfa.md`, "In the kernel").
- **TI-LFA.** `Spf::TiLfa` gives a repair as segments, `[:node, X]` and
  `[:adj, X, Y]`, independent of the data plane. `Spf::Backups` turns
  them into labels (RFC 9855 7.1).
- **The simulator.** Its topology accepts IPv6 prefixes and an IPv6
  loopback (`test/unit/sim/topology_test.rb`; `sim/simulator.rb` sends
  them in TLV 236). Its systems' SR data is SR-MPLS only. A system with
  a `sid` needs an IPv4 loopback.
- **Validation and the catalog.** `validation.rb` holds the SR-MPLS
  rules; `fault.rb` the SR entries, TI-LFA's topologies, packets and
  behaviours; isis4r-sim's HTTP API serves `/api/fault`, `/api/plan`,
  `/api/behave` (`daemon/http.rb`).

## Measured in the kernel

ospflab, Linux 7.0.0-43-generic, iproute2 6.19.0, 2026-11-25. In
network namespaces `srv6spec-a`, `-b` and `-c`, deleted after; no
running lab was touched. `CONFIG_IPV6_SEG6_LWTUNNEL=y`,
`CONFIG_IPV6_SEG6_HMAC=y`, `CONFIG_IPV6_SEG6_BPF=y`, `CONFIG_NET_VRF=m`.

**What iproute2 offers** (`ip -6 route help`):

```
SEG6HDR := [ mode SEGMODE ] segs ADDR1,ADDRi,ADDRn [hmac HMACKEYID] [cleanup]
SEGMODE := [ encap | encap.red | inline | l2encap | l2encap.red ]
SEG6LOCAL := action ACTION [ OPTIONS ] [ count ]
ACTION := { End | End.X | End.T | End.DX2 | End.DX6 | End.DX4 |
            End.DT6 | End.DT4 | End.DT46 | End.B6 | End.B6.Encaps |
            End.BM | End.S | End.AS | End.AM | End.BPF }
OPTION := { flavors FLAVORS | srh SEG6HDR | nh4 ADDR | nh6 ADDR | iif DEV | oif DEV |
            table TABLEID | vrftable TABLEID | endpoint PROGNAME }
FLAVOR := { psp | usp | usd | next-csid }
```

**The netlink numbers** (`/usr/include/linux`, linux-libc-dev
7.0.0-43.43): `LWTUNNEL_ENCAP_SEG6` 5 and `LWTUNNEL_ENCAP_SEG6_LOCAL`
7; `SEG6_LOCAL_ACTION` 1, `NH6` 5, `OIF` 7, `TABLE` 3, `VRFTABLE` 9,
`COUNTERS` 10, `FLAVORS` 11; the actions End 1, End.X 2, End.T 3,
End.DX6 5, End.DX4 6, End.DT6 7, End.DT4 8, End.DT46 16; the encap
modes inline 0, encap 1, encap.red 3. **The kernel's action numbers are
not the IANA codepoints**: End.X is 2 in the kernel and 5 in RFC 8986's
registry, End.DT6 7 and 18. The forwarding adapter keeps its own table.

**Every route below was taken, with `proto 187`**, and shows as
`proto isis`:

```
fc00:0:b::1  encap seg6local action End dev lo metric 1024 pref medium
fc00:0:b::2  encap seg6local action End flavors psp dev lo metric 1024 pref medium
fc00:0:b::41  encap seg6local action End.X nh6 fc00:bc::2 dev bc-b metric 1024 pref medium
fc00:0:b::42  encap seg6local action End.X nh6 fe80::64bf:30ff:fe11:f7d6 oif bc-b dev bc-b metric 1024 pref medium
fc00:0:b::44  encap seg6local action End.T table main dev lo metric 1024 pref medium
fc00:0:b:e000::/64  encap seg6local action End flavors next-csid lblen 32 nflen 16 dev lo metric 1024 pref medium
fc00:0:b:e001::/64  encap seg6local action End.X nh6 fc00:bc::2 flavors next-csid lblen 32 nflen 16 dev bc-b metric 1024 pref medium
fc00:0:c::100  encap seg6local action End.DT46 vrftable 100 dev vrf100 metric 1024 pref medium
fc00:0:c::101  encap seg6local action End.DT6 vrftable 100 dev vrf100 metric 1024 pref medium
fc00:0:c::102  encap seg6local action End.DT4 vrftable 100 dev vrf100 metric 1024 pref medium
fc00:0:c::103  encap seg6local action End.DT6 table main dev lo metric 1024 pref medium
fc00:0:c::104  encap seg6local action End.DX6 nh6 2001:db8:99::2 dev cust metric 1024 pref medium
fc00:0:c::105  encap seg6local action End.DX4 nh4 10.99.0.2 dev cust metric 1024 pref medium
2001:db8:99::/64  encap seg6 mode encap segs 2 [ fc00:0:b::1 fc00:0:c::100 ] dev ab-a metric 1024 pref medium
2001:db8:98::/64  encap seg6 mode encap.red segs 2 [ fc00:0:b::41 fc00:0:c::101 ] dev ab-a metric 1024 pref medium
2001:db8:97::/64  encap seg6 mode inline segs 2 [ fc00:0:c::1 :: ] dev ab-a metric 1024 pref medium
10.99.0.0/24  encap seg6 mode encap segs 1 [ fc00:0:c::102 ] dev ab-a scope link
```

`ip -j` gives the encap as fields:

```json
[
    {
        "dst": "fc00:0:b::41",
        "encap": {
            "encap_type": "seg6local",
            "action": "End.X",
            "nh6": "fc00:bc::2"
        },
        "dev": "bc-b",
        "protocol": "isis",
        "metric": 1024,
        "flags": [],
        "pref": "medium"
    }
]
```

**Flavors.** Each tried alone and in pairs on a dummy:

| Behaviour | Taken | Refused ("Unsupported Flavor operation(s)") |
| --- | --- | --- |
| End | `psp`, `next-csid`, `next-csid,psp` | `usp`, `usd`, `psp,usd`, `usp,usd`, `psp,usp` |
| End.X | `next-csid` | `psp`, `usp`, `usd`, any pair, `next-csid,psp` |
| End.T | `psp` | not tried further |

So no behaviour takes USD, and End.X takes no PSP.

**The device a SID sits on matters.** Three End SIDs, on `lo`, on a
dummy `sr0` and on the ingress veth, each with `count`, and packets
sent to each with H.Encaps:

```
fc00:0:b::1  encap seg6local action End packets 0 bytes 0 errors 0 dev lo metric 1024 pref medium
fc00:0:b::2  encap seg6local action End packets 8 bytes 1472 errors 0 dev sr0 metric 1024 pref medium
fc00:0:b::3  encap seg6local action End packets 8 bytes 1472 errors 0 dev ab-b metric 1024 pref medium
```

**A seg6local SID on `lo` is never hit.** On a dummy it is. FRR asks
for a dummy too ("Dummy interface used to install SRv6 SIDs into the
Linux data plane", from its YANG).

**`seg6_enabled` is not needed for seg6local.** It is 0 by default in
a new namespace, on `all`, `default` and each interface. The counts
above were the same with it 0 or 1 on `all` and on the ingress
interface, in all four combinations.

**Traffic.** A to C through B, one way, counted at each SID:

- H.Encaps `[B End, C End.DT46 vrftable 100]`, B's End on `lo`:
  nothing counted at either. Run again with B's End on `sr0` and C's
  SID an `End.DT6 table 254`: both counted every packet.
- H.Encaps.Red `[B End.X, C End.DT6 vrftable 100]`: 3 packets at each.
- IPv4 in H.Encaps `[C End.DT4 vrftable 100]`: 3 packets at C.
- The packet on the wire from A, H.Encaps with two SIDs:

```
IP6 (flowlabel 0xd16fe, hlim 64, next-header Routing (43), payload length 144) fc00:ab::1 > fc00:0:b::1: RT6 (len=4, type=4, segleft=1, last-entry=1, flags=0x0, tag=0, [0]fc00:0:c::100, [1]fc00:0:b::1) IP6 (flowlabel 0xd16fe, hlim 64, next-header ICMPv6 (58), payload length 64) 2001:db8:a::1 > 2001:db8:99::1: [icmp6 sum ok] ICMP6, echo request, id 43344, seq 1
```

**A list must end in a decapsulating SID.** With H.Encaps to B's End
alone (the last SID is End, segments left 0, an IPv6 packet inside), B
counted the packets as errors and nothing arrived:

```
fc00:0:b::1  encap seg6local action End packets 0 bytes 0 errors 3 dev sr0 metric 1024 pref medium
```

With H.Encaps.Red to B's `End.DT6 table 254`, the inner packet went on
to C, and C's replies came back: `3 packets transmitted, 3 received`.
With the inner packet addressed to B itself, B decapsulated it and
answered "destination unreachable, unreachable route
2001:db8:b::1", and counted `Ip6InNoRoutes`. A legacy `table` lookup
finds no local address. TI-LFA has to live with that; see below.

**`vrftable` needs VRF strict mode.** End.DT4, End.DT46 and End.DT6
were taken with `vrftable`, over a VRF device, once
`net.vrf.strict_mode=1`; before it, End.DT46 and End.DT6 with
`vrftable` were refused with "Strict mode for VRF is disabled". End.DT6
also takes the legacy `table`, and `table 254` works with no VRF.
End.DT4 and End.DT46 with the legacy `table` were not tried. Creating
the VRF device loaded the `vrf` module on ospflab.

**The outer source address.** `ip sr tunsrc show` gives `::` in a new
namespace, and the kernel then picks one by route: the capture above
has `fc00:ab::1`, A's interface address. `ip sr tunsrc set` changes it;
that is generic netlink (`seg6_genl.h`), not rtnetlink.

**A seg6 route is a backup the kernel takes itself.** A route to
`2001:db8:d::/64` via one veth at metric 22, and a second with `encap
seg6 mode encap.red` out of another at 122, with
`ignore_routes_with_linkdown`. With the far end of the first veth down,
`ip route get` gave the second:

```
2001:db8:d::1 from ::  encap seg6 mode encap.red segs 2 [ fc00:0:b::1 fc00:0:b::2 ] dev y-a proto isis src fc00:2::1 metric 122 pref medium
```

So an SRv6 backup is switched by the kernel on carrier loss, as
isisd's IP backups are today. A label route has no metric and cannot
be (`docs/ti-lfa.md`, "In the kernel").

**Not measured**: the deepest SRH the kernel processes or pushes.
iproute2 6.19 took 32 segments and refused 64 on its own buffer
("rta_addattr_l: Error! max allowed bound 1024 exceeded"), so `ip`
cannot measure it. The forwarding step measures it through isisd's own
netlink, before isisd advertises an MSD.

## Measured on FRR 10.7.1

The labs run FRR 10.7.1 (`isis4r-tilfa`, `isis4r-bfd`). Both images on
ospflab, `quay.io/frrouting/frr:10.2.1` and `10.7.1`, have IS-IS SRv6
in `isisd` (`strings`: "segment-routing srv6", "SRv6 End.X SID",
"SRv6 Locator"). 10.7.1's isisd and zebra also have uSID: "uN", "uA",
"uDT6", "uDT46", "usid-f3216", "behavior usid". So the lab's FRR nodes may
use 10.7.1, a release: interop runs only against a released FRR.

Two 10.7.1 containers on a Docker network of their own, point-to-point,
Level 2, a locator each with `block-len 32 node-len 16 func-bits 16`,
and a dummy `sr0` made by hand, then removed. f1 as f2 saw it:

```
  Router Capability: 172.30.99.2 , D:0, S:0
    SR Algorithm:
      0: SPF
    SRv6: O:0
  Extended Reachability: 0000.0000.0002.00 (Metric: 10)
    Remote Interface IPv6 Address(es): fd00:5ec6::3
    SRv6 End.X SID: fc00:0:1:1::, Algorithm: SPF, Weight: 0, Endpoint Behavior: End.X, Flags: B:0, S:0, P:0
        SRv6 SID Structure Locator Block length: 32, Locator Node length: 16, Function length: 16, Argument length: 0,
  IPv4 Interface Address: 172.30.99.2
  IPv6 Reachability: fc00:0:1::/48 (Metric: 0)
  IPv6 Reachability: 2001:db8::1/128 (Metric: 10)
  IPv6 Reachability: fd00:5ec6::/64 (Metric: 10)
  SRv6 Locator: fc00:0:1::/48 (Metric: 0) standard
    Sub-TLVs:
      SRv6 End SID Endpoint Behavior: End, SID value: fc00:0:1::
        Sub-Sub-TLVs:
          SRv6 SID Structure Locator Block length: 32, Locator Node length: 16, Function length: 16, Argument length: 0,
```

And what it installed:

```
fc00:0:1:: nhid 17  encap seg6local action End dev sr0 proto isis metric 20 pref medium
fc00:0:1:1:: nhid 13  encap seg6local action End.X nh6 fe80::20b0:dff:fe35:b036 oif eth0 dev eth0 proto isis metric 20 pref medium
fc00:0:2::/48 nhid 19 via fe80::20b0:dff:fe35:b036 dev eth0 proto isis metric 20 pref medium
```

What this shows:

- The locator goes in TLV 236 and in TLV 27, at metric 0 (9352 section
  5's SHOULD).
- The End SID is the locator with function 0; the End.X SID takes
  function 1.
- End and End.X with no flavor. The End SID sits on `sr0`, the End.X on
  the interface, to the neighbour's link-local address with `oif`.
- The SID Structure is sent with each SID.
- No Prefix Attribute Flags sub-TLV in TLV 27, though 7.1 says
  "SHOULD".
- FRR installs nothing for its own locator beyond its SIDs.
- `show isis segment-routing srv6 node` lists f2 with SRH Max SL 3,
  Max End Pop 3, Max H.encaps 2, Max End D 5.

**The same with a uSID locator** (`behavior usid`, `format usid-f3216`)
on f1. The L2 LSP on the wire, captured at f2 and cut by TLV:

```
TLV 242 22 ac1e63020019020000130100170829032a032c022d05
TLV 22  59 0000000000020000000a300d10fd005ec60000000000000000000000032b1c0000000034fc0000010001e000000000000000000006010420101000
TLV 27  44 000000000000000030fc00000100011c051a00002bfc00000100010000000000000000000006010420101000
```

- TLV 242: SRv6 Capabilities `19 02 0000`, O clear; SR-Algorithm `13 01
  00`; Node MSD `17 08 29 03 2a 03 2c 02 2d 05`, types 41, 42, 44, 45
  with 3, 3, 2, 5.
- TLV 22: sub-TLV 13 (16 octets, the neighbour's address), then End.X
  `2b 1c`: flags 0, algorithm 0, weight 0, **behaviour 0x0034, 52, End.X
  with NEXT-CSID**, SID `fc00:1:1:e000::`, SID Structure `01 04 20 10 10
  00`.
- TLV 27: MTID 0; metric 0, flags 0, algorithm 0, Loc-Size 48, locator
  `fc00:1:1`; End SID `05 1a`: **behaviour 0x002b, 43, End with
  NEXT-CSID**, SID `fc00:1:1::`, SID Structure 32, 16, 16, 0.
- In the kernel: `fc00:1:1::/48 ... action End flavors next-csid lblen
  32 nflen 16 dev sr0` and `fc00:1:1:e000::/64 ... action End.X nh6
  fe80::... oif eth0 flavors next-csid lblen 32 nflen 16 dev eth0`.

Both LSPs were captured again on 2026-11-28, with the End.X SID in
TLV 22, for the codec's fixtures: two FRR 10.7.1 containers, f1 uSID
and f2 not, each with `fc00:0:N::/48`, point to point at Level 2, in a
containerlab lab made and destroyed for it. f1's is
`test/fixtures/frr-10.7.1-l2-lsp-srv6-usid.hex`, behaviours 43 and 52;
f2's is `test/fixtures/frr-10.7.1-l2-lsp-srv6.hex`, behaviours 1 and 5.
Each decodes with no SRv6 Unknown and replays byte for byte
(`test/unit/pdu/lsp_srv6_test.rb`).

FRR's uSID SID Structure has argument length 0. RFC 9800 section 8's
example gives "AL: 48 (= 128-48-16-16)", the argument covering the rest
of the SID. I do not know whether FRR reads the RFC otherwise or the
value is a slip. isisd reads either, and the fault matrix records what
FRR does with ours.

FRR 10.7.1 computes no TI-LFA repair over SRv6: routescope measured
"0 TI-LFA, 6 unprotected" on four FRR routers (routescope #320, below).
Its isisd has `isis_area_delete_backup_srv6_endx_sids`, so it allocates
backup End.X SIDs, but it builds no repair list. So FRR can be P or a
transit on isisd's repairs, never the PLR.

## The design

### Wire format

New classes, each registered under its parent, built four ways, with
`encode`, `parse`, `to_hash`, `to_s`, an entry in
`test/unit/to_hash_catalog.rb`, and hex tests from the RFC layouts and
from FRR 10.7.1's LSP above:

| Where | Type | Class | RFC |
| --- | --- | --- | --- |
| top | 27 | `Tlv::Srv6Locator`, entries of `Srv6Locator::Entry` | 9352 7.1 |
| TLV 27 | 5 | `SubTlv::Srv6EndSid` | 9352 7.2 |
| TLV 22 | 43 | `SubTlv::Srv6EndXSid` | 9352 8.1 |
| TLV 22 | 44 | `SubTlv::Srv6LanEndXSid` | 9352 8.2 |
| sub-TLVs 5, 43, 44 | 1 | `SubTlv::Srv6SidStructure`, a sub-sub-TLV | 9352 9 |
| TLV 242 | 25 | `SubTlv::Srv6Capabilities` | 9352 2 |
| TLV 242 | 23 | `SubTlv::NodeMsd` | 8491 2 |
| TLV 22 | 15 | `SubTlv::LinkMsd` | 8491 3 |
| TLVs 27, 135, 236 | 4 | `SubTlv::PrefixAttributeFlags`, X R N, and A at bit 4 | 7794 2.1, 9352 6 |

Points the classes must keep:

- **The locator** is written in the fewest octets for Loc-Size, as TLV
  236's prefix is. A Loc-Size of 0 or over 128 is kept and replayed;
  the parse reads `(size + 7) / 8` octets, capped at 16, and keeps
  what follows as it is. Building never validates.
- **TLV 27's sub-TLV list is framed by a length octet always**, as TLV
  22's is, not behind a bit as TLV 135's is. The Locator TLV joins the
  prefix sub-TLV registry (9352 11.1.2), so the Prefix Attribute Flags
  class registers once under 27, 135 and 236.
- **One registry of behaviours**, `ISIS::Srv6::BEHAVIORS`, from RFC
  8986's table 10.2.2 and RFC 9800's 12.1: number, name and flavors.
  The SID classes keep the number; `to_s` and `to_hash` give the name,
  and the number when the name is unknown.
- **Flags** hash as letters, `flags: ["B"]`, with `reserved:` when an
  unnamed bit came set, as the SR-MPLS classes do.
- **TLV 242's Router ID stays IPv4.** RFC 7981 section 2 allows 0.0.0.0
  with an IPv6 TE Router ID for a node without IPv4. isisd's labs are
  dual stack, so that waits; see "Out of scope".

### Configuration

```yaml
ipv6: true                    needed by srv6
router_id: 10.255.0.1         as today
srv6:                         SRv6, RFC 9352; off when absent
  locators:
    - name: main
      prefix: fc00:0:1::/48
      algorithm: 0            0 now; 128 to 255 with flex-algo
      structure: { block: 32, node: 16, function: 16, argument: 0 }
  interface: sr0              the dummy the End and End.DT6 SIDs sit on
  decap: true                 an End.DT6 SID per locator, for TI-LFA
  receive_policy: rfc         rfc, strict or lenient (Validation)
interfaces:
  - name: eth1
    end_x: true               default true when srv6 is set
    ti_lfa: link              as today; with srv6, the repair is SRv6
```

- **`srv6` absent means SRv6 off.** No TLV 27, no sub-TLV 25, no
  seg6local route. Today's LSPs stay byte for byte the same.
- **`srv6` needs `ipv6: true`**, and is refused without it, by name.
- **A locator's prefix** must be IPv6, its length the sum of `block`
  and `node`, and `block + node + function + argument` at most 128
  (8986 3.1). Two locators must not overlap. A locator prefix that is
  also one of `ipv6_prefixes` is refused: the locator already goes in
  TLV 236 (below).
- **`interface`** names a dummy device that must exist. The host
  checks it in `/sys/class/net` at start, and isisd logs an error and
  installs no SID if it is missing. isisd does not create it: the lab
  does, as FRR's labs do. See "Decisions", 4.
- **SR-MPLS and SRv6 may run together.** `segment_routing` and `srv6`
  are independent. With both, `ti_lfa` builds the MPLS backup for IPv4
  routes and the SRv6 backup for IPv6 routes (below). Today `ti_lfa`
  is refused without `segment_routing` (`Router.ti_lfa`); it is taken
  with either from then on.
- An unknown key under `srv6` is refused, as today for `interfaces`.

### Origination

- **SRv6 Capabilities** in TLV 242, O clear, one per level. TLV 242 is
  sent when `segment_routing` or `srv6` is set.
- **SR-Algorithm** lists 0, as today. With flex-algo, it lists each
  algorithm isisd takes part in, for SR-MPLS and SRv6 alike (9350 11.1).
- **TLV 27** per level: each locator, its metric 0 (as FRR), D clear,
  its algorithm, and its sub-TLVs: Prefix Attribute Flags (N clear, A
  clear, X clear: 9352 7.1's SHOULD), then the End SID, then the
  End.DT6 SID when `decap` is set. Each SID carries a SID Structure
  from the locator's `structure`.
- **The locator in TLV 236 too**, at the same metric, for algorithm 0
  only (9352 section 5).
- **End.X** in each TLV 22 entry to an adjacency that is Up and has
  `end_x`: one SID, behaviour End.X, algorithm 0, weight 0, B clear,
  P clear. On a LAN, LAN End.X SIDs in the TLV 22 entry to the DIS, one
  per neighbour (8.2).
- **Function allocation**, per locator: 0 for End, 1 for End.DT6, then
  2 upwards for End.X, an adjacency keeping its function while it is
  up. FRR uses 0 and then 1 for End.X (measured), so the two are told
  apart in a capture.
- **MSDs** are sent only once measured (see the kernel section). Until
  then, none: section 4 says a missing Max SL means 0, which only stops
  a headend that reads it from sending isisd an SRH. The open
  questions ask whether that wait is acceptable.
- **Leaking.** A locator leaked from Level 2 to Level 1 keeps its
  algorithm and metric rules, sets D, and carries Prefix Attribute
  Flags with R set (9352 7.1's MUST). Leaking follows `leak:` as for
  TLV 236. Summaries do not cover locators in the first version.

### Calculation

The locators join the existing calculation; SPF itself does not
change.

1. **Read each node's SRv6 state** from its LSPs: SRv6 Capabilities,
   the algorithms, its locators per algorithm, and its End, End.X and
   End.DT6 SIDs. A new reader, `Spf::Srv6`, beside `Spf::Labels`, runs
   after each level's SPF and runs the SRv6 rules in `validation.rb`.
2. **Locator routes.** `read_prefixes` reads TLV 27 entries of
   algorithm 0 as it reads TLV 236's, with the locator's metric and its
   D bit as up/down. Where the same prefix comes in TLV 236 from the
   same node, the TLV 236 entry is kept and the TLV 27 one only marks
   the route as a locator (9352 section 5's MUST). A locator of another
   algorithm is not read here; see "Flex-algo locators".
3. **Locators of nodes without SRv6 Capabilities are still routed.**
   Section 5 asks SRv6-capable routers to install them; it does not
   make the sender's capability a condition. The route is an IPv6 route
   like any other.
4. **Other nodes' SIDs are never installed** (section 5). They are kept
   for the view and for TI-LFA.
5. **Our own SIDs**: End and End.DT6 on `interface`; each End.X to its
   neighbour's link-local address with `oif`, as FRR does. Nothing for
   our own locator beyond its SIDs, as FRR 10.7.1 does.

The result is an SRv6 table per level, `{sid:, behavior:, kind: :end |
:end_x | :decap, adjacency:, locator:}` for our own SIDs, and per node
its locators and SIDs.

### Forwarding

`Forwarding::Netlink` gains two encaps:

- **seg6local**, `LWTUNNEL_ENCAP_SEG6_LOCAL` (7): `SEG6_LOCAL_ACTION`
  with the kernel's action number (End 1, End.X 2, End.DT6 7), then
  `SEG6_LOCAL_NH6` and `RTA_OIF` for End.X, `SEG6_LOCAL_TABLE` 254 for
  End.DT6. A /128, IPv6, protocol 187, on the `interface` dummy or the
  End.X's interface.
- **seg6**, `LWTUNNEL_ENCAP_SEG6` (5): a `seg6_iptunnel_encap`, the mode
  (encap.red, 3) then an SRH (`struct ipv6_sr_hdr`, `seg6.h`), for
  TI-LFA's backups. No gateway: the kernel routes the first SID.

`Forwarding.operations` diffs the SRv6 table as it diffs label tables.
The exact octets are checked against `ip -6 route` in a network
namespace, as the MPLS encoder was, before the encoder is written: the
routes in "Measured in the kernel" are the fixtures.

**The host.** `Router::Host#srv6` checks the dummy exists and is up.
isisd sets nothing for seg6local, since `seg6_enabled` is not needed
(measured). The outer source address of a backup is the kernel's
`tunsrc`; the labs set it to the loopback with `ip sr tunsrc set`,
since setting it from isisd needs generic netlink. isisd logs the
address it expects at start.

### TI-LFA over SRv6

`Spf::TiLfa` is unchanged: it gives P, Q and segments. A new
`Spf::Srv6Backups`, beside `Spf::Backups`, turns them into a SID list
for each IPv6 route behind a protected adjacency:

- `[:node, X]` becomes X's End SID; `[:adj, X, Y]` becomes X's End.X SID
  to Y. 9855 7.2: no node SID is needed before an End.X SID, since it is
  routed by X's locator. So in case 5.3 and 5.4 the list may start with
  P's End.X SID and leave P's End SID out. That is shorter, and the
  first build does it.
- **The list ends in a decapsulating SID.** The kernel drops a packet
  whose last SID is an End with an IPv6 packet inside (measured: errors
  3), and takes no USD flavor. So the last SID is Q's End.DT6, and Q
  forwards the inner packet on its own table, which after the failure
  is the post-convergence path by Q's definition.
- **Where Q is the destination's own node**, Q's End.DT6 with `table
  254` cannot deliver to Q itself (measured: "unreachable route"). The
  step measures two ways out before it builds either: the decap SID on
  a lookup that sees local addresses (an `ip -6 rule`, or `table 255`
  then 254), or ending the list one SID earlier, at the node before Q,
  when that node's own path to Q avoids the failure. Until then such a
  destination is unprotected, with the reason `decap_local`.
- **A node without an End.DT6 SID**, FRR today, cannot be Q. The route
  is unprotected with the reason `no_decap_sid`, unless another Q is
  found. FRR does not advertise one in IS-IS (measured: End only).
- The backup is a second IPv6 route at the route's priority plus 100,
  `encap seg6 mode encap.red`, out of the first hop's interface, as
  today's IP backups. The kernel takes it on carrier loss (measured).
- **SRv6 traffic itself is protected too.** A route to another node's
  locator is an IPv6 route, so its backup is built the same way. Unlike
  a label route, it has a metric, so the kernel switches it with no
  daemon. That is a gain over SR-MPLS's label routes.
- **IPv4 routes** keep their MPLS backup when `segment_routing` is set.
  Carrying IPv4 over an SRv6 repair needs End.DT4 or End.DT46, which
  were measured only over a VRF. Not in the first version.
- `show.ti_lfa` gains `data_plane: srv6` and `sids` beside `labels`.

### Flex-algo locators

This is where this spec meets `docs/design/flex-algo.md`, approved and
merged on 2026-11-25 (#134). Its "Out of
scope" lists "SRv6 flex-algo (P6)", so this spec owns it. It builds on
flex-algo's steps 4 (selection and participation) and 5 (the
calculation), and comes after them:

- **Participation** is flex-algo's: the SR-Algorithm sub-TLV, shared by
  SR-MPLS and SRv6 (9350 11.1). Nothing new.
- **A locator per algorithm.** `algorithm: 128` on a locator, for an
  algorithm in `flex_algo`. It is sent in TLV 27 only, never in TLV 236
  (9352 section 5's SHOULD NOT), and only while isisd takes part.
- **Its route comes from the algorithm's tree.** Flex-algo's
  calculation gives "routes keyed by prefix ... for the label table
  only. No IP route comes from an algorithm." **That changes here**: a
  locator of algorithm K is installed as an IPv6 route from K's tree
  (9350 14.2's MUST). It is the one kind of IP route an algorithm
  gives. A locator of an algorithm isisd does not take part in is not
  installed (14.2's MUST NOT). Flex-algo's spec should say so in its
  calculation section once both are approved.
- **The metric** is the locator's own; a FAPM in TLV 27 is ignored and
  reported (9350 section 8).
- **End.X SIDs per algorithm.** One End.X per adjacency per algorithm
  whose pruning keeps the link, from that algorithm's locator, with the
  algorithm in the SID. 9352 section 8: the algorithm is in each SID.
  Flex-algo lists "Flex-algo-specific Adj-SIDs" out of its scope for
  MPLS, since RFC 9350 has none. For SRv6 they are needed: 9350 14.2
  says LFA paths "MUST only use SRv6 SIDs advertised specifically for
  the given Flex-Algorithm".
- **TI-LFA per algorithm** uses flex-algo's graph per algorithm, and K's
  End, End.X and End.DT6 SIDs only.
- **The two longest-match hazards** of 9352 section 5 (another locator,
  or a TLV 236 prefix, longer than the locator) are reported as
  findings, not prevented.

### API and CLI

- New `show.srv6`: our locators, our SIDs with behaviour, function and
  state in the kernel; per level, each node's capabilities, locators
  and SIDs; and the findings.
- `show.routes`: an IPv6 route gains `locator: true` when it came from
  TLV 27, and `algorithm`.
- `show.topology`: each node gains `locators` and `end_sids`, each link
  `end_x_sids`.
- `show.ti_lfa`: `data_plane` and `sids` (above).
- `show.routes`: an IPv6 route's `backup` gains `sids` and `mode`
  (`encap.red`) where an MPLS backup has `labels`; `case`, `protects`,
  `path`, `p` and `q` stay as they are.
- `show.overview` gains `srv6: true` when `srv6` is configured.
- A new event kind, `srv6`, beside `sr`: a locator learned or
  withdrawn, a SID of ours allocated, installed, refused by the kernel
  or withdrawn, and a finding.
- `policy.srv6`: a locator added or withdrawn while isisd runs, for
  scenarios. Checked as the file is.
- `api.info` lists the new methods; routescope greys what an older
  isisd lacks.
- `isis-cli show srv6`.

New fields are added; none is renamed or removed.

### The simulator

The simulator's systems use the same originator. Its topology gains an
`srv6` section, as `segment_routing` is today:

```yaml
srv6:
  block: fc00:0::/32            each system's locator is block:N::/48
  structure: { block: 32, node: 16, function: 16, argument: 0 }
```

With it, each simulated system advertises a locator, its End SID, an
End.DT6 SID, and an End.X per link. A router may give its own
`locator:`, and `algorithm:` with flex-algo. isis4r-sim installs
nothing: the simulated systems have no data plane.

### routescope

What routescope shows is a routescope specification of its own,
`docs/design/srv6-views.md` there, written after this one is approved.
It is not written here. What it will cover:

- the locators per node, and the SIDs with their behaviour, as a table
  beside `mpls_labels`, read from `show.srv6` on isisd, from FRR's
  `show segment-routing srv6 locator` and `show isis segment-routing
  srv6 node`, and from the kernel's `ip -j -6 route` (`seg6local` and
  `seg6` encaps, as above);
- seg6 routes, a backup's SID list, checked against the kernel as the
  Backup columns' Kernel check is for labels;
- a SID list on the map, as the TI-LFA repair path is drawn;
- scenario conditions and MCP actions: a locator route present, a SID
  installed, a backup's SIDs, `policy.srv6`.

## Built to the conventions

routescope's `docs/design/protocol-conventions.md`, part by part.

### 1. The codec

The classes above, on the object contract, each in the `to_hash`
catalog and in `docs/building-objects.md`, whose test finds them. FRR
10.7.1's uSID LSP is the first fixture, captured again in the codec's
pull request as `test/fixtures/frr-10.7.1-l2-lsp-srv6-usid.hex`, and
an uncompressed one beside it.

### 2. Validation on receive

New rules in `validation.rb`, run by `Spf::Srv6` on the decoded
database. Each with its clause and an action per policy:

| Finding | Channel | Clause | `:rfc` | `:strict` | `:lenient` |
| --- | --- | --- | --- | --- | --- |
| `locator_size_invalid` | errors | 9352 7.1, Loc-Size outside 1 to 128: "The entire TLV MUST be ignored" | ignore the TLV | ignore the node's SRv6 | use what parses |
| `locator_algorithm_conflict` | errors | 7.2, one MTID/locator, two algorithms: "all TLVs ... MUST be ignored" | ignore those TLVs | ignore the node's SRv6 | use the first |
| `end_sid_outside_locator` | errors | 7.2: "MUST be ignored" | ignore the SID | ignore the node's SRv6 | use |
| `end_x_sid_no_locator` | errors | 8: not "a subnet of a Locator with matching topology and algorithm" | ignore the SID | ignore the node's SRv6 | use |
| `sid_structure_twice` | errors | 9: "the parent sub-TLV MUST be ignored" | ignore the SID | ignore the node's SRv6 | use the first |
| `sid_structure_too_long` | errors | 9: a sum over 128 bits | ignore the SID | ignore the node's SRv6 | use |
| `behavior_not_allowed` | errors | 10: "MUST NOT be advertised" where Table 1 says N | ignore the SID | ignore the node's SRv6 | use |
| `behavior_unknown` | gaps | 7.2, 8.1: "ignored by the receiver" | ignore the SID | ignore the SID | ignore the SID |
| `anycast_and_node` | errors | 6: A and N set, "MUST ignore the N-flag" | ignore N | ignore the prefix | use both |
| `x_flag_mismatch` | errors | 6: TLV 236's flags "MUST be preferred" | use TLV 236's | ignore the locator | use TLV 27's |
| `fapm_in_locator` | errors | RFC 9350 8: "MUST be ignored" | ignore the FAPM | ignore the locator | ignore the FAPM |
| `locator_not_longest` | inconclusive | 9352 5: the locator must be the longest match | report | report | report |

`behavior_not_allowed` has no receiver action in 9352. Ignoring the SID
matches 7.2's treatment of an unsupported behaviour, and is the
answer taken at approval ("Decisions", 6).

### 3. Negative tests: the fault catalog

A fifth group, `SRV6`, in `ISIS::Fault`: an LSP with one wrong thing
in its SRv6 data, everything else correct, one entry per finding above
but `locator_not_longest`. A test checks the catalog and the rules
agree, as for SR-MPLS. Then:

- **Topologies**: TI-LFA's catalog topologies, run again with SRv6
  SIDs, each with the SID list RFC 9855 7.2 expects, written by hand.
  Plus three of SRv6's own: Q without an End.DT6 SID (unprotected,
  `no_decap_sid`), Q the destination's node (`decap_local`, until the
  step's measurement decides), and a repair through a uSID node named
  as single-CSID containers.
- **Behaviours**, in the simulator: a locator that flaps, an End.X SID
  that changes value on each LSP refresh, and a locator advertised by
  two systems without the A flag (section 6: "MUST be considered node
  specific").

### 4. The injector

isis4r-sim's `/api/fault` and `/api/plan` take the `SRV6` cases, with
`router` and `locator` as parameters. `/api/behave` takes the three
behaviours. A new action, `/api/locator`, advertises or withdraws a
simulated system's locator, as the prefix actions do. All under the
`X-ISIS4R` header rule the other POSTs follow.

### 5 to 7. API, configuration, CLI

Above. An unknown key is refused, as `interfaces` is today.

### 8. Time

Nothing new runs on a timer. The SRv6 reader runs after SPF, which is
on the injected clock. The time guard needs no new entry.

### 9. Logs and capture

At info: a locator learned or withdrawn, a SID installed or refused by
the kernel (with errno), a backup with no decap SID. Each finding at
warn, with its clause.

**Capture.** Today `isis-capture` gives each TLV one field named by its
`to_s`, with its type, length and value as children
(`wire_capture/dissect.rb`); sub-TLVs are not split out. For SRv6:

- TLV 27's entries and their sub-TLVs, and the SRv6 sub-TLVs of TLVs
  22 and 242, become child fields, with their offsets.
- Every TLV and sub-TLV field gains a `key`: its registry name with
  hyphens for underscores. The registry names stay snake_case symbols,
  as today (`:adj_sid`). The new ones are chosen so the keys read as
  the RFC and CLI terms: `locator`, `end-sid`, `end-x-sid`,
  `lan-end-x-sid`, `srv6-capabilities`, `sid-structure`,
  `prefix-attribute-flags`, `node-msd`, `link-msd`. The existing classes
  get theirs the same way: `prefix-sid`, `adj-sid`, `lan-adj-sid`,
  `sr-capabilities`. routescope's capture filter matches on `key`
  (routescope #320), as it will on ospfv2's for SR in OSPF.
- `key` is added beside `name`; no field is renamed, so an older
  reader of the capture is not broken.

## Labs

One lab, `isis4r-srv6`, with FRR nodes in it, as the owner decided for
flex-algo (its decision 3: "One lab, `isis4r-flexalgo`, with an FRR
node") and as `isis4r-tilfa` has.

- six isisd in a ring with a chord, as `isis4r-tilfa`, Level 2, dual
  stack, SR-MPLS and SRv6 both on, a locator each from `fc00:0::/32`,
  `ti_lfa: node` on every link (CLAUDE.md "Our own Ruby code first");
- two FRR 10.7.1 nodes, f1 and f2, released, on the ring, so each SID
  behaviour is crossed both ways; f2's locator is uSID;
- an isis4r-sim behind one isisd, with a grid of SRv6 systems;
- two Linux hosts, one at each side, that send IPv6 traffic, and one
  with a static `ip -6 route ... encap seg6` to a SID list, since
  isisd builds no SR policy of its own;
- each node's start command creates `sr0` and sets `ip sr tunsrc`.

Scenarios:

- the locators converge, and every node, isisd and FRR, has a route to
  every other locator;
- a packet with a three-SID list crosses End, End.X and End.DT6, on
  isisd and on FRR (`flow` and `flow_lost`, routescope's scenario
  steps);
- f2's uSID locator is routed to, and named as a single container in a
  repair;
- a link fails and the kernel takes the SRv6 backup, with `flow_lost`
  under a bound. FRR computes no SRv6 repair (measured), so isisd is
  the only PLR; FRR is P and transit on isisd's repairs;
- the catalog's SRv6 entries, each refused as the finding says.

`ABOUT.md` says the lab runs on our own code, and that f1 and f2 are
the interop check.

## Tests

- Unit: each class four ways and its hex, against the RFC layouts and
  FRR's LSP; the behaviour registry; origination byte for byte; the
  locator rules in `read_prefixes`; each finding, and the catalog
  against the rules; `Spf::Srv6Backups` on the catalog's topologies.
- Scenario: pass-through equivalence with SRv6 on, so the new reader
  and the forwarding operations go through the controls.
- Interop, in network namespaces as root: `test/interop/kernel_srv6_test.rb`
  installs isisd's seg6local routes and an SRv6 backup through its own
  adapter, sends traffic through them, and takes a link down as
  `kernel_backup_test.rb` does; `test/interop/frr_srv6_test.rb` brings
  up isisd and FRR 10.7.1 and checks each reads the other.
- The fault matrix: the `SRV6` entries sent to isisd and to FRR,
  written to `docs/fault-matrix.md`.
- Lab: `isis4r-srv6`'s scenarios, through routescope.

## Work

One pull request each, in order. Each is small.

1. **Codec.** TLV 27, sub-TLVs 5, 43, 44, 25, 23, 15 and 4, the SID
   Structure, the behaviour registry. The FRR fixtures. Catalog entries
   and the codec's fault cases.
2. **Configuration and origination.** `srv6`, `end_x`; TLV 242's new
   sub-TLV, TLV 27, the locator in TLV 236, End and End.X SIDs, the
   leaking rules. Gate: FRR 10.7.1 lists isisd in `show isis
   segment-routing srv6 node` and decodes its SIDs.
3. **Reading and the calculation.** `Spf::Srv6`, locator routes, the
   validation rules, `show.srv6`, `show.topology`. Gate: each side has
   a route to the other's locator, from TLV 27 and 236 as section 5
   asks.
4. **Forwarding.** seg6local End, End.X, End.DT6 through `Netlink`, on
   the dummy; the MSDs measured and then advertised. Gate: traffic with
   a SID list crosses FRR and isisd both ways.
5. **TI-LFA over SRv6.** The `decap_local` measurement first, then
   `Spf::Srv6Backups` and the seg6 backups in the kernel. Gate: a link
   fails and the kernel takes the SRv6 backup, traffic loss measured.
6. **The injector.** The simulator's `srv6`, the `SRV6` catalog,
   behaviours and `/api/locator`, then the fault matrix against FRR in
   network namespaces.
7. **`isis4r-srv6`.** The lab, with f1 and f2, and its scenarios.
8. **Flex-algo locators**, after flex-algo's steps 4 and 5: locators
   and End.X SIDs per algorithm, the locator route from K's tree, TI-LFA
   per algorithm over SRv6.
9. **uSID**, RFC 9800's NEXT-CSID: uN and uA instantiated with
    `flavors next-csid`, and compressed repair lists (9800 6.2).

Then routescope's `docs/design/srv6-views.md`, then its pull requests,
and the labs in CI there. Then the BGP half.

## The BGP half: RFC 9252 in bgp4rd

The next spec, `docs/design/srv6-services.md` in bgp4r, after this one
is approved. It is not written here. What it starts from:

- bgp4rd allocates End.DT4, End.DT6 and End.DT46 service SIDs for its
  VRFs, and End.DX4 and End.DX6 per CE, and advertises them in the
  BGP Prefix-SID attribute's SRv6 L3 Service TLV (RFC 9252).
- Its ingress PE puts VPN traffic in H.Encaps toward the remote PE's
  service SID. bgp4r's L3VPN PE (P2, `l3vpn-pe.md`) does this with
  labels today.
- The service SIDs come from a locator that isisd advertises, so the
  remote PE has a route to them. Who owns the locator, isisd's
  configuration or a shared one, is that spec's first question.
- End.DT4 and End.DT46 were measured over a VRF device with
  `net.vrf.strict_mode=1` (above). bgp4r's VRFs are VRF devices
  already.

## Out of scope

- SRv6 policies at the headend, other than TI-LFA's repairs. No SR
  Policy, no binding SID (End.B6.Encaps).
- End.T, End.DX*, End.DT4 and End.DT46 in isisd. Service SIDs are
  bgp4rd's.
- The PSP, USP and USD flavors: the kernel takes none for End.X and no
  USD at all (measured).
- Multi-topology, TLVs 222 and 237, and MTID other than 0.
- An IPv6-only node: TLV 242 with Router ID 0.0.0.0 and an IPv6 TE
  Router ID (RFC 7981 section 2).
- SRH HMAC (`CONFIG_IPV6_SEG6_HMAC` is there; nothing asks for it).
- Summaries of locators between levels.
- The O flag (RFC 9259).
- BGP-LS for SRv6 (RFC 9514).

## Answers for routescope's views

routescope's `docs/design/srv6-views.md` (routescope #320) asked ten
questions of this spec, I1 to I10. Its views follow these answers. Its
measurements on FRR 10.7.1, four routers in a square, found three things:
FRR computed no TI-LFA over SRv6 ("0 TI-LFA, 6 unprotected"); FRR
refuses SRv6 flex-algo ("SRv6 Flex-algo dataplane is not yet
supported") and takes one locator per IS-IS instance; and FRR installed
no seg6local route for its End SID. Both sides then measured again.
FRR installs its End SID when a dummy `sr0` exists: here it was made by
hand and named under `segment-routing srv6`; routescope found naming it
is not needed, since `sr0` is FRR's default. Without the dummy, FRR
installs none, and a ping through that End SID is lost. And
`seg6_enabled` is not needed: with it 0 on `all` and on each interface,
seg6local SIDs counted packets here, and pings through End, End.X and
End.DT6 passed in routescope's lab. The lab makes the dummy on
every node.

- **I1, which method.** One new method, `show.srv6`: our locators, our
  SIDs (End, End.DT6, and End.X per adjacency, with the adjacency), and
  per level each node's locators and SIDs. The other views gain fields
  as listed under "API and CLI". SRv6 is on when `show.overview` says
  `srv6: true`; `api.info` lists `show.srv6` once isisd has it.
- **I2, every router's locators.** Yes: per level, per node, each
  locator with its algorithm, metric, D bit and flags, its End SIDs
  with behaviour and SID Structure, and each End.X with its neighbour,
  algorithm, weight, flags and structure, as FRR's database shows.
- **I3, the kernel.** End and End.DT6 (`table 254`) as /128 routes on
  the dummy; each End.X as a /128 to the neighbour's link-local
  address with `oif`. No flavor. Protocol 187, shown as `proto isis`.
  With uSID (step 9), uN and uA follow FRR's measured form: End with
  `flavors next-csid` on the locator's /48, End.X with `flavors
  next-csid` on a /64, with `lblen` and `nflen` from the structure.
- **I4, TI-LFA.** Yes, step 5. A repair shows in `show.routes` as an
  MPLS one does: `backup` with `address`, `interface`, `case`,
  `protects`, `path`, `p`, `q`, and `sids` and `mode` in place of
  `labels`. `show.ti_lfa` gains `data_plane: srv6`. Where Q is the
  destination's own node, or has no decap SID, the route is
  `unprotected` with `decap_local` or `no_decap_sid`.
- **I5, the backup in the kernel.** A `seg6` route in `encap.red` mode,
  at the route's priority plus 100, as MPLS backups are. Not `inline`:
  see "Decisions", 3.
- **I6, SRv6 flex-algo.** Yes, step 8, after flex-algo's steps 4 and 5.
  A locator per algorithm, with `algorithm` on each locator, End.X SID
  and route in the API. FRR refuses it, so it is tested on isisd alone
  and against the simulator; there is no interop peer for it yet.
- **I7, events.** The existing `spf` and `route` events cover the
  locator routes. A new kind, `srv6`, covers a locator learned or
  withdrawn, a SID allocated, installed, refused or withdrawn, and the
  findings, as `sr` does for SR-MPLS.
- **I8, the catalog.** Yes, step 6: the `SRV6` group in
  `ISIS::Fault`, served by isis4r-sim's `/api/fault` and `/api/plan`,
  its behaviours by `/api/behave`, and `/api/locator`.
- **I9, uSID.** Classic End and End.X in the first version; uN and uA
  in step 9 ("Decisions", 1). isisd reads and routes to FRR's uSID
  locators from the first version.
- **I10, LAN End.X.** Yes, in step 2: one LAN End.X SID per neighbour on
  a broadcast link, in the TLV 22 entry to the DIS (9352 8.2), each
  installed as a /128 End.X to that neighbour.

## Decisions

The owner approved the spec on 2026-11-25 with no separate answers.
Each of the draft's seven questions takes the answer the draft
recommended, as the default taken at approval. The owner may change
any of them before its step is built.

1. **uSID later**, step 9. The first version reads uSID SIDs, routes to
   their locators, and names them as single containers in repairs.
2. **The repair's last SID where Q is the destination's node**: the
   TI-LFA step measures the two ways out (a lookup that sees local
   addresses, or ending one SID earlier) and picks one before code.
   Until then such a destination is unprotected, reason `decap_local`.
3. **A decap SID per node**, End.DT6 in the End SID sub-TLV, as the
   design has it, not the inline SRH. An FRR node cannot be Q
   (`no_decap_sid`).
4. **The lab makes the dummy and sets `tunsrc`**, as FRR's labs do.
   isisd checks and logs.
5. **No MSDs** until the forwarding step has measured them.
6. **`behavior_not_allowed`**: under `:rfc`, ignore the SID and report.
7. **This spec carries the flex-algo exception alone**: a locator of
   algorithm K is routed from K's tree. `flex-algo.md` is approved and
   is not changed by this pull request.
