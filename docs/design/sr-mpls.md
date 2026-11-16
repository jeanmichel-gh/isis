# SR-MPLS in isis4rd

Status: approved by the owner 2026-11-16, merged in #84. No code yet.
The open questions at the end keep the answers this document gives
until the owner changes them.

This is P1 in routescope's `docs/protocol-coverage.md` and the SR-MPLS
part of Phase 4 here. It gives the L3VPN lab (P2) its transport labels.

## The problem

isis4rd computes IP routes and installs them in the kernel. It has no
labels. A search for `mpls`, `label`, `sid` and `srgb` in `lib/` and
`exe/` finds nothing (2026-11-16).

We want isis4rd to run SR-MPLS, as RFC 8667 defines it for IS-IS:

- advertise its label block and a SID for its loopback;
- learn the other routers' blocks and SIDs;
- install label routes in the kernel, so packets to a loopback travel
  on labels;
- interoperate with FRR, which does the same.

Phase 4's bar (CLAUDE.md, "Phase 4") applies: correct encoding, correct
state and calculation, correct forwarding, and interoperation with an
independent router.

## The terms, in short

From RFC 8402 and 8667. A short reminder, not a definition.

- **SRGB**, the global block: a label range each router reserves. A
  router advertises it in TLV 242.
- **Prefix-SID**: an index into the SRGB, attached to a prefix in TLV
  135. The label for index I at router X is X's SRGB start plus I.
  A **Node-SID** is a Prefix-SID on a router's loopback (N flag).
- **SRLB**, the local block: labels for local SIDs.
- **Adj-SID**: a local label for one adjacency. A packet with it on top
  leaves on that adjacency.
- **PHP**: the router before the SID's owner pops the label, so the
  owner gets a plain IP packet.

## What exists

Read at isis `5d0763a`.

- Sub-TLVs under a parent TLV: `SubTlv.register_under`
  (`lib/isis/subtlv/subtlv.rb:23`). TLV 22 has sub-TLVs 6 and 8
  (`subtlv/extended_is_reachability.rb`). TLV 135 reads and writes its
  sub-TLV list behind the presence bit
  (`tlv/extended_ip_reachability.rb`). Any other sub-TLV is kept as
  `SubTlv::Unknown` and replayed.
- The originator builds TLV 22 and 135 in `Originator#reachability`
  (`database/originator.rb:442`). TLV 22 entries get sub-TLVs from
  `link_subtlvs` (`:489`).
- SPF: `Spf::Calculation#read_prefixes` (`spf/spf.rb`) keeps the best
  offer per prefix. It does not keep which node advertised it, or the
  entry's sub-TLVs. `Spf::Route` is prefix, metric, adjacencies,
  external, up_down (`spf.rb:76`).
- Forwarding: `Forwarding.operations` diffs two route tables into
  install, replace and withdraw (`forwarding/forwarding.rb`).
  `Forwarding::Netlink` sends RTM_NEWROUTE and RTM_DELROUTE for AF_INET
  and AF_INET6, in Ruby, with protocol 187 (`forwarding/netlink.rb`). It
  has no MPLS attributes.
- Config: `ISIS::Router`'s header comment lists the keys
  (`lib/isis/router.rb:11-38`). There is no router ID key.
- API: JSON lines on `/run/isis4r/isisd.sock`, methods in
  `daemon/api.rb:40-70`, including `api.info`.

On the VM (`ospflab`, kernel 7.0.0-43, 2026-11-16):

- `mpls_router`, `mpls_iptunnel` and `vrf` exist as modules and are not
  loaded at boot. With them loaded, a two-label path through five
  network namespaces (push, PHP pop, pop into a VRF) passed a ping.
- The uapi headers give: `AF_MPLS` 28, `RTA_VIA` 18, `RTA_NEWDST` 19,
  `RTA_ENCAP_TYPE` 21, `RTA_ENCAP` 22, `LWTUNNEL_ENCAP_MPLS` 1,
  `MPLS_IPTUNNEL_DST` 1, label shift 12, bottom-of-stack shift 8. Printed
  by a C program from `linux/rtnetlink.h`, `lwtunnel.h`,
  `mpls_iptunnel.h` and `mpls.h`.
- FRR 10.2.1's `isisd` has `segment-routing global-block`, `local-block`,
  `node-msd` and a prefix-SID map (from `strings` on the binary).

## The design

### Wire format

New classes, each registered under its parent, each with the RFC text
in its comment, and hex round-trip tests as CLAUDE.md asks.

| Where | Type | Name | RFC 8667 |
| --- | --- | --- | --- |
| TLV | 242 | Router Capability | RFC 7981 section 2 |
| under 242 | 2 | SR-Capabilities | 3.1 |
| under 242 | 19 | SR-Algorithm | 3.2 |
| under 242 | 22 | SR Local Block | 3.3 |
| under 2 and 22 of TLV 242 | 1 | SID/Label | 2.3 |
| under 135 and 236 | 3 | Prefix-SID | 2.1 |
| under 22 | 31 | Adj-SID | 2.2.1 |
| under 22 | 32 | LAN-Adj-SID | 2.2.2 |

Points from the text that the classes must keep:

- **TLV 242** is a 4-octet Router ID, a flags octet (S 0x01, D 0x02),
  then sub-TLVs (RFC 7981 section 2).
- **SR-Capabilities** is a flags octet (I, V), then one or more
  descriptors: a 3-octet range and a SID/Label sub-TLV. The descriptors
  are an ordered list; the order changes the labels (3.1).
- **SID/Label** is 3 octets (a label in the low 20 bits) or 4 (an
  index) (2.3).
- **Prefix-SID** is flags (R N P E V L), algorithm, then 4 octets of
  index when V and L are clear, or 3 octets of label when both are set.
  Other combinations MUST be ignored (2.1.1.1).
- **Adj-SID** is flags (F B V L S P), weight, then a label or index as
  in 2.1.1.1 (2.2.1). LAN-Adj-SID adds the neighbor's System ID (2.2.2).
- Unknown flag bits and odd lengths are kept, as everywhere in the
  codec. The parse keeps the octets; validation reports what is wrong.

### Configuration

```yaml
router_id: 10.255.0.1        # new: TLV 242's Router ID
segment_routing:
  srgb: [{start: 16000, size: 8000}]
  srlb: {start: 15000, size: 1000}
prefixes:
  - { prefix: 10.255.0.1/32, metric: 0, sid: 1 }      # index 1
  - { prefix: 10.9.0.0/24, metric: 0, sid: 9, no_php: true }
interfaces:
  - name: eth1
    adj_sid: true            # default true when segment_routing is set
```

- **`segment_routing` absent means SR off.** No TLV 242 and no label
  routes. Today's LSPs stay byte for byte the same.
- **`srgb`** is a list, since 3.1 allows several descriptors. One is
  the usual case. The default is start 16000, size 8000. Ranges must not
  overlap each other or labels 0 to 15 (RFC 3032 section 6: "Label
  values 0-15 inclusive have special meaning"). A bad SRGB refuses the
  configuration.
- **`router_id`**: RFC 7981 section 3 says the Router ID "SHOULD be
  identical to an IP Interface Address [RFC1195] advertised by the
  originating IS" when there is no TE Router ID. The default is the first
  IPv4 /32 among `prefixes`. Without one, SR refuses the configuration.
- **`sid`** on a prefix is its index. A /32 or /128 that the router owns
  gets the N flag (2.1.1.2). `no_php: true` sets P; `explicit_null:
  true` sets P and E (2.1.1.3).

### Origination

- **TLV 242**, in LSP 0: Router ID, S and D clear (3.1: "the S-Flag in
  the Router Capability TLV MUST be unset"), with SR-Capabilities (I
  set, V set when `ipv6` is on), SR-Algorithm `[0]`, and the SRLB. One
  per level.
- **Prefix-SID** in each TLV 135 or 236 entry that has a `sid`.
  Algorithm 0.
- **Adj-SID** in each TLV 22 entry to an adjacency that is Up: V and L
  set, a 3-octet label from the SRLB, F set for the IPv6 one. On a LAN,
  LAN-Adj-SIDs in the TLV 22 entry to the DIS, one per neighbor (2.2.2).
- **Leaking and summaries.** When a prefix with a Prefix-SID goes
  between levels (`spf/leak.rb`, `spf/summary.rb`), the sub-TLV goes
  with it (2.1.2), with R set (2.1.1.2), P set and E clear (2.1.1.3:
  "the router MUST set the P-Flag and MUST clear the E-Flag").
- **Adj-SID labels** are kept per adjacency while it is up. P is not
  set, so a restart may change them (2.2.1 allows that).

### Calculation

A new step after each level's SPF. It does not change SPF itself.

1. **Read each node's SR state** from its LSPs: the SRGB from the
   first SR-Capabilities in the lowest-numbered LSP (3.1), the
   algorithms (default `[0]`, 3.2), and its Prefix-SIDs. An SRGB that
   breaks RFC 8660 section 2.3's rules is ignored, and the node counts
   as having none. TLV 242 from a node not reachable at that level is
   not used (RFC 7981 section 3).
2. **Keep who advertised each prefix.** `read_prefixes` today drops the
   advertiser. It keeps it now, with the entry's Prefix-SID. A Prefix-SID
   whose algorithm the node did not advertise is ignored (2.1). One with
   an invalid V and L pair is ignored (2.1.1.1).
3. **For each route with a Prefix-SID, index I:**
   - **In-label**: our SRGB at I (RFC 8660 section 2.4's formula).
   - **For each next-hop adjacency to neighbor N:**
     - N is the advertiser and P is clear: pop (implicit null, label 3).
     - N is the advertiser, P and E set: explicit null (0 for IPv4, 2
       for IPv6).
     - Otherwise: N's SRGB at I. If N has no SRGB, or I is past its end,
       that next hop gets no label (RFC 8660 section 2.10.1). It stays
       for IP, with a warning.
4. **For a local prefix with a SID**: in-label at I, pop and look up IP.
5. **For each Adj-SID of ours**: its label, pop, out its adjacency.

The result is a label table, one entry per in-label:
`{label:, op: :swap | :pop, next_hops: [{adjacency:, out_label:}]}`,
and an out-label per next hop on each IP route.

**Conflicts.** Two prefixes with the same index, or an index past our
SRGB: no label for either, a warning, and an event. RFC 8660 section 2.5
has tie-breaking rules for collisions. Not read in full; see open
questions.

### Forwarding

`Forwarding::Netlink` gets two things:

- **IP routes with a label.** When the next hop has an out-label, the
  route carries `RTA_ENCAP_TYPE` = `LWTUNNEL_ENCAP_MPLS` and `RTA_ENCAP`
  with `MPLS_IPTUNNEL_DST` set to the label. An implicit null means a
  plain IP next hop. Multipath next hops carry their own encap.
- **Label routes.** `AF_MPLS`, `dst_len` 20, `RTA_DST` the in-label,
  `RTA_VIA` the next hop's family and address, `RTA_OIF`, and
  `RTA_NEWDST` the out-label for a swap. For a pop, no `RTA_NEWDST`.
  Protocol 187, as today.

`Forwarding.operations` diffs the label table as it diffs routes, so a
change is a replace and a missing label is a withdraw. The exact octets
are checked against `ip -M route` (iproute2) in a network namespace, as
bgp4r did for `ip route`, before the encoder is written.

**The host.** Label routes need `mpls_router` loaded, and
`net.mpls.platform_labels` above the top of the SRGB and SRLB. Each
interface needs `net.mpls.conf.IF.input=1`. isisd sets the per-interface
ones for its own interfaces. If `platform_labels` is too small, it logs
an error and runs without label routes. The labs set it in the node's
start command. The VMs load the modules at boot from
`/etc/modules-load.d/`.

### API and CLI

- `show.routes` gains `sid` and, per next hop, `label` when set.
- New `show.labels {level}`: the label table, as the kernel should
  have it.
- New `show.segment_routing`: our SRGB, SRLB, Adj-SIDs, and each node's
  SRGB and algorithms per level.
- `show.topology` gains each prefix's `sid` and each node's `srgb`.
- `api.info` lists the new methods. routescope greys what an older
  isisd lacks.
- `isis-cli show labels` and `show segment-routing`.

### The simulator

The simulator's systems use the same originator. Its topology file gets
`sid` per node loopback and an SRGB per node, so it can advertise a grid
of SR nodes. It installs no labels.

### routescope

Its own pull request, after the isis one, in routescope:

- an `mpls_labels` table in the inspector, read from `show.labels` on
  isis4r, `show mpls table json` on FRR, and `ip -M route` on Linux;
- each prefix's SID and each route's label in `isis_routes`;
- the SID on a node's card and on the map.

The FRR command's output is recorded from FRR 10.2.1 into
`test/fixtures/` before the driver reads it.

## Out of scope

Each one later, with its own spec when it comes:

- TI-LFA, and the B flag on Adj-SIDs (P3);
- the Mapping Server and Binding TLV (2.4, 2.5);
- multi-topology, TLVs 235 and 237;
- Flex-Algo and any algorithm but 0;
- SRv6;
- persistent Adj-SIDs across a restart (the P flag);
- SR-LDP interworking;
- BGP-LS SR TLVs (bgp4r, P4).

## Pull requests

One topic each, in this order, in isis:

1. **Codec.** TLV 242, its sub-TLVs, Prefix-SID, Adj-SID and
   LAN-Adj-SID. Hex tests from the RFC layouts and from an FRR 10.2.1
   capture. The TLV document test picks them up. **Built 2026-11-16.**
   As built:
   - `tlv/router_capability.rb` holds TLV 242. Its sub-TLVs are in
     `subtlv/router_capability.rb`, the Prefix-SID in
     `subtlv/extended_ip_reachability.rb` (under 135 and 236), the
     Adj-SIDs beside TLV 22's other sub-TLVs. The flags octet and SID
     field they share are in `subtlv/subtlv.rb`.
   - SID/Label is registered under 149, the registry RFC 8667 section
     2.3 names, and the SRGB and SRLB descriptors read it there.
   - A SID field is read by its length, not by V and L, so an invalid
     pair replays (section 2.1.1.1 leaves ignoring it to the receiver).
   - Flags hash as the RFC's letters, `flags: ["N"]`, with `reserved:`
     only when an unnamed bit arrived set.
   - The test LSP is router a of routescope's `frr-sr` lab,
     `test/fixtures/frr-10.2.1-l2-lsp-sr.hex`. Every SR sub-TLV in it is
     read; TLV 134 stays unknown.
2. **Origination and config.** `router_id`, `segment_routing`, `sid`;
   TLV 242 and the sub-TLVs in our LSPs; leaking rules. Gate: FRR shows
   our SRGB, Node-SID and Adj-SIDs (`show isis segment-routing node`,
   `show isis database detail`).
3. **Calculation and API.** The label table, `show.labels`,
   `show.segment_routing`. Gate: our table matches FRR's
   `show mpls table` on the same topology.
4. **Forwarding.** Netlink label routes and encap. Gate: traffic below.
5. **Simulator.** SIDs and SRGBs in the topology file.

Then routescope's views, and a lab, `isis4r-sr`, in this repository's
`routescope/labs/`.

## Tests

- Codec: hex both ways for each class; an invalid V and L pair kept and
  reported; several SRGB descriptors in order.
- Calculation, from LSPs built in the test:
  - index to label across two SRGB ranges, with RFC 8660 section 2.4's
    formula and RFC 8667 section 3.1's example: index 100 in
    [100-199][1000-1099] is 1000;
  - PHP: pop toward the advertiser; P set keeps the label; E set gives
    explicit null;
  - **a neighbor whose SRGB differs from ours**: the out-label uses the
    neighbor's, not ours;
  - a neighbor with no SRGB: no label on that next hop;
  - ECMP: one out-label per next hop;
  - an algorithm the node did not advertise: SID ignored;
  - a leaked prefix: R and P set, E clear.
- Forwarding: the netlink octets for a push route, a swap and a pop,
  each compared with what `ip -M route` and `ip route ... encap mpls`
  produce in a namespace (needs root, so in the functional suite).
- The full suite: `rake test`.

## Gate

A lab of four routers in a line, one level, with different SRGBs so a
wrong block shows:

```
f1 ---- r1 ---- r2 ---- f2
FRR     isis4r  isis4r  FRR
16000   17000   18000   16000     SRGB start
idx 1   idx 2   idx 3   idx 4     loopback Node-SIDs
```

- f1 pings f2's loopback from its own. On r1, `tcpdump` shows label
  17000+4 coming in and 18000+4 going out. r2 pops (f2 is next, PHP).
  The reply comes back the same way.
- r1 to f2 shows isis4rd pushing; f2 to r2 shows isis4rd receiving with
  PHP.
- r1's `show.labels` matches `ip -M route` in its container, and both
  match f1's view of r1's SID.
- A link flap: labels follow the new path, with none left stale.

The gate passes against FRR 10.2.1, the version on the VM.

## Open questions

1. **Router ID.** Default to the first IPv4 /32 among `prefixes`, or
   require `router_id` when SR is on? The draft defaults.
2. **Label collisions.** RFC 8660 section 2.5 has tie-breaking rules.
   The draft drops both sides with a warning. Read 2.5 and decide before
   PR 3.
3. **Label routes per level.** A prefix both levels reach gets one label
   route, from the level the IP route uses (Level 1 first, as
   `netlink.rb` already does for IP, with a lower kernel metric). Whether
   the kernel orders `AF_MPLS` routes by metric too is not checked. If
   not, isisd picks the level itself.
4. ~~SRLB use.~~ Answered 2026-11-16: FRR 10.2.1 takes Adj-SIDs from
   its SRLB (15000 and up with `local-block 15000 15999`). Recorded in
   routescope `test/fixtures/frr/sr-mpls/`.

## Measured on FRR 10.2.1

Three FRR routers in a line, a, b and c, with SRGBs 16000, 18000 and
20000 (routescope `test/fixtures/frr/sr-mpls/`, 2026-11-16):

- a pushes 18003 toward c: c's index 3 in b's SRGB. b pops it (PHP). A
  ping from a's loopback to c's passes. This is the calculation above.
- FRR does not install a label for its own Node-SID. With PHP, no
  neighbor sends it one. Step 4 of the calculation may be dropped to
  match; it matters only when a neighbor sets P.
- FRR sets both I and V in SR-Capabilities on an IPv4-only router, and
  advertises a TE Router ID (TLV 134) equal to TLV 242's Router ID.
- FRR's kernel routes use next-hop objects (`nhid`). The label sits on
  the next hop, and `ip -j route` still shows it as `encap`.
