# Flexible algorithm in isis4rd

Status: approved by the owner, 2026-11-25, with the answers in
"Decisions", at the end. No question stays open.

This is P9 in routescope's `docs/protocol-coverage.md`: "Application-
specific link attributes, then the Flexible Algorithm Definition, its
SIDs and an SPF per algorithm, and TI-LFA per algorithm." The order of
the work there is P5, P9, P6, P7, P8. Flex-algo comes before SRv6 (P6),
because SRv6 deployments lean on it. OSPF comes after P7, and is not in
this document.

The RFCs read for it are in `specs/rfc/`, a local folder that is not
committed: 9350, 9479, 9855, 8667, 8402, 8570, 7308, 7981, 5305 and
9843. Every section cited below was read there.

## The problem

isisd computes one shortest path tree per level, on the IGP metric. SR
runs on algorithm 0 only. An operator cannot ask for a path on lowest
delay, or a path that avoids some links, and still use plain
Prefix-SIDs.

Flex-algo gives that. A router advertises a definition: a metric type,
a calculation type and a set of constraints, under a number from 128 to
255. Every router that takes part computes a tree for that number on
that definition. Each prefix can carry one Prefix-SID per algorithm. A
packet that carries the algorithm's label follows the algorithm's path.

We want isisd to:

- advertise link attributes for flex-algo, as RFC 9479 asks;
- advertise and select Flexible Algorithm Definitions (FADs), as RFC
  9350 asks;
- take part in an algorithm, with Prefix-SIDs for it;
- compute a tree and a label table per algorithm, and install the
  labels;
- compute TI-LFA backups per algorithm, on the algorithm's constraints;
- interoperate with FRR, which does the same.

## The terms, in short

A reminder, not a definition. From RFC 9350 sections 3 to 5 and RFC
9479 section 4.

- **Flex-Algorithm**: a number from 128 to 255 (9350 section 4).
- **FAD**: Flexible Algorithm Definition. A calculation type, a metric
  type and constraints (section 4). In IS-IS, sub-TLV 26 of the Router
  Capability TLV 242 (section 5.1).
- **Winning FAD**: the FAD every router selects for an algorithm: the
  highest priority, then the highest System ID (section 5.3).
- **Participation**: a router takes part in algorithm K for SR when it
  lists K in its SR-Algorithm sub-TLV (section 11.1).
- **Color**: one bit of an Admin Group or an Extended Admin Group (EAG)
  (section 13). Bit 0 is the least significant bit (RFC 5305 section
  3.1; RFC 7308 section 2.2).
- **ASLA**: Application-Specific Link Attributes. Sub-TLV 16 under TLV
  22, with a bit mask that names the applications that use the values
  (9479 section 4.2). Flex-algo is bit 3, the X bit (9350 section 12).

## What the RFCs ask

### RFC 9479, link attributes per application

- The bit mask (section 4.1): a SABM length octet with the L flag, a
  UDABM length octet, then the two masks, each 0 to 8 octets. Bits are
  sent from bit 0, the most significant bit of the first octet. So R is
  0x80, S 0x40, F 0x20, and flex-algo's X is 0x10.
- Sub-TLV 16 under TLV 22 (section 4.2): the mask, then sub-sub-TLVs in
  the same formats as the legacy sub-TLVs, under the same numbers
  (section 7.3, Table 5). The ones flex-algo needs: 3 Admin Group, 14
  Extended Admin Group, 18 TE Default Metric, 34 Min/Max Unidirectional
  Link Delay.
- A SABM or UDABM length over 8: "the entire sub-TLV MUST be ignored".
- L flag set: the applications in the mask use the legacy sub-TLVs of
  the link, and the sub-sub-TLVs in this ASLA "MUST be ignored on
  receipt".
- Conflicting values for one application, attribute and link: "the
  first advertisement received in the lowest-numbered" LSP is used.
- L flag not the same in all sub-TLVs for one application and link: "the
  L-flag MUST be considered set".
- A zero-length mask: its values are used by an application only when
  no ASLA with that application's bit gives the attribute for the link.
- TLV 238, Application-Specific SRLG (section 4.3): the neighbor's
  System ID and pseudonode, the mask, link identifier sub-TLVs, then
  SRLG values of 4 octets. At least one set of link identifiers.

### RFC 9350, the FAD and the calculation

- **The FAD sub-TLV** (section 5.1): type 26 under TLV 242. Algorithm,
  metric type, calculation type, priority, then sub-sub-TLVs. Metric
  type 0 is the IGP metric, 1 the minimum unidirectional link delay (RFC
  8570 section 4.2), 2 the TE default metric (RFC 5305 section 3.7).
  Both 1 and 2 are read from ASLA. The Router Capability TLV that
  carries a FAD "MUST have the S bit clear".
- **Scope** (section 5.1): area or level. An L1/L2 router MAY copy the
  winning Level 2 FAD into Level 1. It "MUST NOT" copy from Level 1 to
  Level 2.
- **Selection** (section 5.3): an algorithm outside 128 to 255 is
  ignored. Highest priority wins, then highest System ID. A router that
  does not take part ignores the FADs for that algorithm.
- **Unsupported FAD** (section 5.3): if there is no FAD, or the winning
  FAD has a calculation type, metric type, constraint, flag or
  sub-sub-TLV the router does not support, it "MUST stop participating".
  It withdraws K from SR-Algorithm and removes the algorithm's
  forwarding state.
- **Sub-sub-TLVs** (section 6): 1 Exclude Admin Group, 2 Include-Any, 3
  Include-All, 4 Flags (bit 0 is M), 5 Exclude SRLG. The admin groups
  use the EAG format; lengths are multiples of 4. Types 1 to 4 twice in
  one FAD: the FAD is ignored. Twice across split FADs from one system:
  the first in the lowest-numbered LSP. Type 5 may repeat across split
  FADs; the receiver uses the union. An unknown flag bit stops
  participation (section 6.4).
- **Split FADs** (section 6): a FAD may span several sub-TLVs. The fixed
  part must match. If it differs, the first in the lowest-numbered LSP
  wins.
- **FAPM** (section 8): sub-TLV 6 under TLVs 135, 235, 236 and 237. An
  algorithm and a 4-octet metric. The first for an algorithm counts.
  Over MAX_PATH_METRIC: the prefix is not considered for that algorithm.
  On intra-area routes it is ignored (section 13.1).
- **Link attributes** (section 12): flex-algo "MUST use" ASLA with the
  X bit, unless the L flag is set, then the legacy sub-TLVs. A receiver
  "MUST accept both" Admin Group and Extended Admin Group.
- **The calculation** (section 13): prune nodes that do not take part
  (SR "MUST use such pruning"). Prune links, in order: an excluded
  color; an excluded SRLG; no include-any color; not every include-all
  color; a metric the definition needs and the link does not advertise
  ("A metric of value 0 MUST NOT be assumed"). Use the definition's
  metric type and calculation type. The two-way check is the base one:
  "The result of the existing Flex-Algorithm-agnostic, two-way
  connectivity check is used".
- **Between levels** (section 13.1): with the M flag, the FAPM is the
  metric for inter-area prefixes, and a prefix without one is
  unreachable for that algorithm. Without M, the base metric is used,
  and that is "NOT RECOMMENDED". A path metric over 32 bits is
  0xFFFFFFFF.
- **Forwarding** (section 14.1): the path is installed "using the MPLS
  label that corresponds to the Prefix-SID that was advertised for that
  Flex-algorithm". No Prefix-SID for the algorithm: no forwarding entry.
  With no path, traffic "MUST be dropped". LFA paths use the same
  constraints and only the algorithm's Prefix-SIDs, and no Adj-SID of a
  pruned link.
- **Last resort** (section 15.3): a delay or TE metric of 2^24 - 1 makes
  the link a link of last resort, not an unusable one.

### RFC 9855 section 8, TI-LFA per algorithm

TI-LFA for a flex-algo "MAY" be supported. If it is, the P-space, the
Q-space and the post-convergence path "SHOULD" all come from the
algorithm's constrained SPF. The repair list "SHOULD only use
Node-SIDs/Adj-SIDs bound to the Flexible Algorithm and/or unprotected
Adj-SIDs of the regular SPF".

### RFC 8667 and RFC 8402, SIDs per algorithm

- A Prefix-SID's algorithm "MUST be set to 0 or to any value advertised
  in the SR-Algorithm sub-TLV". A receiver ignores a Prefix-SID for an
  algorithm its originator did not advertise (8667 section 2.1).
- Algorithm 0 must be in SR-Algorithm when the sub-TLV is sent (8667
  section 3.2). It is level scoped, S clear.
- One prefix may carry several Prefix-SIDs "so long as the tuple
  <prefix, topology, algorithm> is unique" (8402 section 3.1).

### Not in this document

RFC 9843 (2025) updates 9350 with a bandwidth metric type and bandwidth
constraints. It is left for later. isisd stops participating in a FAD
that uses them, as section 5.3 asks.

## What exists

Measured from the code at isis master `5e9ee45`, 2026-11-25.

- **SR is algorithm 0 only.** `Spf::Calculation#prefix_sid` takes "An
  entry's Prefix-SID for algorithm 0, the only one computed here"
  (`lib/isis/spf/spf.rb`). `Spf::Labels#node_sid` takes the first
  Prefix-SID with `algorithm.zero?` (`lib/isis/spf/labels.rb`).
- **SR-Algorithm is read, and sent as [0].** `SubTlv::SrAlgorithm`
  (`lib/isis/subtlv/router_capability.rb`) holds a list. `Labels` reads
  it per node, defaulting to `[0]`. `Validation`'s
  `:algorithm_not_advertised` already drops a Prefix-SID for an
  algorithm its node does not list.
- **One tree per level.** `Spf::Calculation` runs RFC 1142 Annex C.2 on
  the default metric. `MAXIMUM_PATH_SPLITS = 2`, from RFC 1142's
  `maximumPathSplits-Default`. `MAX_PATH_METRIC = 0xFE000000` and
  `MAX_LINK_METRIC = 0xFFFFFF`, from RFC 5305 section 3.
- **Parallel links are folded.** `Calculation#read_links` keeps, per
  neighbor, the lowest metric of all TLV 22 entries. Flex-algo prunes
  per link, so it must prune before this fold.
- **The two-way check reads the same links.** `extend_from` requires
  `links(n)&.key?(node)`. For an algorithm, RFC 9350 section 13 asks for
  the base check, so the back link must be looked up in algorithm 0's
  links, not in the pruned ones.
- **TI-LFA** is `Spf::Graph` (`graph.rb`), `Spf::TiLfa` (`ti_lfa.rb`)
  and `Spf::Backups` (`backups.rb`). `Graph.from_database` reads every
  link, each Node-SID with N set, and each Adj-SID with F clear. It does
  not look at the Adj-SID's B flag. It keeps one Adj-SID per [from, to]:
  the first found. isisd's own Adj-SIDs have B clear
  (`database/segment_routing.rb`).
- **TE sub-TLVs under TLV 22**: 6 (IPv4 interface address), 8 (IPv4
  neighbor address), 31 (Adj-SID), 32 (LAN-Adj-SID)
  (`lib/isis/subtlv/extended_is_reachability.rb`). No Admin Group, no
  EAG, no TE metric, no delay, no ASLA, no SRLG TLV. Anything else is
  kept as `SubTlv::Unknown`.
- **Prefix sub-TLVs**: only Prefix-SID (3) under TLVs 135 and 236.
- **Validation and faults.** `lib/isis/validation.rb` holds eight SR
  rules. `lib/isis/fault.rb` holds four groups: SR codec cases, TI-LFA
  topologies, TI-LFA packets and behaviours (`flap`, `stale_lsp`,
  `srgb_change`). `isis4r-sim` serves them over HTTP with `/api/fault`.
- **API**: `show.segment_routing`, `show.labels`, `show.topology`,
  `show.ti_lfa`, `policy.ti_lfa`, `link.metric`, among others
  (`lib/isis/daemon/api.rb`).

## Measured on FRR 10.7.1

FRR 10.7.1 is the release isis's labs use today (`isis4r-tilfa`). I ran
it alone in a container on ospflab, 2026-11-25, `quay.io/frrouting/
frr:10.7.1`, `FRRouting 10.7.1_git (f3e3c8b9d984)`.

- It takes `flex-algo 128` under `router isis`, with
  `advertise-definition`, `metric-type delay`, `priority 200`,
  `affinity exclude-any red` and `dataplane sr-mpls`, an `affinity-map`,
  and `segment-routing prefix ... algorithm 128 index 101`.
- It advertises the FAD in its LSP. `show isis database detail` prints:

  ```
  Router Capability: 10.255.0.1 , D:0, S:0
    Segment Routing: I:1 V:1, Global Block Base: 16000 Range: 8000
    SR Local Block Base: 15000 Range: 1000
    SR Algorithm:
      0: SPF
    Flex-Algo Definition: 128
      Metric-Type: 1
      Calc-Type: 0
      Priority: 200
      Exclude-Any: 0x00000002
      Include-Any: not-set
      Include-All: not-set
      M-Flag: 0
  ```

- Alone, it did not list 128 in SR-Algorithm, did not advertise the
  algorithm 128 Prefix-SID, and `show isis flex-algo` said "Source: Not
  found" for the elected FAD.

Then two FRR routers with a link between them, 2026-11-25, captured on
the wire (`test/fixtures/frr-10.7.1-l2-lsp-flex-algo.hex`):

- With `affinity` bit positions 1, 32 and 40, it sent the Extended
  Admin Group `0e08 00000002 00000101`: groups numbered by 32-bit word.
- It sent the legacy sub-TLVs and an ASLA sub-TLV with X set, and also
  a UDABM of 0x10. The ASLA held the EAG, the TE metric and the delay.
- With `delay 5000`, it sent only sub-TLV 33, the average delay. RFC
  9350 metric type 1 reads the minimum, sub-TLV 34. With `delay 5000
  min 4000 max 6000`, it sent both 33 and 34. The lab's FRR router
  needs the second form.
- With a neighbor, at Level 2, it still elected no FAD ("Source: Not
  found").

The routescope flex-algo views session measured further, with five FRR
10.7.1 routers, 2026-11-25 (routescope `docs/design/flex-algo-views.md`,
its appendix):

- FRR elects a FAD at Level 1 only. At Level 2 it elects none.
- Only FADs with the IGP metric run. A FAD with `metric-type delay` or
  `metric-type te` is elected, then disabled as an "unsupported
  definition", and FRR withdraws it from SR-Algorithm (9350 section
  5.3).
- The same with `delay N min N max N` on every link: the LSPs carried
  the Min/Max delay, in ASLA too, and the delay FAD was still disabled.
  So it is not the missing sub-TLV 34.
- FADs show in text only, not in JSON.

So FRR 10.7.1 can carry an IGP-metric algorithm at Level 1, and nothing
more. The lab is planned with that in mind ("Labs").



## The design

### Wire format

New codec classes, each built four ways, with `encode`, `parse`,
`to_hash`, `to_s` and an entry in `test/unit/to_hash_catalog.rb`:

| Where | Type | Class | RFC |
| --- | --- | --- | --- |
| TLV 22 | 3 | `AdminGroup`, a 4-octet mask | 5305 3.1 |
| TLV 22 | 14 | `ExtendedAdminGroup`, multiples of 4 octets | 7308 2.1 |
| TLV 22 | 18 | `TeDefaultMetric`, 24 bits | 5305 3.7 |
| TLV 22 | 33 | `LinkDelay`, A bit, the average in µs | 8570 4.1 |
| TLV 22 | 34 | `MinMaxLinkDelay`, A bit, min and max in µs | 8570 4.2 |
| TLV 22, 238 | 4 | `LinkIdentifiers` | 5307 1.1 |
| TLV 22, 238 | 12, 13 | `Ipv6InterfaceAddress`, `Ipv6NeighborAddress` | 6119 4.2, 4.3 |
| TLV 22 | 16 | `Asla`: the bit mask, then sub-sub-TLVs from its own registry | 9479 4.1, 4.2 |
| top | 138 | `Tlv::Srlg` (GMPLS-SRLG) | 5307 |
| top | 238 | `Tlv::AslaSrlg` | 9479 4.3 |
| TLV 242 | 26 | `Fad`, with sub-sub-TLVs 1 to 5 | 9350 5.1, 6 |
| TLV 135, 236 | 6 | `Fapm` | 9350 8 |

The ASLA sub-sub-TLVs reuse the legacy classes, registered a second
time under `Asla`'s registry with the same numbers (9479 section 7.3).
The `Fad` sub-sub-TLVs get a registry of their own. An unknown
sub-sub-TLV is kept as `Unknown` and replayed, as everywhere.

A wrong length is kept, as the codec keeps it today. Building never
validates.

As built in step 1: 33, 4, 12 and 13 were added to the plan. FRR sends
33 (below), and TLV 238's link identifiers (9479 section 4.3, Table 2)
are 4, 6, 8, 12 and 13. Groups past 31 are numbered by 32-bit word:
group 32 is the low bit of the second word. RFC 7308 section 2.2's
example can be read otherwise; FRR numbers by word.

### Configuration

```yaml
affinity_map:                 colors by name; bit 0 is the least
  red: 1                      significant (RFC 5305 3.1, RFC 7308 2.2)
  blue: 2
flex_algo:                    the algorithms this system takes part in;
  - algorithm: 128            needs segment_routing
    advertise: true           send the FAD; false: take part only
    priority: 128             0 to 255
    metric_type: delay        igp, delay or te
    exclude_any: [red]
    include_any: []
    include_all: []
    exclude_srlg: []
prefixes:
  - prefix: 10.255.0.1/32
    sid: 1                    algorithm 0, as today
    algorithm_sids:           one index per algorithm
      128: 101
interfaces:
  - name: eth1
    affinity: [red]
    delay: 5000               µs, sent as min and max
    te_metric: 100
    srlg: [10]
```

An unknown key is refused, as today. An algorithm outside 128 to 255 is
refused. A color not in `affinity_map` is refused. `algorithm_sids`
names only algorithms in `flex_algo`. The M flag is not configurable
until the step that builds it.

### Origination

- **Link attributes.** For each interface with `affinity`, `delay`,
  `te_metric` or `srlg`, one ASLA sub-TLV with the X bit only, L clear.
  Affinity goes as an Extended Admin Group. SRLGs go in TLV 238 with the
  X bit, the link identified by its IPv4 addresses. No legacy sub-TLVs:
  9479 section 6.1 says new applications "MUST NOT make use of legacy
  advertisements", and nothing in isisd uses them.
- **FAD.** For each `flex_algo` entry with `advertise`, one FAD sub-TLV
  in a TLV 242 with S clear, at each level. Split across sub-TLVs only
  when one is over 255 octets.
- **Participation.** SR-Algorithm lists 0, then each algorithm whose
  winning FAD isisd supports (section 5.3). An algorithm stops being
  listed when its winning FAD becomes unsupported or disappears, and is
  listed again when it is fixed.
- **Prefix-SIDs.** One Prefix-SID per `algorithm_sids` entry, with the
  same flags as the algorithm 0 SID, only while isisd takes part in that
  algorithm (8667 section 2.1: "MUST be set to 0 or to any value
  advertised").

As built in step 2: the delay goes as Min/Max (34), min and max the
same, and as the average (33) too, as FRR 10.7.1 sends a link with
`delay N min N max N`. A group is 0 to 1023: FRR 10.7.1's
`affinity-map` takes bit position 1023 and refuses 1024. A delay or TE
metric is 24 bits. `srlg` needs `ip_addresses`, since TLV 238 names the
link by them; past 58 SRLGs it takes a second TLV 238. The interfaces'
attributes are checked as the file is read; `link.attributes`, to
change them while isisd runs, is not built yet.

Participation depends on the database, so a change of winning FAD
regenerates the LSP. The LSP generation timer covers it.

### Selection

`Spf::FlexAlgo`, one per level, recomputed when the database changes:

1. Collect every FAD of the level: from LSPs with Number 0 present,
   each system's sub-TLVs merged by section 6's rules.
2. For each configured algorithm, the winner: highest priority, then
   highest System ID.
3. Supported or not: calculation type 0; metric type 0, 1 or 2; flags
   none set (M only once the M flag is built, later); sub-sub-TLVs 1, 2, 3, 5 and
   4. Anything else: not supported, with the reason kept for the view.

A Level 1 copy of the Level 2 winner (section 5.1, "MAY") is not built
(decision 5).

As built in step 4: `Spf::FlexAlgo` runs after each SPF run, in the
Decision Process. This system's own FADs come from its configuration,
not its LSP, so it takes part from its first LSP. `FlexAlgoConfig`
reads and checks `flex_algo` and `algorithm_sids`; `advertise` is true
by default and `priority` 128. FADs that do not fit in the first TLV
242's 255 octets go in a second TLV 242. `policy.flex_algo` changes a
configured algorithm only; adding or removing one needs a restart.
`Router.symbolize` now keeps a numeric key, since YAML reads
`algorithm_sids: {128: 101}` with one; before, such a file crashed
isisd. Not yet checked against FRR: that is step 7's, with the lab's.

### Calculation

An algorithm's tree comes from the same `Spf::Calculation`, given a
**link reader** and a **node filter**:

- The node filter keeps a node when its SR-Algorithm lists the
  algorithm, and keeps this system. A pseudonode is kept; a LAN is a
  link, not a router.
- The link reader reads each TLV 22 entry on its own, before the fold
  to one metric per neighbor. It applies section 13's five rules in
  order. The attributes come from one helper, `Spf::LinkAttributes`,
  which applies 9479's rules for the X bit: an ASLA with X; else, with
  L set, the legacy sub-TLVs; else a zero-length mask's values; else
  none.
- The metric is the IGP metric, the min delay, or the TE metric, as the
  FAD says. A link without the needed metric is pruned. An IGP metric
  of 0xFFFFFF is still not used (RFC 5305). A delay or TE metric of
  2^24 - 1 is used, as a last resort (9350 section 15.3).
- The two-way check looks for the back link among algorithm 0's links.
- `MAXIMUM_PATH_SPLITS` and `MAX_PATH_METRIC` apply as for algorithm 0.
- Prefixes: a node's prefixes that carry a Prefix-SID for the
  algorithm, at their base metric. Intra-level only, until the M flag
  step.

The output is routes keyed by prefix, as today, for the label table
only. **No IP route comes from an algorithm.** IP traffic stays on
algorithm 0. Steering IP into an algorithm (BGP color, an SR policy) is
outside this document.

As built in step 2: `Spf::LinkAttributes` reads one node's LSPs. A
link is a TLV 22 entry, keyed by its neighbour and its first sub-TLVs
6, 8, 4 and 12, so parallel links stay apart and entries of one link
in several fragments join. A conflict is two values that differ, among
the ASLA sub-TLVs with X, or among the zero-length ones. With both an
Admin Group and an EAG, the AG gives groups 0 to 31 and the EAG the
rest (RFC 7308 section 2.3.1). The ASLA sub-TLV's L flag does not reach
SRLGs, which are not among its sub-sub-TLVs; TLV 238's own does. A TLV
238 is matched to a link by its neighbour and any identifier they
share. `show.topology` uses it now; the calculation will in step 5.

A property for the tests: a FAD with metric type 0 and no constraints,
with every node taking part, gives the same next hops as algorithm 0,
on any topology. It runs on the same 300 random topologies as TI-LFA's.

As built in step 5: `Spf::Calculation` takes `algorithm:` and
`definition:`, the winning FAD. A system's participation is the first
SR-Algorithm sub-TLV in its lowest-numbered LSP; none is no
participation. The RFC says nothing of a pseudonode's links: they carry
no attributes, so they are taken at their metric, 0, without the rules;
the router's link to the pseudonode carries the attributes and the
cost. This system's first hop is its own link as its LSP gives it, not
the circuit's metric: on a point-to-point circuit the TLV 22 entry to
the neighbour, matched by the neighbour's address when the entry names
it; on a LAN, its entry to the pseudonode that lists the neighbour. A
prefix with the up/down bit is left out, and no default route is
added toward an attached system: inter-level waits for the M flag.
Each link pruned is kept with its rule (`Calculation#pruned`), so a
test can see the rules' order. The Decision Process runs one
calculation per algorithm this system takes part in, after selection,
in algorithm order; a change of one of its routes is an event of kind
`flex_algo_route`, at info. The property holds on 300 random
topologies, of 3 to 12 systems (`test/unit/spf/flex_algo_calculation_test.rb`).
The catalog's topology cases are `Fault::FLEX_ALGO_TOPOLOGIES`, a group
of their own; `fa_ti_lfa_constraint` is step 6's. Not yet checked
against FRR: that is step 7's.

### Labels and forwarding

`Spf::Labels` gains an `algorithm`. For algorithm K it reads the
Prefix-SIDs for K, and the in-label is K's index in this system's
SRGB. The out-label uses the next hop's SRGB, as for algorithm 0. PHP,
explicit null and the validation rules are unchanged.

A prefix unreachable in K gets no label route, so a packet with K's
label is dropped: 9350 section 14.1 asks that. The forwarding adapter
installs label routes as today; each entry gains its algorithm.

`Validation`'s `:prefix_sid_duplicate` checks indexes across all
algorithms: an index names one label in each SRGB, whatever the
algorithm. A second Prefix-SID for the same prefix and algorithm is a
finding too (8402 section 3.1).

As built in step 5: `Spf::Labels` takes `algorithm:`, and `build`
takes `taken:`, the indexes the tables built before it use. Algorithm
0's table is built first, then each flex-algo's in order. An index one
of them already uses, with or without a label route here, is a
`:prefix_sid_duplicate` finding that names the one left out, and the
table built first keeps it; inside one table both are left out, as
before. A flex-algo's table has no Adj-SID entries: they are algorithm
0's. `Forwarding::LabelTable#update` takes the flex-algo tables beside
algorithm 0's and installs them through the same adapter.
`show.labels` gives each entry's `algorithm`; `show.flex_algo` gives
each algorithm's `routes`, its prefixes with their metric and next
hops, since no IP route shows them. Measured in network namespaces on
ospflab, Linux 7.0, 2026-11-25 (`test/interop/kernel_flex_algo_test.rb`):
three isisd in a line, S installs 17103, D's index 103 for 128, swapped
to A's 18103; with D's FAD changed to include only red, a color no link
has, S withdraws 17103 and keeps algorithm 0's 17003.

### TI-LFA per algorithm

`Spf::Graph.from_database` gains the algorithm. For algorithm K:

- The links and nodes are K's, after the same pruning as the
  calculation, at K's metric.
- Node-SIDs are K's: the Prefix-SID for K with N set.
- Adj-SIDs only of links that survive K's pruning. Where two parallel
  links join one pair, the Adj-SID of a surviving one.
- Adj-SIDs with B clear only (RFC 9855 section 8, "unprotected").

`Spf::TiLfa` and `Spf::Backups` are unchanged: they work on whatever
graph they are given. A route of algorithm K's label table gets a
backup when the interface has `ti_lfa`. The `ti_lfa` key stays one per
interface, for all algorithms. 9350 section 14.1 says every router
taking part "SHOULD advertise at least one Flex-Algorithm-specific
Node-SID". Without one, a repair through that router cannot be built,
and the backup says why.

As built in step 6: `Graph.from_database` and `Spf::Backups` take
`algorithm:` and `definition:`. The graph reads the database through
the same `Calculation` as the algorithm's tree, so the node filter, the
five rules and the metric are one code path; `Calculation#kept?` says
whether one TLV 22 entry survives, for its Adj-SIDs. `Spf::TiLfa` is
unchanged, and its `:no_sid` is the reason a repair through a system
without the algorithm's Node-SID is unprotected. The Decision Process
computes each algorithm's backups after its label table, when any
interface has `ti_lfa`, and logs a change as algorithm 0's, kind
`:ti_lfa`, with the algorithm. `show.ti_lfa` gives a row per protected
interface and algorithm, with `algorithm`, and its trees and
milliseconds count every algorithm; a flex-algo label row carries its
backup as algorithm 0's does. As for algorithm 0, the label routes'
backups are computed and shown, not installed: that waits for
routescope's TI-LFA step 2c. `fa_ti_lfa_constraint` is in
`Fault::FLEX_ALGO_TOPOLOGIES`: the repair goes by B in 128, where
algorithm 0's goes by A over a red link. Not yet checked against FRR:
that is step 7's.

### API and CLI

- `show.flex_algo`: per level, per configured algorithm: the winning
  FAD, its originator, supported or the reason it is not, taking part
  or not, and the FADs that lost.
- `show.labels`: each entry gains `algorithm`.
- `show.topology`: each link gains `affinity`, `delay`, `te_metric` and
  `srlg`, as advertised. Each node gains its `algorithms`.
- `show.ti_lfa` and the backups: each gains `algorithm`.
- `policy.flex_algo`: change a FAD while isisd runs (priority,
  constraints, metric type), for scenarios. Checked as the file is.
- `link.attributes`: change an interface's affinity, delay or TE metric
  while isisd runs, as `link.metric` does for the metric.
- `isis-cli`: `show isis flex-algo`, and the algorithm in the label and
  topology views.

New fields are added; none is renamed or removed.

### routescope

What routescope shows is a routescope specification of its own,
`docs/design/flex-algo-views.md` there, written after this one is
approved. It is not written here. What it will cover, from P9's row in
`docs/protocol-coverage.md`:

- the algorithm in the SR columns and the label table;
- a path per algorithm on the map, with the algorithm picked;
- the FADs and which one won;
- link attributes on the map's links;
- scenario conditions and MCP actions for the views and the policy.

routescope's vocabulary (`rake vocabulary`) picks up the new fields
once its driver reads them.

## Built to the conventions

Following routescope `docs/design/protocol-conventions.md`, as TI-LFA
did.

### 1. The codec

The classes above, four ways in, five ways out, in the `to_hash`
catalog. `docs/building-objects.md` gains a section on the ASLA
sub-TLV, since its sub-sub-TLVs are the legacy classes under a second
registry.

### 2. Validation on receive

New rules in `lib/isis/validation.rb`. Each is a finding with its
clause and its action per policy (`:rfc`, `:strict`, `:lenient`):

| Finding | Clause | `:rfc` action |
| --- | --- | --- |
| `fad_algorithm_range` | 9350 5.3, outside 128 to 255 | ignore the FAD |
| `fad_subtlv_twice` | 9350 6.1 to 6.5, one sub-sub-TLV twice in one FAD | ignore the FAD |
| `fad_split_differs` | 9350 6, fixed parts differ | use the first in the lowest LSP |
| `fad_split_subtlv_twice` | 9350 6.1 to 6.4, across split FADs | use the first in the lowest LSP |
| `fad_s_bit` | 9350 5.1, FAD in a TLV 242 with S set | ignore the FAD and report (decision 6) |
| `fad_eag_length` | 9350 6.1 to 6.3, not a multiple of 4 | ignore the FAD and report (decision 6) |
| `fad_unsupported` | 9350 5.3, calc type, metric type, flag or sub-sub-TLV not supported | stop taking part |
| `fapm_algorithm_range` | 9350 8 | ignore the FAPM |
| `fapm_twice` | 9350 8, same algorithm twice | use the first |
| `fapm_too_large` | 9350 8, over MAX_PATH_METRIC | prefix not in that algorithm |
| `fapm_intra_area` | 9350 13.1 | ignore the FAPM |
| `asla_mask_too_long` | 9479 4.2, SABM or UDABM over 8 | ignore the sub-TLV |
| `asla_l_flag_values` | 9479 4.2, L set and values present | ignore the values |
| `asla_l_flag_mixed` | 9479 4.2, L differs for one application | L set |
| `asla_conflict` | 9479 4.2, two values for one application and link | use the first in the lowest LSP |
| `asla_srlg_no_link_id` | 9479 4.3, no link identifier, or one twice | ignore the TLV |
| `prefix_sid_algorithm_twice` | 8402 3.1, one prefix and algorithm, two SIDs | use the first and report (decision 7) |

As built in step 2: one finding more, `admin_group_mismatch` (RFC 7308
section 2.3.1, "SHOULD report this mismatch"), since the reader needs
the rule anyway. Each ASLA finding's actions under the three policies
are in `docs/protocol-testing.md`. The findings are listed per node in
`show.topology`, as `link_findings`.

As built in step 3: `fapm_too_large` and `fapm_intra_area` are not
findings. Section 8 and section 13.1 say what a receiver does with such
a FAPM, but no clause forbids sending one, and `docs/protocol-testing.md`
keeps findings for what a sender broke, as it does for an index past
the SRGB. The calculation leaves such a prefix out, or the FAPM unused,
once the M flag is built. `fad_eag_length` covers section 6.5's SRLG
list too, which "MUST be a multiple of 4 octets" as the admin groups
must. `fad_subtlv_twice` covers types 1 to 5, as sections 6.1 to 6.5
each say; `fad_split_subtlv_twice` types 1 to 4, since 6.5 lets the SRLG
list repeat. The FAD findings come from `Spf::Definitions`, which reads
one system's FADs and merges those split across sub-TLVs, the first
step of "Selection"; the FAPM and Prefix-SID findings from
`Spf::PrefixMetrics`. `fad_unsupported` comes with each Definition
isis4r cannot run, with the reason; until the M flag is built, a FAD
with M set is one.

`:algorithm_not_advertised` already covers a Prefix-SID for an
algorithm its node does not list.

### 3. Negative tests: the fault catalog

`lib/isis/fault.rb` gains:

- **Codec cases**, one per finding above, built on the SR case's
  helper. As built in step 2: the ASLA cases are a group of their own,
  `Fault::FLEX_ALGO_CATALOG`, held to their findings as the SR cases are.
  They join the fault matrix against FRR in step 7. Step 3 adds the FAD,
  FAPM and Prefix-SID cases to the same group.
- **Topology cases**, like TI-LFA's, each a small graph with the paths
  the RFC expects: `fa_exclude_any`, `fa_include_any`, `fa_include_all`,
  `fa_exclude_srlg`, `fa_delay`, `fa_te_metric`, `fa_link_no_metric`
  (pruned, not 0), `fa_last_resort` (2^24 - 1 still used),
  `fa_node_not_participating` (pruned), `fa_one_way` (base two-way
  check), `fa_priority`, `fa_system_id_tie`, `fa_no_fad` (no
  participation), `fa_partition` (no path, no label route),
  `fa_ti_lfa_constraint` (the repair avoids an excluded link that
  algorithm 0's repair would take).
- **Behaviours** for `isis4r-sim`: `fad_takeover` (a higher priority FAD
  appears, then goes), `participation_flap` (a simulated system drops
  the algorithm from SR-Algorithm, then lists it again),
  `delay_change` (a link's delay rises past another path's, then falls).

A unit test holds the catalog and `validation.rb` to each other, as
today.

### 4. The injector

`isis4r-sim`'s topology file gains the same keys as isisd: per router
`flex_algo`, `algorithm_sids`; per link `affinity`, `delay`,
`te_metric`, `srlg`; and a top `affinity_map`. `/api/fault` serves the
new entries. The behaviours run under `/api/behave`, as `flap` does
today. They become `sim:` steps and MCP actions in routescope, as
TI-LFA's step 6e2 did.

As built in step 7, which is three pull requests: 7a, the injector;
7b, the interop and the topologies in the fault matrix, against FRR in
network namespaces; 7c, the codec entries in the fault matrix.
7a: the topology file takes `affinity_map`, a router's `flex_algo` and
`algorithm_sids` (its loopback's), and a link's `affinity`, `delay`,
`te_metric` and `srlg`, checked as isisd checks them. A simulated
system lists every algorithm of its `flex_algo` in SR-Algorithm,
whatever FAD wins, since a simulator sends what it is told. A link with
`srlg` gets IPv4 addresses, 198.18.0.0 + 4N + 1 and + 2, for TLV 238.
The simulator's own end of a link to a simulated system carries the
link's attributes. `/api/catalog` lists the flex-algo codec entries
beside the SR ones, and `/api/fault` injects them. The three behaviours
end on their own after `hold`, or after `count` flaps for
`participation_flap`; `behave_stop` undoes them early.

7b, against FRR 10.5.1, the release the interop jobs install, at Level
1 (measured 2026-11-26):

- `test/interop/frr_flex_algo_test.rb`, isisd and FRR on one link. Each
  reads the other's FAD, and both elect the same winner, FRR's at
  priority 200 and then isisd's at 250. Each installs the other's
  Prefix-SID for 128 as a label route that pops toward it. Each reads
  the other's link attributes. FRR sends them twice, as legacy
  sub-TLVs and in an ASLA with X whose user-defined mask is 0x10.
  isisd sends only the ASLA, and FRR prints it as X alone.
- FRR 10.5.1 sends no link attributes unless `mpls-te on` is set. It
  takes `link-params` only through mgmtd. zebra drops them from its own
  file, and mgmtd, which has no `-f`, did not read that file. So the
  labs start mgmtd and give zebra's lines through vtysh (`FrrLab`'s
  `frr_zebra`). The affinity-map must be given to zebra as well as to
  isisd.
- `test/interop/frr_flex_algo_topology_test.rb` runs the 15 topology
  cases on real routers, a namespace per system
  (`test/support/flex_topology_lab.rb`). S is isisd or FRR. isisd gives
  every case's answer. FRR gives the answer wherever it runs the FAD:
  exclude-any, include-any, include-all, a system that does not take
  part, the two-way check, the partition, and TI-LFA's repair through B
  with D's 128 label in B's SRGB. It elects a FAD with a delay or TE
  metric, or with an Exclude SRLG, then disables it as an "unsupported
  definition" and does not take part. So FRR 10.5.1, like 10.7.1, runs
  only IGP-metric FADs, and no SRLG rule. FRR gives an algorithm's
  routes and its FAD in text only.
- The topologies are a group of their own in `docs/fault-matrix.md`.
- Found against FRR and fixed: `policy.flex_algo` refused any change to
  an algorithm with colors ("color 1 is not in affinity_map"), since it
  checked the entry's groups again as names.

7c, the codec entries against FRR 10.5.1 (measured 2026-11-26):

- `test/interop/frr_flex_fault_test.rb` puts each of the 16 entries of
  `Fault::FLEX_ALGO_CATALOG` in s1's LSP, as the SR entries are
  (`SrFaultLab` with `flex:`). isisd and FRR take part in 128 and
  advertise no FAD, so s1's FAD is the only one. A link entry is a
  second link from s1 toward FRR.
- isisd does what the RFC asks on every entry it reads, and names each
  finding. It reads no FAPM: FAPMs wait for the M flag (decision 2). It
  uses the first of two Prefix-SIDs for one algorithm, but names no
  finding: `Spf::PrefixMetrics`, which makes the FAPM and Prefix-SID
  findings, is not called by isisd yet. Found, not fixed here.
- FRR uses a FAD that RFC 9350 asks be ignored: one with a sub-TLV
  twice (the second wins), one with the S bit. Of FADs split across
  sub-TLVs it uses the last, not the first. It discards the whole LSP
  that carries a FAD admin group of 5 octets. It prints a link's ASLA
  as it parsed it, but drops one with a SABM of 9 octets; which values
  it uses does not show. It prints no FAPM.
- The entries are a group of their own in `docs/fault-matrix.md`,
  "Flex-algo data".

### 5 to 7. API, configuration, CLI

Above.

### 8. Time

FAD selection and participation run in the Decision Process, on its
scheduler. A FAD change waits for the same SPF delay. Tests run on the
manual clock.

### 9. Logs and capture

A change of winning FAD, of participation, or of support, is an event
of kind `:flex_algo`, at info. The wire capture's dissector names the
new TLVs and sub-TLVs.

## Labs

One lab, `isis4r-flexalgo`, in isis's `routescope/labs/`, with one FRR
node, as `isis4r-tilfa` has (the owner's decision, 2026-11-25).

### `isis4r-flexalgo`

Changed by the owner, 2026-11-25 (decision 8), after FRR 10.7.1 was
measured ("Measured on FRR 10.7.1"): it runs only IGP-metric FADs, and
elects FADs at Level 1 only. So f1 sits where an IGP-metric algorithm
crosses it, and every router is at Level 1.

Every router but f1 runs isis4r. f1 is FRR 10.7.1, on the middle path.
Three paths from r1 to r4, so three algorithms give three paths:

```
         r2  (top: IGP 10 + 10, delay 20 ms each, red)
       /    \
     r1 - f1 - r4 -- s1 (isis4r-sim)
       \    /
         r3  (bottom: IGP 20 + 20, delay 2 ms each)

  middle, r1-f1-r4: IGP 15 + 15, delay 5 ms each
```

- Every router is at Level 1.
- Algorithm 0: the top, IGP 20.
- Algorithm 128, delay, no constraint: the bottom, 4 ms. f1 does not
  take part in 128, so 128 prunes it (RFC 9350 section 13): a router of
  another make, pruned.
- Algorithm 129, IGP, exclude red: the middle, through f1, IGP 30. Its
  labels cross FRR.
- TI-LFA on r1. With r1-r3 down, 128's repair goes by the top: the
  middle is pruned from 128. With r1-f1 down, 129's repair goes by the
  bottom, never the top: it is red. Algorithm 0's repair would take the
  top.
- f1's links are configured with `delay N min N max N`, so it sends
  sub-TLV 34 as well as 33.
- s1 runs the behaviours and the codec faults against r4.
- The SRGBs differ, as in `isis4r-tilfa`, so a label from the wrong
  block shows.

Its scenarios check the label tables, the paths, the repairs and the
faults. They send packets with an algorithm's label, as the TI-LFA
packet group does, and check where they leave. The numbers above are a
design. The lab's `ABOUT.md` gives the measured ones.

The scenarios with f1:

- f1 wins 129's FAD on priority, then an isis4r router does: every
  router selects the same winner.
- f1's labels for 129 agree with the isis4r routers' on the path.
- f1 withdraws 128 from its SR-Algorithm, and the isis4r routers prune
  it from 128.
- f1's ASLA and isisd's are read both ways.
- A FAD with a constraint one side lacks: that side stops taking part,
  and the other routes around it.

FRR shows FADs in text only, not in JSON. A scenario that needs f1's
FAD state reads the text.

Its `ABOUT.md` says f1 is the interop check (CLAUDE.md, "Our own Ruby
code first"), as `isis4r-tilfa`'s does.

As built in step 8 (measured on ospflab, 2026-11-27):

- The lab is as designed above, with s1 simulating one system, t1,
  behind r4. Its `ABOUT.md` gives the measured labels and times.
- r4 advertises both FADs: 128's, the delay, at priority 0, so a FAD
  from s1 at priority 0 wins on System ID; and 129's with no constraint,
  at priority 100, below f1's, which excludes red at 200. So the
  election scenario can lower f1's through vtysh and see 129 go over
  the top.
- Its five scenarios read label tables only (`mpls_label`): routescope
  has no condition yet for the FAD a router elects, no `policy.flex_algo`
  step, and its `sim:` step drops the behaviours' `algorithm`,
  `priority`, `metric_type`, `hold` and `delay`, so they run with their
  defaults. No packet is sent on an algorithm's label: no scenario step
  sends a chosen label stack. These wait for routescope's specification.
- The catalog's link entries are not run here: s1's extra link goes
  toward a system that does not report it back, so the two-way check
  drops it. The fault matrix covers them (step 7c).
- f1's ASLA and isisd's are read both ways in the namespace tests
  (step 7b). Here only their effect shows: 128 on the delay over the
  bottom, 129 around red.

A teaching lab in routescope, with pauses, as `ti-lfa` is, belongs to
the routescope specification.

## Tests

- Unit: every codec class four ways, the catalog, the validation rules,
  selection (priority, System ID, split FADs), the link reader's rules
  in order, the calculation on the topology cases, the label table per
  algorithm, TI-LFA per algorithm.
- Property: algorithm with IGP metric and no constraints equals
  algorithm 0, on 300 random topologies.
- Interop in network namespaces (`test/interop`), against FRR 10.7.1:
  the FAD, ASLA and Prefix-SIDs read both ways, the selected winner, and
  the label tables. Then the fault matrix against FRR, as 6e1 did for
  TI-LFA.
- Kernel: an algorithm's label routes installed and removed
  (`test/interop/kernel_*`).
- Lab: the lab's scenarios, through routescope.

## Work

One pull request each, in order. Each is small.

1. **Link attributes, codec.** Admin Group, EAG, TE metric, min/max
   delay, ASLA, TLVs 138 and 238. Catalog entries. RFC 5307 fetched
   first.
2. **Link attributes, origination and reading.** The configuration
   keys, ASLA with X, `Spf::LinkAttributes`, `show.topology`, the ASLA
   findings.
3. **FAD and FAPM, codec.** Sub-TLV 26 and its sub-sub-TLVs, sub-TLV 6
   under 135 and 236. Catalog entries, the FAD and FAPM findings, the
   codec fault cases.
4. **Selection and participation.** `flex_algo`, `algorithm_sids`,
   `Spf::FlexAlgo`, SR-Algorithm and the Prefix-SIDs per algorithm,
   `show.flex_algo`, `policy.flex_algo`.
5. **The calculation and labels.** The link reader and node filter, the
   label table per algorithm, installed in the kernel. The topology
   cases and the property.
6. **TI-LFA per algorithm.** The graph per algorithm, Adj-SIDs of
   surviving links with B clear, `fa_ti_lfa_constraint`.
7. **The injector.** The topology keys, the behaviours, `/api/fault`,
   then the fault matrix against FRR in network namespaces.
8. **`isis4r-flexalgo`.** The lab, with f1, and its scenarios.

Then routescope's specification, then its pull requests, and the lab
in CI there.

Later, after the lab (the owner's decision, 2026-11-25): **the M flag
and FAPM between levels** (section 13.1). Until then isisd stops taking
part in a FAD with M set, and flex-algo stays inside one level. The
FAPM codec and its findings are still built in step 3.

## Out of scope

- OSPF flex-algo (after P7).
- SRv6 flex-algo (P6).
- RFC 9843's bandwidth metric and constraints.
- Measured delay. The delay is configured, not measured.
- Steering IP traffic into an algorithm.
- Flex-algo-specific Adj-SIDs. They are not in RFC 9350.
- Multi-topology. isisd has none, and the FAD is topology independent
  (9350 section 5.3).

## Decisions

The owner's answers, 2026-11-25. All seven of the draft's questions are
answered.

1. **SRLG now**, in steps 1 and 2: TLVs 138 and 238 and the
   exclude-SRLG rule.
2. **The M flag and inter-level FAPM later**, after the lab. See "Work".
3. **One lab**, `isis4r-flexalgo`, with an FRR node, f1.
4. **ASLA only.** isisd sends no legacy link attributes for flex-algo
   (9479 section 6.1). It still reads legacy ones when an ASLA's L flag
   says to.
5. **No Level 1 copy of the Level 2 FAD.** Section 5.1 makes it a
   "MAY"; it is not built now.
6. **A FAD in a TLV 242 with S set, or an admin group whose length is
   not a multiple of 4**: the RFC says "MUST" for the sender only.
   Under `:rfc` and `:strict`, isisd ignores the FAD and reports the
   finding. Under `:lenient`, it uses it. The lab notes what FRR does.
7. **Two Prefix-SIDs for one prefix and one algorithm**: RFC 8402
   section 3.1 asks the tuple be unique, but names no receiver action.
   isisd uses the first, in the lowest-numbered LSP, and reports.
8. **The lab's f1 on the middle path, every router at Level 1**
   (2026-11-25, after FRR 10.7.1 was measured). f1 carries algorithm
   129, and 128 prunes it.
