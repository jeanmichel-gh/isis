# Protocol testing

How isis4r checks what it receives, and what a test can make it do with
something wrong. Built to routescope's `docs/design/protocol-conventions.md`,
part 2, as bgp4r, vtep4r and bfd4r are.

## Findings

`lib/isis/validation.rb` holds the receive rules, each a named finding
with the clause it comes from (`CLAUDE.md`, "Validation"). It decides
nothing; the caller acts on a finding under the receive policy. A finding
is on one of three channels: `errors` (the sender broke a clause), `gaps`
(isis4r has no code for it) and `inconclusive` (what arrived cannot
support a verdict).

The first rules are segment routing's (RFC 8667, RFC 8660). They run on
the LSP database after each SPF run, in `Spf::Labels`, since each needs
several sub-TLVs or several systems' LSPs. isisd logs a finding by its
name, and `show.segment_routing` lists them per level.

| Finding | Channel | When |
| --- | --- | --- |
| `srgb_range_zero` | errors | an SRGB descriptor with a range of 0 |
| `srgb_overlap` | errors | two SRGB ranges that overlap |
| `srgb_reserved` | errors | an SRGB range below 16 or past 1048575 |
| `sr_capabilities_twice` | errors | more than one SR-Capabilities from one system |
| `prefix_sid_vl_invalid` | errors | a Prefix-SID with V set and L clear, or L set and V clear |
| `algorithm_not_advertised` | errors | a Prefix-SID for an algorithm its origin does not run |
| `prefix_sid_duplicate` | errors | one index on two prefixes |
| `prefix_sid_label` | gaps | a Prefix-SID that is a label, not an index |

The link attribute rules (RFC 9479, RFC 7308) are flex-algo's
(`docs/design/flex-algo.md`). `Spf::LinkAttributes` makes them as it
reads one node's link attributes for the X bit, and `show.topology` lists
them per node as `link_findings`.

| Finding | Channel | When |
| --- | --- | --- |
| `asla_mask_too_long` | errors | an ASLA sub-TLV with a SABM or UDABM longer than 8 octets |
| `asla_l_flag_values` | errors | an ASLA sub-TLV with the L flag set that carries values |
| `asla_l_flag_mixed` | errors | the L flag set in one ASLA sub-TLV for flex-algo on a link and clear in another |
| `asla_conflict` | errors | two values of one attribute for flex-algo on one link |
| `asla_srlg_no_link_id` | errors | a TLV 238 with no link identifier, or one type twice |
| `admin_group_mismatch` | errors | an Admin Group and an Extended Admin Group that differ in groups 0 to 31 |

`asla_l_flag_values` covers TLV 238 too: SRLGs in one with L set.

The flex-algo definition rules (RFC 9350, RFC 8402). `Spf::Definitions`
makes the FAD ones as it reads one system's FADs and merges those split
across sub-TLVs (section 6); `Spf::PrefixMetrics` makes the FAPM and
Prefix-SID ones as it reads a system's prefixes. Selection (work step 4)
will act on them.

| Finding | Channel | When |
| --- | --- | --- |
| `fad_algorithm_range` | errors | a FAD for an algorithm outside 128 to 255 |
| `fad_subtlv_twice` | errors | one sub-sub-TLV, types 1 to 5, twice in one FAD |
| `fad_split_differs` | errors | FADs for one algorithm from one system whose fixed parts differ |
| `fad_split_subtlv_twice` | errors | one sub-sub-TLV, types 1 to 4, in two FADs for one algorithm from one system |
| `fad_s_bit` | errors | a FAD in a Router Capability TLV with the S bit set |
| `fad_eag_length` | errors | a FAD admin group or SRLG sub-sub-TLV whose length is not a multiple of 4 |
| `fad_unsupported` | gaps | a FAD with a calculation type, metric type, flag or sub-sub-TLV isis4r cannot run |
| `fapm_algorithm_range` | errors | a FAPM for an algorithm outside 128 to 255 |
| `fapm_twice` | errors | two FAPMs for one algorithm on one prefix |
| `prefix_sid_algorithm_twice` | errors | two Prefix-SIDs for one algorithm on one prefix |

A FAPM past MAX_PATH_METRIC, and one on a prefix inside its level, are
not findings: section 8 and section 13.1 say what a receiver does, and no
clause forbids sending them. The calculation leaves such a prefix out,
or the FAPM unused, once the M flag is built.

Two outcomes are not findings, since no sender broke a clause: an index
past this system's SRGB, and a neighbor without an SRGB (RFC 8660
section 2.10.1 sends the packet another way). They stay problems, in the
same list.

## Receive policies

`segment_routing: { receive_policy: rfc }` in isisd's file. Each rule
says what each policy does.

| Policy | Does |
| --- | --- |
| `rfc` | the default: what the clause asks. An SRGB that breaks RFC 8660 section 2.3 is "completely ignored", and its node "treated as if it does not have an SRGB"; the first SR-Capabilities is used; an invalid Prefix-SID is not used; two prefixes with one index both go without a label |
| `strict` | refuses on any finding: a node with a finding on its SR-Capabilities has none of its SR data used |
| `lenient` | uses what arrived where it can, to watch what a sender sends: an SRGB that overlaps or has an empty range, and a Prefix-SID whose algorithm its origin did not list. An SRGB with reserved labels is still ignored, since those labels cannot be installed |

On link attributes, `rfc` ignores an ASLA sub-TLV whose mask is too
long, ignores values beside the L flag, takes a mixed L flag as set, uses
the first of two values, in the lowest LSP Number, and the Admin Group
over the EAG for groups 0 to 31. `strict` does the same, but uses
neither of two conflicting values, nor an affinity whose AG and EAG
differ. `lenient` reads a mask past 8 octets, uses values beside the L
flag as if it were clear, and with a mixed L flag uses the values of the
sub-TLVs with L clear.

On FADs, `rfc` ignores one for an algorithm outside 128 to 255, one with
a sub-sub-TLV twice, one in a TLV 242 with S set, and one whose admin
group or SRLG length is not a multiple of 4 (decision 6). Across one
system's split FADs it uses the first. `strict` ignores the algorithm's
FADs from that system on any finding. `lenient` uses the first of a
sub-sub-TLV twice, and uses a FAD with S set or an odd length. A FAD
isis4r cannot run stops its taking part under every policy (section
5.3). On a prefix, the first FAPM and the first Prefix-SID for an
algorithm are used; `strict` uses no FAPM for an algorithm sent twice,
and neither Prefix-SID.

The tests: `test/unit/validation_test.rb` for each rule,
`test/unit/spf/sr_findings_test.rb` for each finding on hand-built LSPs
and each policy.

## The fault catalog

`ISIS::Fault` (`lib/isis/fault.rb`), as bgp4r's `BGP::Fault`, vtep4r's
`VXLAN::Fault` and bfd4r's `BFD::Fault`: crafted inputs, each with one
wrong thing, everything else what a correct system sends. Building never
validates. Each entry names the finding it makes; what the RFC expects of
a receiver, and the clause, are that finding's.

| Entry | Finding | Builds |
| --- | --- | --- |
| `srgb_range_zero` | `srgb_range_zero` | an SRGB descriptor with a range of 0 |
| `srgb_overlap` | `srgb_overlap` | two SRGB ranges that overlap by half |
| `srgb_reserved` | `srgb_reserved` | an SRGB from label 8, among the reserved labels 0 to 15 |
| `sr_capabilities_twice` | `sr_capabilities_twice` | two SR-Capabilities sub-TLVs in one Router Capability |
| `prefix_sid_vl_invalid` | `prefix_sid_vl_invalid` | a Prefix-SID with V set and L clear |
| `prefix_sid_label` | `prefix_sid_label` | a Prefix-SID carried as a label, V and L set |
| `algorithm_not_advertised` | `algorithm_not_advertised` | a Prefix-SID for algorithm 0 from a system whose SR-Algorithm lists 1 only |
| `prefix_sid_duplicate` | `prefix_sid_duplicate` | one index on the loopback and on a second prefix |

```ruby
ISIS::Fault.names                       # the entries
ISIS::Fault.entry(:srgb_overlap)        # its finding, channel, expect, rfc
ISIS::Fault.tlvs(:srgb_overlap)         # Router Capability and reachability TLVs
ISIS::Fault.build(:srgb_overlap, system_id: "0000.0000.0003",
                  neighbors: { "0000.0000.0002" => 10 })   # a whole LSP
ISIS::Fault.wire(:srgb_overlap)         # its octets
```

`tlvs` is for an injector, which adds them to the LSP of the system it
plays; `build` and `wire` give LSP number 0 of the system. The context
(`Fault.context`) sets the system, its loopback and index, its SRGB, a
second prefix, and its neighbors.

`test/unit/fault_test.rb` builds each entry as an LSP in a database and
reads it with `Spf::Labels`: each makes its own finding and no other.
Every rule has an entry, and every entry a rule, so the catalog and
`validation.rb` cannot drift apart.

### Flex-algo

The flex-algo entries, `ISIS::Fault::FLEX_ALGO_CATALOG`, each with one
wrong thing: in a link's attributes for flex-algo, which
`Spf::LinkAttributes` reads; in a FAD, which `Spf::Definitions` reads;
or in a prefix's sub-TLVs, which `Spf::PrefixMetrics` reads. Each makes
its finding there, and `test/unit/fault_test.rb` holds them to it as it
holds the SR entries. They are a group of their own, in the fault
matrix too: `test/interop/frr_flex_fault_test.rb` gives each to isisd
and FRR, as the SR entries are given (`docs/fault-matrix.md`, "Flex-algo
data"). `ISIS::Fault.flex_algo_catalog` lists them; `entry`, `tlvs`, `build` and
`wire` take them as they take the SR entries.

| Entry | Finding | Builds |
| --- | --- | --- |
| `asla_mask_too_long` | `asla_mask_too_long` | an ASLA sub-TLV with X and a SABM of 9 octets |
| `asla_l_flag_values` | `asla_l_flag_values` | an ASLA sub-TLV with X and L set that carries a TE metric |
| `asla_l_flag_mixed` | `asla_l_flag_mixed` | two ASLA sub-TLVs with X on one link, L set in one |
| `asla_conflict` | `asla_conflict` | two ASLA sub-TLVs with X on one link, TE metrics 100 and 200 |
| `asla_srlg_no_link_id` | `asla_srlg_no_link_id` | a TLV 238 with X and SRLG 10, and no link identifier |
| `admin_group_mismatch` | `admin_group_mismatch` | an ASLA sub-TLV with X, Admin Group 1 and Extended Admin Group 2 |
| `fad_algorithm_range` | `fad_algorithm_range` | a FAD for algorithm 127 |
| `fad_subtlv_twice` | `fad_subtlv_twice` | a FAD with two Exclude Admin Group sub-TLVs |
| `fad_split_differs` | `fad_split_differs` | two FADs for algorithm 128, priorities 100 and 200 |
| `fad_split_subtlv_twice` | `fad_split_subtlv_twice` | two FADs for algorithm 128, each with an Exclude Admin Group |
| `fad_s_bit` | `fad_s_bit` | a FAD for algorithm 128 in a Router Capability TLV with S set |
| `fad_eag_length` | `fad_eag_length` | a FAD whose Exclude Admin Group is 5 octets |
| `fad_unsupported` | `fad_unsupported` | a FAD for algorithm 128 with calculation type 1 |
| `fapm_algorithm_range` | `fapm_algorithm_range` | a FAPM for algorithm 100 on the loopback |
| `fapm_twice` | `fapm_twice` | two FAPMs for algorithm 128 on the loopback, metrics 10 and 20 |
| `prefix_sid_algorithm_twice` | `prefix_sid_algorithm_twice` | two Prefix-SIDs for algorithm 0 on the loopback, indexes 3 and 4 |

### SRv6

The SRv6 entries, `ISIS::Fault::SRV6_CATALOG` (`docs/design/srv6.md`,
"3. Negative tests"), each with one wrong thing in a system's SRv6 data,
everything else what `Fault.srv6` gives a correct system: SRv6
Capabilities, the locator in TLV 236 and in TLV 27, an End SID and an
End.X SID with a SID Structure. Each is named for the finding it will
make. The codec builds them, and `test/unit/fault_srv6_test.rb` holds
each to its one change and to its round trip. The findings are the
validation step's, so until then the entries are not in
`Fault.catalog`, which reads each finding's rule:
`ISIS::Fault.srv6_catalog`, `srv6_tlvs` and `srv6_build` give them, a
Level 2 LSP by default.

| Entry | Builds |
| --- | --- |
| `locator_size_invalid` | a locator with a Loc-Size of 129 |
| `locator_algorithm_conflict` | the same locator in a second SRv6 Locator TLV, at algorithm 128 |
| `end_sid_outside_locator` | an End SID that is not in its locator |
| `end_x_sid_no_locator` | an End.X SID that no locator of the system covers |
| `sid_structure_twice` | an End SID with two SID Structure sub-sub-TLVs |
| `sid_structure_too_long` | an End SID whose SID Structure sums to 144 bits |
| `behavior_not_allowed` | an End SID with behaviour End.X, 5 |
| `behavior_unknown` | an End SID with behaviour 125, which IANA lists as unassigned |
| `anycast_and_node` | a locator whose Prefix Attribute Flags set both N and A |
| `x_flag_mismatch` | a locator with X set in TLV 27 and clear in TLV 236 |
| `fapm_in_locator` | a FAPM for algorithm 128 in the SRv6 Locator TLV |

### TI-LFA's topologies

The catalog's second group, `ISIS::Fault::TOPOLOGIES`: topologies that
are well formed but hard for TI-LFA (RFC 9855). Each names the section
it tests, the point of local repair (PLR), the failure, the
destination, and the repair the RFC expects, written by hand from the
RFC: its case, first hop, P and Q, and its segments; or why there is
none.

| Entry | Section | Failure | Expects |
| --- | --- | --- | --- |
| `ti_lfa_neighbor` | RFC 9855 5.1 | link F at S, to D | `neighbor` via N, P N, Q N: no segment |
| `ti_lfa_pq_node` | RFC 9855 5.2 | link F at S, to D | `pq_node` via A, P B, Q B: Node-SID(B) |
| `ti_lfa_p_and_q_adjacent` | RFC 9855 5.3 | link F at S, to D | `p_and_q_adjacent` via A, P B, Q D: Node-SID(B), Adj-SID(B-D) |
| `ti_lfa_figure_1` | RFC 9855 5.4 | node N1 at S, to D | `p_and_q_apart` via N2, P R1, Q R3: Node-SID(R1), Adj-SID(R1-R2), Adj-SID(R2-R3) |
| `ti_lfa_figure_2` | RFC 9855 9 | node R3 at R2, to D | `p_and_q_apart` via R7, P R7, Q R4: Adj-SID(R7-R8), Adj-SID(R8-R4) |
| `ti_lfa_no_path` | RFC 9855 5 | link F at S, to D | unprotected, `no_path` |
| `ti_lfa_ecmp` | RFC 9855 5 | link F at S, to D | ECMP through A |
| `ti_lfa_overload` | RFC 9855 5 | link F at S, to D | unprotected, `no_path` |
| `ti_lfa_one_way` | RFC 9855 5 | link F at S, to D | unprotected, `no_path` |
| `ti_lfa_too_deep` | RFC 9855 5.4 | node F at S, to D | unprotected, `too_deep` |

Every system of an entry gets a loopback 10.255.0.N/32 with Prefix-SID
index N and an SRGB of its own, 16000 + 1000 N, so a label taken from
the wrong block shows.

```ruby
ISIS::Fault.topology_names               # the entries
ISIS::Fault.topology(:ti_lfa_figure_1)   # its links, PLR, failure, destination, expect
ISIS::Fault.topology_file(:ti_lfa_figure_1)  # as an isis4r-sim file (docs/simulator.md)
```

`test/unit/fault_topology_test.rb` runs each entry as an isis4r-sim
file, reads the graph back from the simulator's database, so the
Router Capabilities, Prefix-SIDs and Adj-SIDs are the ones a router
learns, and computes TI-LFA at the PLR. Each must give what it expects.
`test/interop/frr_ti_lfa_test.rb` runs the same entries on real routers,
isisd's and FRR's, and compares their repairs (`docs/ti-lfa.md`, "On
real routers, against FRR").

### Flex-algo's topologies

The catalog's flex-algo topologies, `ISIS::Fault::FLEX_ALGO_TOPOLOGIES`:
small graphs, each with the path RFC 9350 expects from S to D for
algorithm 128, written by hand from the RFC. Each names the FAD that
wins, then S's first hops and the metric, or why there is no path.
Colors are groups: red 1, green 2, blue 3, yellow 4. Delays are in
microseconds.

| Entry | Section | Builds | Expects |
| --- | --- | --- | --- |
| `fa_exclude_any` | RFC 9350 section 13, rule 1 | A to D is red; the FAD excludes red: by B | D's FAD; via B, metric 10 |
| `fa_include_any` | RFC 9350 section 13, rule 3 | A's links are blue, B's green; the FAD includes any of green and yellow: by B | D's FAD; via B, metric 10 |
| `fa_include_all` | RFC 9350 section 13, rule 4 | A's links have green only, B's green and blue; the FAD includes all of both: by B | D's FAD; via B, metric 10 |
| `fa_exclude_srlg` | RFC 9350 section 13, rule 2 | A to D is in SRLG 10; the FAD excludes it: by B | D's FAD; via B, metric 10 |
| `fa_delay` | RFC 9350 section 5.1, metric type 1 | A's links 20 ms each, B's 2 ms; the FAD's metric is the delay: by B, 4 ms | D's FAD; via B, metric 4000 |
| `fa_te_metric` | RFC 9350 section 5.1, metric type 2 | A's links TE metric 50 each, B's 3; the FAD's metric is TE: by B, 6 | D's FAD; via B, metric 6 |
| `fa_link_no_metric` | RFC 9350 section 13, rule 5 | A to D has no delay; the FAD's metric is the delay: A to D is pruned, not 0, so by B | D's FAD; via B, metric 40000 |
| `fa_last_resort` | RFC 9350 section 15.3 | S to A has a delay of 2^24 - 1, the only path: used, as a last resort | D's FAD; via A, metric 16777216 |
| `fa_node_not_participating` | RFC 9350 section 13 | A does not take part: it is pruned, so by B | D's FAD; via B, metric 10 |
| `fa_one_way` | RFC 9350 section 13, the two-way check | D's link back to A is red, A's to D is not; the FAD excludes red: the two-way check is algorithm 0's, so by A | D's FAD; via A, metric 2 |
| `fa_partition` | RFC 9350 section 14.1 | the only path is red; the FAD excludes red: D unreachable, no label route | D's FAD; D unreachable, no label route |
| `fa_priority` | RFC 9350 section 5.3 | D's FAD, IGP, priority 100; B's, delay, priority 200: B's wins, so by B on delay | B's FAD; via B, metric 4000 |
| `fa_system_id_tie` | RFC 9350 section 5.3 | A's FAD, IGP, and B's, delay, both priority 100: B has the greater System ID and wins, so by B on delay | B's FAD; via B, metric 4000 |
| `fa_no_fad` | RFC 9350 section 5.3 | no system advertises a FAD: S does not take part | S does not take part |
| `fa_ti_lfa_constraint` | RFC 9855 section 8 | S protects its link to F with TI-LFA; A to D is red, the FAD excludes red: the repair goes by B, where algorithm 0's goes by A | D's FAD; via F, metric 2; link F repaired via B (`neighbor`), algorithm 0's via A |

Systems are numbered as they first appear in the links: system N is
0000.0000.00NN, with loopback 10.255.0.N/32, Prefix-SID index N for
algorithm 0 and 100 + N for 128, and the SRGB 16000 + 1000 N.

```ruby
ISIS::Fault.flex_topology_names     # the entries
ISIS::Fault.flex_topologies         # each: links, not_taking_part, fads, expect
```

`test/unit/spf/flex_algo_calculation_test.rb` builds each entry's LSPs,
selects the FAD at S (`Spf::FlexAlgo`), computes algorithm 128's tree
(`Spf::Calculation`) and its label table (`Spf::Labels`). Each must
give what it expects, and D's label must swap to the first hop's SRGB,
or be popped toward D itself. An entry with a repair also runs TI-LFA
for algorithm 128 at S (`Spf::Backups`) and for algorithm 0, each of
which must take its own first hop.

`test/interop/frr_flex_algo_topology_test.rb` runs each entry again on
real routers, a network namespace per system
(`test/support/flex_topology_lab.rb`): isisd at every system, and S
either isisd or FRR's isisd. isisd is held to the entry; FRR to what
it did on its recorded version. Both go in `docs/fault-matrix.md`.

### Packets at the PLR

The catalog's third group, `ISIS::Fault::PACKETS`: packets that reach
the point of local repair while it repairs, sent by a host behind it.
`expect` is the repair, the repair list then the destination's label in
Q's SRGB (RFC 9855 6.1 and 7.1), or `record` for an edge the RFC leaves
open, where what happens is recorded.

| Entry | Section | Sends | Expects |
| --- | --- | --- | --- |
| `packet_ip` | RFC 9855 5 | an IPv4 packet to the destination | the repair |
| `packet_prefix_sid` | RFC 9855 6.1, 7.1 | the destination's Prefix-SID, as the PLR's SRGB gives it, over IPv4 | the repair |
| `packet_ip_ttl_1` | RFC 9855 5 | an IPv4 packet to the destination with a TTL of 1 | record |
| `packet_mpls_ttl_1` | RFC 9855 6.1 | the destination's Prefix-SID with a TTL of 1 | record |
| `packet_unknown_label` | RFC 9855 6 | a label the PLR holds no route for | record |
| `packet_adj_sid` | RFC 9855 6.2 | the PLR's Adj-SID to the failed neighbor, over IPv4; isisd does not protect Adj-SIDs | record |

```ruby
ISIS::Fault.packet_names                 # the entries
ISIS::Fault.packet(:packet_prefix_sid, src: "10.9.0.2", dst: "10.255.0.3",
                   labels: { destination: 17_003 })   # [0x8847, octets]
ISIS::Fault.packet_named_by(40_001)      # the entry a UDP source port names
```

Each packet's UDP source port names its entry, so an ICMP error that
quotes only its headers still does. `test/unit/fault_packet_test.rb`
checks each is built as its entry says. `test/interop/kernel_ti_lfa_test.rb`
sends them at a real PLR during a repair (`docs/ti-lfa.md`, "Packets at
the PLR").

### Behaviours

The catalog's fourth group, `ISIS::Fault::BEHAVIOURS`: misbehaviour
over time, each a named script isis4r-sim runs
(`Sim::Simulator#behave`, `POST /api/behave`, `docs/simulator.md`). One
runs at a time. `flap`, `participation_flap`, `fad_takeover` and
`delay_change` end on their own; the others hold until `behave_stop`.
`behave_stop` undoes what any of them did. The flex-algo behaviours
need a simulated system with `flex_algo` (`docs/simulator.md`).

| Behaviour | Section | Parameters | The simulator | Expects |
| --- | --- | --- | --- | --- |
| `flap` | RFC 9855 1 | `circuit`, optional; `count` 3; `down` 10; `up` 10 | stops its hellos on circuit for down seconds, then sends them for up seconds, count times; every interface without circuit | the router across circuit uses its repair from each loss until it converges, and computes its backups again once the adjacency is back; after the last, they are those it had before |
| `stale_lsp` | RFC 1142 7.2.8.2, 7.3.16.4 | `router` | router's neighbours report their links to it down, while its own LSP stays as it was, never refreshed, until it expires | no route and no repair crosses router, since only router reports its links; its LSP expires after its lifetime |
| `srgb_change` | RFC 8660 2.4, RFC 9855 7.1 | `router`; `start`, optional | router's LSP 0 carries its SRGB moved to start, 100000 labels up unless given, while its Prefix-SIDs keep their indexes; what router forwards is not changed | a label in router's SRGB moves with the block: a repair's last label when router is Q, and a route's label when router is the next hop |
| `fad_takeover` | RFC 9350 5.3 | `router`; `algorithm` 128; `priority` 255; `metric_type`, optional; `hold` 30 | router advertises a FAD for algorithm at priority, with metric_type when given, for hold seconds, then what it advertised before | every router that takes part in algorithm selects router's FAD while it is advertised, unless one of greater priority, or System ID at the same, is there, and the one before after; the paths follow the winner's metric type |
| `participation_flap` | RFC 9350 11, 13 | `router`; `algorithm` 128; `count` 3; `down` 10; `up` 10 | router leaves algorithm out of its SR-Algorithm, and its Prefix-SIDs for it, for down seconds, then lists it again for up seconds, count times | every router prunes router from algorithm while it does not list it, so no path in algorithm crosses it and its prefixes have no label route in algorithm; all come back once it lists it again |
| `delay_change` | RFC 9350 5.1, metric type 1 | `link`; `delay` 100000; `hold` 30 | link's delay, both ways, is delay microseconds for hold seconds, then what it was | a delay algorithm's paths leave link while its delay makes another path shorter, and come back after |

```ruby
sim.behave(:flap, circuit: "a", count: 2, down: 8, up: 12)
sim.behave(:stale_lsp, router: "x")
sim.behave(:srgb_change, router: "s1")   # the simulator's own, or any simulated system
sim.behaviour                            # { name:, params:, at: }, or nil
sim.behave_stop                          # { stopped: :srgb_change }
```

`test/unit/sim/behaviour_test.rb` runs each against a point of local
repair, an ordinary Router with `ti_lfa: link` toward the simulator,
whose repair is P and Q adjacent (RFC 9855 5.3) with the simulator as
Q:

- `flap`: in each loss the PLR has converged on its repair's first hop;
  in each return its backup is computed again, the one it had.
- `stale_lsp`: the PLR holds the system's LSP at the sequence it had,
  reaches nothing through it, and routes around it; the LSP expires
  after `lsp_lifetime`. Stopped, the system is generated again, past
  the expired copy.
- `srgb_change` on Q: the repair's last label moves 100000 up with the
  block, and the Adj-SID before it stays. Stopped, both are back.

`test/unit/sim/flex_algo_test.rb` runs the flex-algo ones against an
ordinary Router taking part in 128, whose path to p3 in 128 avoids a red
link through p2:

- `fad_takeover` on p2, IGP at 255: the Router takes p2's FAD, and its
  path in 128 takes the red link; after `hold`, p3's FAD and the path
  through p2 again.
- `participation_flap` on p2: the Router prunes p2 from 128, so p3 is
  unreachable in 128 and its label route goes; both come back.
- `delay_change` on p1--p2: the path's delay rises by the change, then
  falls back. Stopped early, it is undone.

## The fault matrix

`docs/fault-matrix.md` shows what isisd and FRR's isisd do with each SR
entry, topology and packet beside what the RFC expects. `rake
fault_matrix` writes it, as root with FRR, from what the interop tests
measured: `frr_sr_fault_test.rb`, `frr_ti_lfa_test.rb` and
`kernel_ti_lfa_test.rb`. `test/docs/fault_matrix_test.rb` fails when the
catalog gains an entry the matrix does not show.
