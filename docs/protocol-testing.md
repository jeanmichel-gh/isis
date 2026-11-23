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
runs at a time. `flap` ends on its own; the others hold until
`behave_stop`, which undoes what they did.

| Behaviour | Section | Parameters | The simulator | Expects |
| --- | --- | --- | --- | --- |
| `flap` | RFC 9855 1 | `circuit`, optional; `count` 3; `down` 10; `up` 10 | stops its hellos on circuit for down seconds, then sends them for up seconds, count times; every interface without circuit | the router across circuit uses its repair from each loss until it converges, and computes its backups again once the adjacency is back; after the last, they are those it had before |
| `stale_lsp` | RFC 1142 7.2.8.2, 7.3.16.4 | `router` | router's neighbours report their links to it down, while its own LSP stays as it was, never refreshed, until it expires | no route and no repair crosses router, since only router reports its links; its LSP expires after its lifetime |
| `srgb_change` | RFC 8660 2.4, RFC 9855 7.1 | `router`; `start`, optional | router's LSP 0 carries its SRGB moved to start, 100000 labels up unless given, while its Prefix-SIDs keep their indexes; what router forwards is not changed | a label in router's SRGB moves with the block: a repair's last label when router is Q, and a route's label when router is the next hop |

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
