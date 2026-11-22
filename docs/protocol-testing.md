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
