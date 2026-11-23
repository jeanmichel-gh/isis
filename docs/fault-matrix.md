# The fault matrix

What isisd and FRR's isisd do with each entry of the fault catalog
(`ISIS::Fault`, `docs/protocol-testing.md`), beside what the RFC
expects. As bfd4r's and vtep4r's `docs/fault-matrix.md`.

**Generated** by `rake fault_matrix` on 2026-11-23, Linux 7.0.0-43-generic,
isis4r 0.1.0, Ruby 3.3.8, FRR 10.5.1. Do not edit it by hand; run again, as root:

```sh
sudo env "PATH=$PATH" ISIS_FRR=1 rake fault_matrix
```

It runs the interop tests that measure each group, in network
namespaces, and writes what they found. A cell in bold differs from
what the RFC expects. isisd is held to the RFC by those tests, FRR
to what it did on its recorded version.

## SR data

`test/interop/frr_sr_fault_test.rb`. An isis4r-sim, s1, faces isisd
and FRR at once, with one simulated system, r, behind it. Each entry
goes in s1's own LSP, so s1 is the next hop whose SR data is at
fault. A cell says the receiver's label toward r's loopback, the
label routes the entry added or took away, and isisd's finding.

| Entry | What | RFC expects | isisd | FRR isisd |
| --- | --- | --- | --- | --- |
| `srgb_range_zero` | an SRGB descriptor with a range of 0 | ignore_srgb (RFC 8667 3.1) | no label toward r; adds 23999; drops 16002, 16005; finding srgb_range_zero | no label toward r; adds 25999 |
| `srgb_overlap` | two SRGB ranges that overlap by half | ignore_srgb (RFC 8660 2.3) | no label toward r; adds 23998; drops 16002, 16005; finding srgb_overlap | no label toward r; adds 25998 |
| `srgb_reserved` | an SRGB from label 8, among the reserved labels 0 to 15 | ignore_srgb (RFC 8660 2.3) | no label toward r; adds 23997; drops 16002, 16005; finding srgb_reserved | no label toward r; adds 25997 |
| `sr_capabilities_twice` | two SR-Capabilities sub-TLVs in one Router Capability | use_first (RFC 8667 3.1) | label 17005 toward r; adds 23996; finding sr_capabilities_twice | label 17005 toward r; adds 25996 |
| `prefix_sid_vl_invalid` | a Prefix-SID with V set and L clear | ignore_sid (RFC 8667 2.1.1.1) | label 17005 toward r; finding prefix_sid_vl_invalid | **discards s1's LSP, keeps the one before; label 17005 toward r** |
| `prefix_sid_label` | a Prefix-SID carried as a label, V and L set | a gap of isis4r (RFC 8667 2.1.1.1) | label 17005 toward r; finding prefix_sid_label | label 17005 toward r; adds 24994 |
| `algorithm_not_advertised` | a Prefix-SID for algorithm 0 from a system whose SR-Algorithm lists 1 only | ignore_sid (RFC 8667 2.1) | label 17005 toward r; finding algorithm_not_advertised | **label 17005 toward r; adds 25993** |
| `prefix_sid_duplicate` | one index on the loopback and on a second prefix | drop_both (RFC 8667 2.1) | label 17005 toward r; finding prefix_sid_duplicate | label 17005 toward r; adds 25992 |

`prefix_sid_label` is a gap: isis4r has no code for a Prefix-SID
carried as a label. `prefix_sid_duplicate` is recorded: RFC 8660 2.5
recommends a tie-break that keeps one of the colliding prefixes,
which isis4r does not build, so it leaves both out.

## Topologies

`test/interop/frr_ti_lfa_test.rb`, on real routers in network
namespaces: isisd at every system, the PLR isisd or FRR. A repair is
read as the routers forward it, from the first hop. `ti_lfa_one_way`
stays a unit test: two real routers report a link both ways or
neither.

| Entry | What | RFC expects | isisd | FRR isisd |
| --- | --- | --- | --- | --- |
| `ti_lfa_neighbor` | the neighbor on the post-convergence path is in P and Q: no segment | via N: Node-SID(D) | via N: Node-SID(D) | via N: Node-SID(D) |
| `ti_lfa_pq_node` | B is in A's P-space and in Q(D): B's Node-SID | via A: Node-SID(B), Node-SID(D) | via A: Node-SID(B), Node-SID(D) | **via A: Node-SID(B), Adj-SID(B-D)** |
| `ti_lfa_p_and_q_adjacent` | P is B, Q is D, adjacent: B's Node-SID then B's Adj-SID to D | via A: Node-SID(B), Adj-SID(B-D) | via A: Node-SID(B), Adj-SID(B-D) | via A: Node-SID(B), Adj-SID(B-D) |
| `ti_lfa_figure_1` | RFC 9855 Figure 1, node N1 fails: P R1 and Q R3 apart | via N2: Node-SID(R1), Adj-SID(R1-R2), Adj-SID(R2-R3), Node-SID(D) | via N2: Node-SID(R1), Adj-SID(R1-R2), Adj-SID(R2-R3), Node-SID(D) | **via N2: Node-SID(R1), Adj-SID(R1-R2), Adj-SID(R2-R3), Adj-SID(R3-D)** |
| `ti_lfa_figure_2` | RFC 9855 Figure 2, R2 protects against node R3: Adj-SIDs R7-R8 and R8-R4 | via R7: Adj-SID(R7-R8), Adj-SID(R8-R4), Node-SID(D) | via R7: Adj-SID(R7-R8), Adj-SID(R8-R4), Node-SID(D) | **via R7: Node-SID(R7), Adj-SID(R7-R8), Adj-SID(R8-R4), Adj-SID(R4-R5), Adj-SID(R5-D)** |
| `ti_lfa_no_path` | the failure cuts the destination off | unprotected, no_path | unprotected, no_path | no backup |
| `ti_lfa_ecmp` | another primary first hop survives: no repair list | ECMP | ECMP | no backup |
| `ti_lfa_overload` | the only other path crosses B, overloaded: no transit, so no repair | unprotected, no_path | unprotected, no_path | no backup |
| `ti_lfa_too_deep` | P and Q 30 hops apart: 31 labels, past the kernel's 30 | unprotected, too_deep | not run | not run |

isisd's node repair on `ti_lfa_too_deep` falls back to the link's,
as its node protection does (`docs/ti-lfa.md`). FRR shows no backup
where there is no repair, or another primary next hop.

## Packets at the PLR

`test/interop/kernel_ti_lfa_test.rb`, on `ti_lfa_pq_node`. The PLR's
daemons are stopped before the link to F loses carrier, so what
follows is the kernel's alone, under the routes each PLR installed.
H sends each packet; A and H capture. `packet_prefix_sid` is a
known gap of isisd: a label route has no backup in the kernel
(routescope `docs/design/ti-lfa.md`, step 2c).

| Entry | What | RFC expects | isisd | FRR isisd |
| --- | --- | --- | --- | --- |
| `packet_ip` | an IPv4 packet to the destination | the repair, then D's label in Q's SRGB | reaches A: Node-SID(B), Node-SID(D), TTL 63 | **dropped; ICMP 3/0 back** |
| `packet_prefix_sid` | the destination's Prefix-SID, as the PLR's SRGB gives it, over IPv4 | the repair, then D's label in Q's SRGB | **dropped** | **dropped** |
| `packet_ip_ttl_1` | an IPv4 packet to the destination with a TTL of 1 | record | dropped; ICMP 11/0 back | dropped; ICMP 3/0 back |
| `packet_mpls_ttl_1` | the destination's Prefix-SID with a TTL of 1 | record | dropped | dropped |
| `packet_unknown_label` | a label the PLR holds no route for | record | dropped | dropped |
| `packet_adj_sid` | the PLR's Adj-SID to the failed neighbor, over IPv4; isisd does not protect Adj-SIDs | record | dropped | dropped |

## Behaviours

The catalog's behaviours act over time and are not in the matrix.
`test/unit/sim/behaviour_test.rb` runs each against a PLR.

Differs from the RFC: `packet_ip` (FRR isisd), `packet_prefix_sid` (FRR isisd), `packet_prefix_sid` (isisd), `prefix_sid_vl_invalid` (FRR isisd), `algorithm_not_advertised` (FRR isisd), `ti_lfa_pq_node` (FRR isisd), `ti_lfa_figure_2` (FRR isisd), `ti_lfa_figure_1` (FRR isisd).
