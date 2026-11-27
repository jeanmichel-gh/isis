# The fault matrix

What isisd and FRR's isisd do with each entry of the fault catalog
(`ISIS::Fault`, `docs/protocol-testing.md`), beside what the RFC
expects. As bfd4r's and vtep4r's `docs/fault-matrix.md`.

**Generated** by `rake fault_matrix` on 2026-11-26, Linux 7.0.0-1020-azure,
isis4r 0.1.0, Ruby 3.3.14, FRR 10.5.1. Do not edit it by hand; run again, as root:

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
| `ti_lfa_too_deep` | P and Q 30 hops apart: 31 labels, past the kernel's 30 | unprotected, too_deep | link fallback, via A0: Node-SID(D) | **via A0: Node-SID(A0), Adj-SID(A0-A1), Adj-SID(A1-A2), Adj-SID(A2-A3), Adj-SID(A3-A4), Adj-SID(A4-A5), Adj-SID(A5-A6), Adj-SID(A6-A7), Adj-SID(A7-A8), Adj-SID(A8-A9), Adj-SID(A9-A10), Adj-SID(A10-A11), Adj-SID(A11-A12), Adj-SID(A12-A13), Adj-SID(A13-A14), Adj-SID(A14-A15), Adj-SID(A15-A16), Adj-SID(A16-A17), Adj-SID(A17-A18), Adj-SID(A18-A19), Adj-SID(A19-A20), Adj-SID(A20-A21), Adj-SID(A21-A22), Adj-SID(A22-A23), Adj-SID(A23-A24), Adj-SID(A24-A25), Adj-SID(A25-A26), Adj-SID(A26-A27), Adj-SID(A27-A28), Adj-SID(A28-A29), Adj-SID(A29-A30), Adj-SID(A30-D) (32 labels)** |

isisd's node repair on `ti_lfa_too_deep` falls back to the link's,
as its node protection does (`docs/ti-lfa.md`). FRR shows no backup
where there is no repair, or another primary next hop.

## Flex-algo topologies

`test/interop/frr_flex_algo_topology_test.rb`, on real routers in
network namespaces, as the topologies above: isisd at every system,
S isisd or FRR. Every system takes part in algorithm 128 but those
the entry leaves out. A cell says the FAD S selects, and S's route
to D in 128: its first hops and metric.

| Entry | What | RFC expects | isisd | FRR isisd |
| --- | --- | --- | --- | --- |
| `fa_exclude_any` | A to D is red; the FAD excludes red: by B | winner D; by B, metric 10 | winner D; by B, metric 10 | winner D; by B, metric 10 |
| `fa_include_any` | A's links are blue, B's green; the FAD includes any of green and yellow: by B | winner D; by B, metric 10 | winner D; by B, metric 10 | winner D; by B, metric 10 |
| `fa_include_all` | A's links have green only, B's green and blue; the FAD includes all of both: by B | winner D; by B, metric 10 | winner D; by B, metric 10 | winner D; by B, metric 10 |
| `fa_exclude_srlg` | A to D is in SRLG 10; the FAD excludes it: by B | winner D; by B, metric 10 | winner D; by B, metric 10 | **not taking part: winner D, disabled (unsupported definition)** |
| `fa_delay` | A's links 20 ms each, B's 2 ms; the FAD's metric is the delay: by B, 4 ms | winner D; by B, metric 4000 | winner D; by B, metric 4000 | **not taking part: winner D, disabled (unsupported definition)** |
| `fa_te_metric` | A's links TE metric 50 each, B's 3; the FAD's metric is TE: by B, 6 | winner D; by B, metric 6 | winner D; by B, metric 6 | **not taking part: winner D, disabled (unsupported definition)** |
| `fa_link_no_metric` | A to D has no delay; the FAD's metric is the delay: A to D is pruned, not 0, so by B | winner D; by B, metric 40000 | winner D; by B, metric 40000 | **not taking part: winner D, disabled (unsupported definition)** |
| `fa_last_resort` | S to A has a delay of 2^24 - 1, the only path: used, as a last resort | winner D; by A, metric 16777216 | winner D; by A, metric 16777216 | **not taking part: winner D, disabled (unsupported definition)** |
| `fa_node_not_participating` | A does not take part: it is pruned, so by B | winner D; by B, metric 10 | winner D; by B, metric 10 | winner D; by B, metric 10 |
| `fa_one_way` | D's link back to A is red, A's to D is not; the FAD excludes red: the two-way check is algorithm 0's, so by A | winner D; by A, metric 2 | winner D; by A, metric 2 | winner D; by A, metric 2 |
| `fa_partition` | the only path is red; the FAD excludes red: D unreachable, no label route | winner D; D unreachable | winner D; D unreachable | winner D; D unreachable |
| `fa_priority` | D's FAD, IGP, priority 100; B's, delay, priority 200: B's wins, so by B on delay | winner B; by B, metric 4000 | winner B; by B, metric 4000 | **not taking part: winner B, disabled (unsupported definition)** |
| `fa_system_id_tie` | A's FAD, IGP, and B's, delay, both priority 100: B has the greater System ID and wins, so by B on delay | winner B; by B, metric 4000 | winner B; by B, metric 4000 | **not taking part: winner B, disabled (unsupported definition)** |
| `fa_no_fad` | no system advertises a FAD: S does not take part | not taking part | not taking part | not taking part |
| `fa_ti_lfa_constraint` | S protects its link to F with TI-LFA; A to D is red, the FAD excludes red: the repair goes by B, where algorithm 0's goes by A | winner D; by F, metric 2; repair via B: Node-SID(D) | winner D; by F, metric 2; repair via B: Node-SID(D) | winner D; by F, metric 2; repair via B: Node-SID(D) |

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

Differs from the RFC: `packet_prefix_sid` (isisd), `packet_ip` (FRR isisd), `packet_prefix_sid` (FRR isisd), `prefix_sid_vl_invalid` (FRR isisd), `algorithm_not_advertised` (FRR isisd), `ti_lfa_pq_node` (FRR isisd), `ti_lfa_figure_2` (FRR isisd), `ti_lfa_too_deep` (FRR isisd), `ti_lfa_figure_1` (FRR isisd), `fa_priority` (FRR isisd), `fa_delay` (FRR isisd), `fa_link_no_metric` (FRR isisd), `fa_exclude_srlg` (FRR isisd), `fa_last_resort` (FRR isisd), `fa_system_id_tie` (FRR isisd), `fa_te_metric` (FRR isisd).
