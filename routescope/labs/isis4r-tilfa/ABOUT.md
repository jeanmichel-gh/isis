---
title: isis4r TI-LFA, tested against FRR
tags: [isis, sr, mpls]
role: interop
---
# isis4r TI-LFA, tested against FRR

isis's lab for testing TI-LFA (RFC 9855) on real routers. Six isis4r routers and one FRR in a ring, with a chord from r2 to r5, and an isis4r-sim, s1, behind r3. Its scenarios check; they do not teach. routescope's `ti-lfa` lab teaches TI-LFA with pauses, on RFC 9855's Figure 1.

This is the interop and testing lab. Every router but f1 runs isis4r; f1 is FRR 10.7.1, there to compare its repairs with isis4r's and to carry isis4r's repair through a router of another make.

```
  f1 ----- r1 ----- r2 ----- r3 ----- s1 -- t1 (simulated)
  |    10      10   |   10   |   10
10|               10|      10|
  |                 |        |
  r6 ------------- r5 ------ r4
         1000          1000

  r1  21000   r2  22000   r3  23000   r4  24000   SRGB start; Node-SID
  r5  25000   r6  26000   f1  16000 (FRR)         index N on 10.255.0.N
  s1  19000, index 9      t1  30000, index 10     simulated by s1
```

Every SRGB is 1000 labels, and every SRLB starts at 15000. The SRGBs differ on purpose: a label from the wrong block shows.

- r1's eth1, toward r2, has `ti_lfa: node`. r2's eth1, toward r1, has `ti_lfa: link`. f1's eth1, toward r1, has `isis fast-reroute ti-lfa level-2`.
- The links r4-r5 and r5-r6 are at metric 1000. They keep P and Q apart: with r2 down, r1's repair to r3 is Node-SID(r6), then the Adj-SIDs r6-r5 and r5-r4, through f1 (RFC 9855 5.4).
- isisd gives an Adj-SID the lowest free SRLB label when the adjacency first comes up. r6 starts 20 s after the others, so r5's Adj-SID toward r4 is 15000 and toward r6 15001. r5's eth3 and r6's eth2 carry no Adj-SID (`adj_sid: false`), so r6's only one, toward r5, is 15000. The repairs below hold on every start.

## Scenarios

### repairs

The backups each PLR computes, read from routescope's `isis_backup` and `ti_lfa` views, then `policy.ti_lfa` changed on r1 while isisd runs. Measured on ospflab, 2026-11-23, isis4r at isis c59ed42:

| PLR | To | Mode | Via | Labels |
| --- | --- | --- | --- | --- |
| r1 | r3 | node | f1 | 16006, 15000, 15000, 24003 |
| r1 | r5 | node | f1 | 16006, 15000 |
| r1 | t1 | node | f1 | 16006, 15000, 15000, 24010 |
| r1 | r2 | node, link fallback | f1 | 16006, 15000, 25002 |
| r1 | r3 | link | f1 | 16006, 15000, 25003 |
| r2 | r1 | link | r5 | 15001, 26001 |
| f1 | r3 | FRR | r6 | 26006, 15000, 23003 |

- r1 protects 6 destinations and leaves none unprotected.
- f1's repair is FRR's own. It pushes its first hop's Node-SID, and ends with r3's label in r3's own SRGB, 23003. Its Q is r5, and RFC 9855 7.1 asks for r3's label in Q's SRGB, 25003. r5 has no label route for 23003. In isis's namespace tests, FRR 10.5.1 ended its repairs with Adj-SIDs to the destination instead (`docs/ti-lfa.md`).

### failover

r1's link to r2 loses carrier. The scenario checks that r1 forwards on its backup, then converges, then puts the link back.

- An IP flow from r1, sourced from 10.0.17.1, and a labelled flow from f1, both to r3's loopback, count what the failure loses.
- The IP flow is sourced from r1's link address, not its loopback. A reply to r1's loopback goes on label 22001 through r2, and a label route has no backup in the kernel (routescope `docs/design/ti-lfa.md`, step 2c). With the loopback as source, the replies were lost until isisd converged.

Measured on ospflab, 2026-11-23, one run, with the host at a load near 150 on 6 CPUs and swapping:

- r1 forwarded on its backup 0.64 s after the link went down: through f1 (10.0.17.2) on 16006, 15000, 15000, 24003.
- isisd converged on the path through f1 at metric 1040 in 9.9 s; the link back, r1 was on r2 again in 1.3 s.
- The IP flow lost 4.1 s; the labelled flow from f1 lost 11.0 s. f1's flow enters r1 on r1's label for r3, and a label route has no backup in the kernel (step 2c), so it waits for isisd.

Under that load an earlier run saw r2's adjacency to r5 drop, and r1 converge on metric 2030. The scenario sets no bounds on the losses yet; they wait for a quiet host.

### sr-faults

Each SR entry of the fault catalog (`ISIS::Fault`, `docs/protocol-testing.md`) goes in s1's own LSP, with prefix 10.255.250.1/32 at index 500, through isis4r-sim's HTTP API. r3, whose next hop toward t1 is s1, shows what an SRGB entry does. r1 (isisd) and f1 (FRR 10.7.1) show what a Prefix-SID entry does. Each is cleared after, and every label comes back.

| Entry | r3 (isisd) | r1 (isisd) | f1 (FRR 10.7.1) |
| --- | --- | --- | --- |
| `srgb_range_zero`, `srgb_overlap`, `srgb_reserved` | no label toward t1, routes it as IP; pops 23009 and 23500 toward s1 | 21500 to 22500 | 16500 to 21500 |
| `sr_capabilities_twice` | 23010 to 19010, the first SRGB | 21500 to 22500 | 16500 to 21500 |
| `prefix_sid_vl_invalid` | | no 21500; IP route | no 16500, no route |
| `prefix_sid_label` | | no 21500 | no 16500 |
| `algorithm_not_advertised` | drops 23009, s1's own | no 21500 | 16500 to 21500 |
| `prefix_sid_duplicate` | | no 21500 | 16500 to 21500 |

These are this lab's results, on FRR 10.7.1. isis's `docs/fault-matrix.md` holds the namespace tests' results on FRR 10.5.1.

**A stale route on f1.** Measured 2026-11-23: when `sr_capabilities_twice` is cleared, 10.255.250.1 leaves s1's LSP. FRR's isisd drops it from `show isis route` and drops label 16500. zebra and the kernel keep the route, with label 21500 toward r1, which r1 no longer has, so f1's traffic to that prefix is lost. It stayed for minutes, through the next entries, until isisd was restarted. The same route after `srgb_range_zero` went cleanly. The difference seen: the route that stayed had a TI-LFA backup (26006, 15000, 19500), and the other had none. The scenario reads isisd's tables, which are right, so it does not catch this; `ip route show 10.255.250.1` on f1 does. To clear it, restart f1's isisd (`kill` its PID; watchfrr starts it again).

### behaviours

The catalog's three behaviours, run by isis4r-sim one at a time.

Measured on ospflab, 2026-11-23:

- `flap`: s1's hellos on eth1 stop for 15 s. r3 lost its route to t1 after 9.9 s, about its hold time of 10 s, and label 23010 with it. The hellos back, r3 had t1 again at metric 20 after 15.9 s, and 23010 to 19010.
- `stale_lsp`: t1's LSP held as it was while s1 reports t1 gone. r3 and r1 drop t1, by the two-way check. Stopped, r3 has t1 at metric 20 and f1 at 50.
- `srgb_change`: s1's SRGB moves to 119000. r3's 23010 swaps to 119010, and 23009 still pops toward s1. Stopped, 23010 swaps to 19010 again.

## What it does not check

- **Labelled packets at the PLR.** A scenario has no step that sends a packet with a chosen label stack. So the catalog's packet entries (`packet_prefix_sid`, `packet_mpls_ttl_1`, `packet_unknown_label`, `packet_adj_sid`) are checked only in isis's `test/interop/kernel_ti_lfa_test.rb`. Here, only the flows are: plain IP from r1, and FRR's labels from f1.
- **The fault matrix.** It runs in network namespaces (`rake fault_matrix`), not here.
- **s1 overloaded.** An overloaded isis4r-sim cuts off every system behind it, since overload blocks transit.

## Running it

```sh
docker build -t isis4r --build-context datalink-socket=../datalink-socket --build-context bfd4r=../bfd4r .
docker pull quay.io/frrouting/frr:10.7.1
sudo containerlab deploy -t isis4r-tilfa.clab.yml
```

Label routes need the `mpls_router` and `mpls_iptunnel` modules on the host. routescope finds the lab under `routescope/labs`, and runs its scenarios from the Scenarios panel.
