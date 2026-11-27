---
title: isis4r flex-algo, tested against FRR
tags: [isis, sr, mpls]
role: interop
---
# isis4r flex-algo, tested against FRR

isis's lab for testing flex-algo (RFC 9350) on real routers. Four isis4r routers and one FRR, three paths from r1 to r4, so three algorithms take three paths, and an isis4r-sim, s1, behind r4. Its scenarios check; they do not teach.

This is the interop and testing lab. Every router but f1 runs isis4r; f1 is FRR 10.7.1, on the middle path, there to carry algorithm 129's labels through a router of another make, and to elect a FAD beside isis4r's.

```
         r2              top: IGP 10 + 10, delay 20 ms each, red
       /    \
     r1 - f1 - r4 -- s1 -- t1 (simulated)
       \    /           middle: IGP 15 + 15, delay 5 ms each
         r3              bottom: IGP 20 + 20, delay 2 ms each

  r1  21000   r2  22000   r3  23000   r4  24000   SRGB start; Node-SID
  f1  16000 (FRR)         s1  19000   t1  30000   index N on 10.255.0.N,
                                                  100 + N for 128, 200 + N for 129
```

Every router is at Level 1: FRR 10.7.1 elects a FAD at Level 1 only (isis `docs/design/flex-algo.md`, decision 8). Every SRGB is 1000 labels, every SRLB starts at 15000, and the SRGBs differ, so a label from the wrong block shows.

| Algorithm | FAD | r1 to r4 |
| --- | --- | --- |
| 0 | | the top, through r2, IGP 20 |
| 128 | r4's, delay, no constraint, priority 0 | the bottom, through r3, 4 ms |
| 129 | f1's, IGP, excluding red, priority 200; r4's, IGP, no constraint, priority 100 | the middle, through f1, IGP 30 |

- f1 elects r4's FAD for 128 and disables it, "unsupported definition": FRR runs the IGP metric only. So f1 does not take part in 128, and 128 prunes it.
- r2's links are all red, so 129 does not reach r4 from r2.
- r4's FAD for 128 is at priority 0, so a FAD from s1 at priority 0 wins on System ID. The faults scenario relies on that.
- f1's links carry `delay 5000 min 5000 max 5000`, so it sends the minimum delay, sub-TLV 34, that 128 reads.
- r1 has `ti_lfa: link` on each interface.

Measured on ospflab, 2026-11-27, isis4r at isis 565cb36, FRR 10.7.1. r1's labels for r4, as isisd shows them, with their TI-LFA backups:

| Label | Algorithm | Next hop, label | Backup |
| --- | --- | --- | --- |
| 21004 | 0 | r2, 22004 | f1, 16004 |
| 21104 | 128 | r3, 23104 | r2, 22104: the top, since f1 is pruned from 128 |
| 21204 | 129 | f1, 16204 | r3, 23204: the bottom, never the red top |

f1, FRR, shows 128's FAD, r4's, as "disabled (unsupported definition)", and 129's as its own, at priority 200. It pops 16204 toward r4, and swaps t1's 16210 to r4's 24210.

The backups of label routes are computed and shown, not installed (routescope `docs/design/ti-lfa.md`, step 2c), so a label moves when isisd converges.

## Scenarios

Each reads label tables, with `mpls_label`: a label's next hop and out label is the path its algorithm takes.

All five passed on ospflab, 2026-11-27, the first four three times and election once, the last time from a fresh start.

### algorithms

Each algorithm's path from r1 to r4 and to t1, and f1's 129 labels. f1 has no 128 label, and r2 no 129 label for r4.

### election

f1's priority for 129 goes from 200 to 50 through vtysh. r4's FAD, with no constraint, wins at every router: r1's 129 label for r4 went over the top, through r2, in 2.0 s, r2 got its own 129 label for r4, and f1 kept reaching r1 on 129. Back to 200, and 129 went through f1 again in 1.4 s.

### failover

r1 loses each link in turn. With the bottom down, 128 goes over the top; with f1 down, 129 goes over the bottom; with the top down, algorithm 0 goes through f1. Each label moved 10.3 to 11.1 s after its link went down, over three runs: about isisd's hold time of 10 s, since the backups of label routes are not installed. Each link back, its label was back in 1.3 to 2.6 s.

### faults

Entries of the fault catalog's flex-algo group (isis `docs/protocol-testing.md`) in s1's own LSP:

| Entry | What r1 does | RFC |
| --- | --- | --- |
| `fad_split_differs` | uses s1's first FAD, priority 100: 128 on the IGP metric, over the top | 9350 section 6: the first |
| `fad_unsupported` | elects s1's, calculation type 1, and stops taking part in 128: r1 and r4 drop their 128 labels; 129 goes on | 9350 section 5.3: stop taking part |
| `fad_s_bit` | ignores s1's FAD: 128 stays on the delay | 9350 section 5.1: ignore |
| `fad_subtlv_twice` | ignores it | 9350 section 6.1: ignore |
| `fad_eag_length` | ignores it | 9350 section 6.1: ignore |
| `prefix_sid_algorithm_twice` | r4 pops 24500 toward s1, index 500, the first, and has no 24501. f1, FRR, swaps 16500 to 24500, and has no 16501 | 8402 section 3.1: the first |

r1 took part in 128 again 3.5 to 11.2 s after `fad_unsupported` was cleared.

### behaviours

isis4r-sim's flex-algo behaviours on t1, with their defaults. `fad_takeover`, t1's FAD for 128 at priority 255 on the IGP metric for 30 s: r1's 128 label for r4 went over the top in 1.6 to 2.9 s, and back over the bottom 28.8 to 30.5 s later. `participation_flap`, t1 out of 128 for 10 s, three times: r1's 128 label for t1 went, and came back each time.

## What it does not check

These wait for routescope's flex-algo views for isisd and their scenario steps (routescope `docs/design/flex-algo-views.md`; isis `docs/design/flex-algo.md`, "Work"):

- **The FAD each router elects, and whether it takes part.** No condition reads them yet, so the scenarios read the labels each election leaves.
- **`policy.flex_algo`.** routescope's `isis:` step takes four actions, and this is not one. The election scenario changes f1's FAD, through vtysh, instead.
- **The behaviours' own keys.** routescope's `sim:` step passes `router`, `count`, `down`, `up` and `link`, but not `algorithm`, `priority`, `metric_type`, `hold` or `delay`, so the behaviours run with their defaults. `delay_change` changes a metric and no path here, and no condition reads an algorithm's metric, so it is not run.
- **Labelled packets.** A scenario has no step that sends a packet with a chosen label stack, so no packet is sent on an algorithm's label. A `flow` or `traceroute` follows algorithm 0's IP routes.
- **The flex-algo link entries of the catalog.** An entry's link from s1 goes toward a system that does not report it back, so the two-way check drops it, and no path changes. isis's `test/interop/frr_flex_fault_test.rb` checks them, as the fault matrix's "Flex-algo data".
- **TI-LFA's backups for an algorithm, used.** They are computed and shown, not installed.

## Running it

```sh
docker build -t isis4r --build-context datalink-socket=../datalink-socket --build-context bfd4r=../bfd4r .
docker pull quay.io/frrouting/frr:10.7.1
sudo containerlab deploy -t isis4r-flexalgo.clab.yml
```

Label routes need the `mpls_router` and `mpls_iptunnel` modules on the host. routescope finds the lab under `routescope/labs`, and runs its scenarios from the Scenarios panel.
