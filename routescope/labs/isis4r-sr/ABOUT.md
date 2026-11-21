---
title: isis4r forwarding on SR-MPLS labels
tags: [isis, sr, mpls]
role: main
---
# isis4r forwarding on SR-MPLS labels

Two isis4r routers in a line between two FRR routers, all at IS-IS Level 2 with segment routing over MPLS (RFC 8667), and an isis4r-sim with a simulated SR grid behind r2. Each loopback has a Node-SID, and isis4r installs its labels in its container's kernel. Watch a packet cross the line on labels, swapped by isis4r and popped before its last hop, and every router's table grow labels toward the grid.

```
  f1 ---- r1 ---- r2 ---- f2
  FRR     isis4r  isis4r  FRR       level 2, area 49.0001
  16000   17000   18000   16000     SRGB start
  idx 1   idx 2   idx 3   idx 4     Node-SID on 10.255.0.N/32
      10.0.12.0/30    10.0.23.0/30    10.0.34.0/30
                        |
                        s1 (isis4r-sim)   SRGB 19000, idx 9 on 10.255.0.9
                        |                 10.0.35.0/30
                    r1c1 -- r1c2 -- r1c3
                     |       |       |
                    r2c1 -- r2c2 -- r2c3  simulated, SRGB 16000, Node-SIDs
                     |       |       |    101 .. 109 on 10.200.0.1 .. 9
                    r3c1 -- r3c2 -- r3c3  r3c3 with SRGB 21000
```

The SRGBs differ on purpose: a label is always taken from the next router's block, so one from the wrong block would show.

## What to look for

Measured on the VM, 2026-11-16, with isis4r built from the SR-MPLS forwarding branch:

- `ip -M route` on r1: 17004 swaps to 18004 toward r2, for f2's loopback; 17001 and 17003 pop, each toward its owner (PHP); 15000 and 15001 are its Adj-SIDs, popped onto their links. On r2: 18001 swaps to 17001 toward r1, and 18004 pops before f2.
- `ip route show proto isis` on r1: `10.255.0.4 encap mpls 18004 via 10.0.23.2`, isis4r pushing a label for f2's loopback.
- `isis-cli show labels` on r1 or r2 lists the same table, and `isis-cli show segment_routing` every router's SRGB.
- A ping from f1's loopback to f2's, `ping -I 10.255.0.1 10.255.0.4` on f1, crosses on labels: tcpdump shows 17004 into r1, 18004 from r1 to r2, and plain IP from r2 to f2. Back from f2: FRR pushes 18001, r2 swaps it to 17001, r1 pops it.
- r1 down its link to r2 (`ip link set eth2 down` in r1's network namespace): r1 withdraws every label through it, keeping 15000 and 17001 toward f1. Up again: its label table comes back as it was, and the ping crosses again.

### The simulated grid

Measured on the VM, 2026-11-16, isis4r at isis 7ad1b77:

- Toward r1c1's SID, 101, each label comes from the next router's block: f1 sends 17101 to r1, r1 swaps it to 18101 toward r2, r2 swaps it to 19101 toward s1 (`show mpls table` on f1, `ip -M route` on r1 and r2). The same for 105 and 109.
- FRR f1 lists the nine simulated systems in `show isis segment-routing node`, r3c3 with its own block 21000-28999, and s1 with 19000-26999.
- s1 itself has no label toward the grid: it has no real adjacency to a simulated system, so the path ends at s1. Simulated systems forward nothing, so pings stay between f1 and f2.

routescope's SR nodes table lists all 14 systems on r1 as on f1, each with its Router ID, SRGB, SRLB and Node-SID (isis 880bf1f, routescope 0da2b43).

### The grid's sim actions move the labels

Measured on the VM, 2026-11-16, isis4r at isis 880bf1f. r2 holds 9 label routes toward the grid, 18101 to 19101 through 18109 to 19109, all toward s1. Each action was run on s1 with `isis-cli sim ACTION KEY=VALUE`, then undone:

| Action | r2's grid labels |
| --- | --- |
| `link.down link=s1--r1c1`, the grid's only way in | all 9 withdrawn |
| `link.down` on `r1c1--r1c2` and `r1c1--r2c1` | only 18101 (r1c1) left |
| `router.overload router=r1c1 on=true` | only 18101 left: no transit through r1c1 |
| `prefixes.withdraw router=r3c3 prefix=10.200.0.9/32` | 18109 withdrawn, 8 left |
| `link.metric link=r1c1--r1c2 metric=40` | unchanged; r2's metric to r1c2 goes from 30 to 50 |

Each undo brings the 9 back. The out-labels stay in s1's block (19xxx), since s1 is r2's next hop for every grid prefix; r3c3's own block, 21000, is used only by the router before it. FRR f1 follows the same way: with `s1--r1c1` down its nine 161xx labels go, and come back as 16101 to 17101 and so on.

How fast: a change reaches r2's kernel in 30 to 300 ms. A change to an LSP that s1 sent less than 5 s before waits until those 5 s are up: s1's point-to-point link to r2 sends the same LSP at most every 5 s (`MINIMUM_LSP_TRANSMISSION_INTERVAL` in `lib/isis/adjacency/p2p_circuit.rb`). `s1--r1c1` up after a 10 s gap showed in 147 ms; after a 2 s gap, in 2.9 s. Actions run one after the other each took about 4.8 s for this reason.

## Scenario

`scenarios/sr-break.yml`, "Break the SR path", runs in routescope's Scenarios panel:

1. It checks f2's Node-SID along the line: f1 swaps 16004 to 17004, r1 swaps 17004 to 18004, and r2 pops it. Each entry is installed in the kernel.
2. It checks the IS-IS routes push 17004 on f1 and 18004 on r1, and that r2 swaps 18101 into s1's block, 19101.
3. A ping from f1's loopback crosses to f2's.
4. It takes r1's eth2 down: r1 withdraws its route and 17004, keeps 17001 toward f1, and the ping fails.
5. It brings eth2 back up: the route, 17004 to 18004, and the ping come back.

On the VM on 2026-11-16, with routescope at e20935b, it passed twice: 18 of 18 steps, in 15 s and 14 s. The route went 2.7 s after the link, and came back 1.4 s and 0.8 s after it.

## Running it

The host needs the `mpls_router` and `mpls_iptunnel` modules; the lab VMs load them at boot. Each isis4r node sets `net.mpls.platform_labels` through /proc, since the isis4r image has no `sysctl`, and isisd turns on MPLS input on its own interfaces. The FRR nodes set both in `exec`.

Images: `isis4r:latest`, built in an isis checkout beside datalink-socket, and FRR:

```sh
docker build -t isis4r --build-context datalink-socket=../datalink-socket --build-context bfd4r=../bfd4r .
docker pull quay.io/frrouting/frr:10.7.1
```

Start it from routescope's Labs panel (`routescope-labs install isis/isis4r-sr`), or here: `sudo containerlab deploy -t isis4r-sr.clab.yml`.
