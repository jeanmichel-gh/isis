---
title: BFD on three isis4r routers
tags: [isis, bfd]
role: main
---
# BFD on three isis4r routers

BFD's main lab, on our own code: three isis4r routers in a triangle,
each running isisd beside bfd4r's bfdd4r, with BFD on every link, and
bfd4r's injector, bfd4r-sim, on a stub link. It shows what BFD is for:
a link that stays up but drops every packet. The design is routescope's
`docs/design/bfd-lab.md`, step 8a.

```
            r2 10.255.0.2 ---- s1 bfd4r-sim
           /  \          eth3   10.0.24.0/30
  eth1    / 10 \ 10    eth2
         /      \
  r1 -------------- r3
  10.255.0.1  30  10.255.0.3
  eth2         eth1
```

Level 1, area 49.0001. r1 reaches r3 via r2 at metric 20. The direct
link, at 30, is the backup. IS-IS hellos are at isisd's defaults,
3 s x 10, so the hold time is 30 s. BFD runs at bfdd4r's 300 ms x 3,
900 ms to detect.

r2's bfdd4r also has a session to s1, added at start by `bfd4r-cli
session.add ... client=lab`, since s1 is not an IS-IS neighbor. s1
opens its side when it starts (`s1/peer.rb`).

## Scenarios

| Scenario | What it shows |
| --- | --- |
| `loss-with-bfd` | 100% loss on r1 to r2 with netem, the link left up. BFD goes Down, isisd drops the adjacency at once (reason `bfd`), and r1's pings to r3 go by the direct link. Then the loss is cleared, and comes back at once, while r1's LSP for the link coming up is a moment old: `failover_again`. |
| `loss-without-bfd` | The same, with that link's two BFD sessions set AdminDown first. RFC 5882 4.2: a router does not act on an AdminDown session, so isisd waits out its 30 s hold time. |
| `sim-misbehaves` | s1 goes silent (r2 Down after its Detection Time), then AdminDown (r2 Down, diagnostic 3), then sends one packet with TTL 254, which r2 discards (RFC 5881 5) while it stays Up. |

Each router sets `lsp_generation`, the backoff
(`docs/design/lsp-generation.md`): a change to its own LSP goes out at
once after a quiet time, then waits 1, 2, 4 s and so on, up to 30 s.
Without it isisd holds a change until 30 s after its last LSP, and a
loss right after another change fails over that much later. So the
scenarios run back to back, with no wait first.

## Measured

Through routescope on ospflab (amd64, 6 CPUs), the isis4r image built
at isis 885f38a and bfd4r 6b5c09c, one scenario straight after another,
in the order below, with the host's load average (1 minute) at the
start. The VM was paused for about two hours between the fourth run and
the fifth. `failover` is from the netem step to the first ping of three
from r1's loopback to r3's that all come back. `restore` is from
clearing the loss to r1's route back via r2. The ping is polled, about
once a second.

| Time (UTC) | Load | Scenario | failover | restore | failover_again |
| --- | --- | --- | --- | --- | --- |
| 2026-11-22 23:09 | 98 | loss-with-bfd | 2.7 s | 0.2 s | 3.5 s |
| 2026-11-22 23:10 | 86 | loss-without-bfd | 30.5 s | 2.4 s | |
| 2026-11-22 23:11 | 65 | loss-with-bfd | 1.3 s | 1.8 s | 8.9 s |
| 2026-11-22 23:11 | 61 | loss-without-bfd | 30.3 s | 2.6 s | |
| 2026-11-23 01:18 | 46 | loss-with-bfd | 2.6 s | 3.1 s | 8.9 s |

`failover_again` is longer than `failover` because of the LSP
generation backoff, seen in r1's log. Each change r1 makes to its LSP
within 30 s of the one before doubles the wait for the next: 1, 2, 4,
then 8 s. In the 01:18 run, r1's LSP changed at 01:17:54, 01:18:10, 15
and 23. BFD went Down for the second loss at 01:18:16.78; r1 moved its
own routes at once, but its LSP went out at 23.11, 8.0 s after the one
before. The 23:09 run came after a quiet time, so its second LSP went
out 0.3 s after BFD Down.

Flooding adds no wait. r3 stored r1's LSP 3 ms after r1 generated it:
isisd sends a new LSP at once when the neighbour has acknowledged the
one before (`clear_srm` in `lib/isis/database/update_process.rb`).

`sim-misbehaves`, two runs, both at 01:18: r2 Down 3.0 and 2.1 s
after s1 was told to go silent. The script waits 1 s after Up, then
the Detection Time.

## Image

`isis4r:latest`, built in an isis checkout beside datalink-socket and
bfd4r. It carries bfd4r's `bfdd4r`, `bfd4r-cli`, `bfd4r-sim` and
`with-bfdd4r`.

```sh
docker build -t isis4r --build-context datalink-socket=../datalink-socket --build-context bfd4r=../bfd4r .
```
