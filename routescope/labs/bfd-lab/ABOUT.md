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
| `loss-with-bfd` | 100% loss on r1 to r2 with netem, the link left up. BFD goes Down, isisd drops the adjacency at once (reason `bfd`), and r1's pings to r3 go by the direct link. |
| `loss-without-bfd` | The same, with that link's two BFD sessions set AdminDown first. RFC 5882 4.2: a router does not act on an AdminDown session, so isisd waits out its 30 s hold time. |
| `sim-misbehaves` | s1 goes silent (r2 Down after its Detection Time), then AdminDown (r2 Down, diagnostic 3), then sends one packet with TTL 254, which r2 discards (RFC 5881 5) while it stays Up. |

Both loss scenarios wait 60 s before the loss. isisd sends its own LSP
at most every 30 s (`MINIMUM_LSP_GENERATION_INTERVAL` in
`lib/isis/database/originator.rb`) and holds a change until then. Run
right after another, a loss scenario found an LSP still held, and
failed over 16 to 21 s later than on a quiet network.

## Measured

Through routescope on ospflab (amd64), 2026-11-22, the isis4r image
built at isis cd3fee5 and bfd4r 3ad0f14. `failover` is from the netem step to the first ping of
three from r1's loopback to r3's that all come back. `restore` is from
clearing the loss to r1's route back via r2. The ping is polled, about
once a second.

| Scenario | Run | failover | restore |
| --- | --- | --- | --- |
| loss-with-bfd | 1 | 2.6 s | 2.6 s |
| loss-with-bfd | 2 | 2.8 s | 1.5 s |
| loss-with-bfd | 3 | 2.5 s | 2.8 s |
| loss-without-bfd | 1 | 28.8 s | 2.0 s |
| loss-without-bfd | 2 | 30.5 s | 0.7 s |

`sim-misbehaves`, two runs: r2 Down 2.2 and 2.1 s after s1 was told to
go silent. The script waits 1 s after Up, then the Detection Time.

## Image

`isis4r:latest`, built in an isis checkout beside datalink-socket and
bfd4r. It carries bfd4r's `bfdd4r`, `bfd4r-cli`, `bfd4r-sim` and
`with-bfdd4r`.

```sh
docker build -t isis4r --build-context datalink-socket=../datalink-socket --build-context bfd4r=../bfd4r .
```
