---
title: isis4r between two FRR routers
tags: [isis]
role: interop
---
# isis4r between two FRR routers

isis4r between two IS-IS areas, with FRR on each side. r1 is isis4r at Level 1-2 in area 49.0001. f1 is FRR at Level 1 in the same area. f2 is FRR at Level 2 only, in area 49.0002. Watch r1 join the two: f1 reaches f2 by the attached bit, and f2 reaches f1 through Level 2.

```
  f1 10.255.0.2 ---- r1 10.255.0.1 ---- f2 10.255.0.3
  FRR, level 1       isis4r, 1 and 2    FRR, level 2
  area 49.0001       area 49.0001       area 49.0002
       10.0.12.0/30           10.0.13.0/30
```

## What to look for

- r1 sets the attached bit in its Level 1 LSP, so f1 reaches f2 by a default route through r1 (`show ip route` on f1).
- r1 puts area 49.0001's prefixes into Level 2, so f2 reaches f1's loopback through r1 (`show isis route` on f2).
- r1 installs its routes in its container's kernel (`ip route` on r1, proto isis), and f1 pings f2's loopback through it.
- `isis-cli` on r1: `show adjacencies`, `show database`, `show routes`.
- r1 advertises only its loopback, the one prefix in `r1/isisd.yml`. isisd does not advertise its interfaces' subnets, as FRR does. So r1 learns 10.0.12.0/30 and 10.0.13.0/30 from f1 and f2 and installs them through them (`ip route` on r1, metric 21 and 22). The kernel's connected route still wins, so traffic is not affected. Measured 2026-11-14.

## Images

`isis4r:latest`, built in an isis checkout beside datalink-socket, and FRR:

```sh
docker build -t isis4r --build-context datalink-socket=../datalink-socket .
docker pull quay.io/frrouting/frr:10.2.1
```

`test/lab/isis4r-frr.sh` in the isis repo runs this lab and checks it, in containerlab or in network namespaces.
