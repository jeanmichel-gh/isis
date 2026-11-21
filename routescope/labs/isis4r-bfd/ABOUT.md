---
title: isis4r and FRR with BFD
tags: [isis, bfd]
role: interop
---
# isis4r and FRR with BFD

The interop check of isisd's BFD client: isis4r and FRR on one point to point link, each with BFD on it. r1 runs isisd under `with-bfdd4r`, so bfd4r's bfdd4r answers in its namespace, and its interface has `bfd: true`. f1 runs FRR with bfdd and `isis bfd`.

```
  r1 10.255.0.1 ---- f1 10.255.0.2
  isis4r, bfdd4r     FRR 10.7.1, bfdd
        10.0.12.0/30, Level 1, area 49.0001
```

## What to look for

- `isis-cli show adjacencies` on r1: the adjacency Up, and `bfd up`. `show bfd peers` on f1: the session to 10.0.12.1 up.
- r1's hellos carry TLV 148, BFD-Enabled (RFC 6213). FRR's carry none (captured 2026-11-21 on 10.2.1 and on 10.7.1: TLVs 1, 8, 129, 132 and 240), since its isisd does not implement RFC 6213, so BFD is not required on r1's side: the adjacency comes Up on its hellos, and its session then, as FRR does it (RFC 5882 4.1).
- Cut the link with `tc qdisc add dev eth1 root netem loss 100%` on both: the adjacency goes Down on both in under a second, the BFD detection time, where the hold time is 3 s. On r1, the `adjacency` event says reason `bfd`.
- Set a session AdminDown. RFC 5882 4.2: on Up to AdminDown, or Up to Down because the remote end says AdminDown, "clients SHOULD NOT take any control protocol action". On f1 (`bfd`, `peer 10.0.12.1 local-address 10.0.12.2 interface eth1`, `shutdown`) or on r1 (`bfd4r-cli session.admin interface=eth1 peer=10.0.12.2 down=true`), the adjacency stays Up on both, and the session stays AdminDown until it is set back. FRR 10.7.1's bfdd tells its isisd "Admin Down", which it does not act on. FRR 10.2.1, which this lab ran until 2026-11-21, told it Down for r1's AdminDown: its isisd dropped the adjacency and sent TLV 240 Down, r1 went Up to Initializing by RFC 5303 3.2's table, and let go of the session, so the AdminDown did not stay.

## The check

`test/lab/isis4r-bfd.sh` in the isis repo deploys it, waits for BFD and the adjacency on both, puts 100% loss on the link with netem on both ends, and times each side from the moment its peer's netem went on, when it stops hearing anything, to the adjacency going Down: r1 from isisd's log line, f1 from a loop on `show isis neighbor` inside f1. It fails unless both are under a second and r1's reason is `bfd`, then lifts the loss and waits for both to come back.

Then AdminDown, each end in turn: neither may change the adjacency on either side, and r1's session must still be AdminDown six seconds later.

Measured 2026-11-21 on an amd64 VM, five runs in a row, all passing: r1 Down 0.727 to 0.924 s after the loss, f1 0.689 to 0.914 s. Both ends run bfdd4r's and bfdd's 300 ms intervals and a multiplier of 3, so detection alone takes up to 900 ms, which leaves little room under a second. It is not in CI for that reason. On FRR 10.7.1, four runs on the same VM: r1 0.779 to 0.934 s, f1 0.661 to 0.793 s.

## Images

`isis4r:latest`, built in an isis checkout beside datalink-socket and bfd4r, and FRR:

```sh
docker build -t isis4r --build-context datalink-socket=../datalink-socket --build-context bfd4r=../bfd4r .
docker pull quay.io/frrouting/frr:10.7.1
sudo test/lab/isis4r-bfd.sh       # ISIS4R_IMAGE=... for another isis4r image
```
