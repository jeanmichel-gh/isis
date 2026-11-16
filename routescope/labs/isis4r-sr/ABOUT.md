# isis4r forwarding on SR-MPLS labels

Two isis4r routers in a line between two FRR routers, all at IS-IS Level 2 with segment routing over MPLS (RFC 8667). Each loopback has a Node-SID, and isis4r installs its labels in its container's kernel. Watch a packet cross the line on labels, swapped by isis4r and popped before its last hop.

```
  f1 ---- r1 ---- r2 ---- f2
  FRR     isis4r  isis4r  FRR       level 2, area 49.0001
  16000   17000   18000   16000     SRGB start
  idx 1   idx 2   idx 3   idx 4     Node-SID on 10.255.0.N/32
      10.0.12.0/30    10.0.23.0/30    10.0.34.0/30
```

The SRGBs differ on purpose: a label is always taken from the next router's block, so one from the wrong block would show.

## What to look for

Measured on the VM, 2026-11-16, with isis4r built from the SR-MPLS forwarding branch:

- `ip -M route` on r1: 17004 swaps to 18004 toward r2, for f2's loopback; 17001 and 17003 pop, each toward its owner (PHP); 15000 and 15001 are its Adj-SIDs, popped onto their links. On r2: 18001 swaps to 17001 toward r1, and 18004 pops before f2.
- `ip route show proto isis` on r1: `10.255.0.4 encap mpls 18004 via 10.0.23.2`, isis4r pushing a label for f2's loopback.
- `isis-cli show labels` on r1 or r2 lists the same table, and `isis-cli show segment_routing` every router's SRGB.
- A ping from f1's loopback to f2's, `ping -I 10.255.0.1 10.255.0.4` on f1, crosses on labels: tcpdump shows 17004 into r1, 18004 from r1 to r2, and plain IP from r2 to f2. Back from f2: FRR pushes 18001, r2 swaps it to 17001, r1 pops it.
- r1 down its link to r2 (`ip link set eth2 down` in r1's network namespace): r1 withdraws every label through it, keeping 15000 and 17001 toward f1. Up again: its label table comes back as it was, and the ping crosses again.

## Running it

The host needs the `mpls_router` and `mpls_iptunnel` modules; the lab VMs load them at boot. Each isis4r node sets `net.mpls.platform_labels` through /proc, since the isis4r image has no `sysctl`, and isisd turns on MPLS input on its own interfaces. The FRR nodes set both in `exec`.

Images: `isis4r:latest`, built in an isis checkout beside datalink-socket, and FRR:

```sh
docker build -t isis4r --build-context datalink-socket=../datalink-socket .
docker pull quay.io/frrouting/frr:10.2.1
```

Start it from routescope's Labs panel (`routescope-labs install isis/isis4r-sr`), or here: `sudo containerlab deploy -t isis4r-sr.clab.yml`.
