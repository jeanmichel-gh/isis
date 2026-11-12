# isis4r in three areas

Three IS-IS areas, 49.0001 to 49.0003, over a Level 2 backbone. In each area, `bN` is an isis4r border at Level 1-2, `rN` an isis4r router at Level 1, and `sN` an isis4r simulator with a 3x3 grid of Level 1 systems behind it. The borders meet in a Level 2 ring. Watch what a border puts into Level 2, what it tells its own area by the attached bit, and how the backbone reroutes.

```
     49.0001                49.0002                49.0003
   grid 3x3, L1           grid 3x3, L1           grid 3x3, L1
        |                      |                      |
       s1 ---- r1             s2 ---- r2             s3 ---- r3
        |      |               |      |               |      |
       b1 -----+              b2 -----+              b3 -----+
        |                      |                      |
        +======== L2 ==========+========= L2 =========+
        |                                             |
        +===================== L2 ====================+
```

## The nodes

| Node | Program | Level | Area | Loopback |
|------|---------|-------|------|----------|
| b1, b2, b3 | isisd | 1-2 | 49.000N | 10.255.0.1, .2, .3 |
| r1, r2, r3 | isisd | 1 | 49.000N | 10.255.0.21, .22, .23 |
| s1, s2, s3 | isis4r-sim | 1 | 49.000N | 10.255.0.11, .12, .13 |

Area N's grid: r1c1 to r3c3, system IDs 0000.000N.0101 to 0000.000N.0303, loopbacks 10.20N.0.1 to 10.20N.0.9. r3c3 also has 3N.0.0.0/24 to 3N.0.9.0/24. Each simulator enters its grid at r1c1.

## The links

Every link is point-to-point, metric 10.

| Link | Prefix | Level |
|------|--------|-------|
| b1:eth1 - b2:eth1 | 10.0.12.0/30 | 2 |
| b2:eth2 - b3:eth1 | 10.0.23.0/30 | 2 |
| b1:eth2 - b3:eth2 | 10.0.13.0/30 | 2 |
| bN:eth3 - sN:eth1 | 10.N.0.0/30 | 1 |
| bN:eth4 - rN:eth1 | 10.N.1.0/30 | 1 |
| rN:eth2 - sN:eth2 | 10.N.2.0/30 | 1 |

## What to look for

- **Between borders, only Level 2 comes up.** RFC 1142 section 7.1.3: "The procedures for establishing an adjacency between two level 1 ISs require that there be at least one area address in common between their two manualAreaAddresses lists". Each border has 2 adjacencies at Level 1 (its `s` and its `r`) and 2 at Level 2.
- **Each border carries its area into Level 2.** b1 reaches area 1's r3c3, 10.201.0.9/32, at 60: b1-s1, s1-r1c1, four grid hops. b2 reaches it at 70 over b1, or at 80 through b3 when b1-b2 is down.
- **Each border sets the attached bit** in its Level 1 LSP 00-00. RFC 1142 section 7.2.9.2: if a Level 2 system "can reach at least one other area using that metric, it shall - set AttachedFlag for metric k to True". When it cannot, the same section sets it to False.
- **Each `r` follows the bit.** It knows only its own area, and has a default route, 0.0.0.0/0, to its border. So r1 pings r2: out by its default route to b1, over Level 2 to b2, and back the same way.

## Scenarios

| Scenario | Does | Checks |
|----------|------|--------|
| `baseline` | nothing | the adjacencies by level; area 1 in b2's Level 2 at 70; the attached bit on each border; each `r`'s default route; r1 pings r2 and r3 pings r1 |
| `backbone-link-down` | b1:eth1 down, then up | b2 reaches area 1 through b3 at 80, and r1 still pings r2; then 70 again |
| `border-cut-off` | b1:eth1 and b1:eth2 down, then up | b1 clears the attached bit; r1 loses its default route and cannot ping r2; b2 loses area 1; all come back |
| `area-prefix-withdraw` | s1's r3c3 withdraws 31.0.0.0/24 x 10, then advertises | b2 and b3 lose them at Level 2, then get them back |
| `grid-metric` | s1--r1c1 metric 10 to 100, then back | b1 reaches r3c3 at 150, b2 at 160, then at 70 again |

The design is `docs/design/isis4r-areas-lab.md` in the isis repo. `test/scenario/isis4r_areas_lab_test.rb` runs these files on simulated time and checks the same numbers. The ping checks need an isis4r image with `ping` in it.

## Images

Every node runs `isis4r:latest`, built in an isis4r checkout beside datalink-socket:

```sh
docker build -t isis4r --build-context datalink-socket=../datalink-socket .
```
