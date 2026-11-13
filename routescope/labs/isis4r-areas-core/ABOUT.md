# isis4r in three areas around a Level 2-only backbone

Three IS-IS areas, 49.0001 to 49.0003, around `c0`, a backbone router at Level 2 only in its own area, 49.0000. In each area, `bN` is a Level 1-2 border, `rN` a Level 1-only router, and `sN` an isis4r simulator with a 3x3 grid of Level 1 systems. Each area exercises one thing a border does: **area 1 leaking**, **area 2 summaries**, **area 3 the attached bit**.

```
                   c0 (isisd, L2 only, 49.0000)
                 /          |               \
    b1 (L1-2) ------- b2 (L1-2)            b3 (L1-2)
    /      \          /      \             /      \
 r1 (L1) - s1      r2 (L1) - s2         r3 (L1) - s3
            |                 |                    |
        grid 3x3          grid 3x3             grid 3x3
        49.0001           49.0002              49.0003
        leaking           summaries            false ATT
```

Areas 1 and 2 reach the backbone two ways, through `c0` and through each other. Area 3 has one way, through `c0`.

## The nodes

| Node | Program | Level | Area | System ID | Loopback |
|------|---------|-------|------|-----------|----------|
| c0 | isisd | 2 | 49.0000 | 0000.0000.0100 | 10.255.0.100 |
| b1, b2, b3 | isisd | 1-2 | 49.000N | 0000.0000.000N | 10.255.0.N |
| r1, r2, r3 | isisd | 1 | 49.000N | 0000.0000.002N | 10.255.0.2N |
| s1, s2, s3 | isis4r-sim | 1 | 49.000N | 0000.0000.001N | 10.255.0.1N |
| area N grid | simulated | 1 | 49.000N | 0000.000N.0101 to .0303 | 10.20N.0.1 to .9 |

Each grid's `r3c3` also has 3N.0.0.0/24 to 3N.0.9.0/24. Each simulator enters its grid at `r1c1`. A simulator speaks IS-IS but installs no routes and forwards nothing, so a route through `sN` carries no traffic.

## The links

Every link is point-to-point, metric 10.

| Link | Prefix | Level |
|------|--------|-------|
| c0:eth1 - b1:eth1 | 10.0.1.0/30 | 2 |
| c0:eth2 - b2:eth1 | 10.0.2.0/30 | 2 |
| c0:eth3 - b3:eth1 | 10.0.3.0/30 | 2 |
| b1:eth2 - b2:eth2 | 10.0.12.0/30 | 2 |
| bN:eth3 - sN:eth1 | 10.N.0.0/30 | 1 |
| bN:eth4 - rN:eth1 | 10.N.1.0/30 | 1 |
| rN:eth2 - sN:eth2 | 10.N.2.0/30 | 1 |

## What to look for

- **Level by area.** Between systems in different areas only Level 2 comes up. RFC 1142 section 7.1.3: Level 1 needs "at least one area address in common". `c0` has 3 Level 2 adjacencies and no Level 1 at all.
- **Databases by level.** `r1` holds 12 Level 1 LSPs: b1, r1, s1 and nine grid systems. The Level 2 database holds 4: c0 and the three borders. No simulated system reaches Level 2.
- **Each border carries its area into Level 2.** `b1` reaches area 1's r3c3, 10.201.0.9/32, at 60. `b2` and `c0` reach it at 70, and `b3` at 80, through `c0`.
- **The attached bit.** Each border sets it in its Level 1 LSP 00-00 while Level 2 reaches another area (RFC 1142 section 7.2.9.2). Each `rN` has a default route to its border at 10.
- **Leaking, area 1.** With `policy.leak` on `b1`, `r1` gets area 3's routes in Level 1 with the **up/down bit** (RFC 5302 section 4), and prefers them to its default. `b1` never puts them back into Level 2.
- **Summaries, area 2.** With `policy.summaries` on `b2`, one prefix replaces those it covers in Level 2 (RFC 1195 section 3.2). It goes when nothing it covers is reachable.
- **The attached bit is trusted, area 3.** A Level 1 router follows the **nearest** system with the bit (RFC 1142 section 7.2.9.1). If a simulated system claims it, `r3` follows it, and its traffic goes nowhere.
- **The bit means "some other area".** With `c0` overloaded, `b3` reaches only `c0`'s area. It keeps the bit, so `r3` keeps a default route that leads nowhere useful.

## Scenarios

| Scenario | Does | Checks |
|----------|------|--------|
| `baseline` | nothing | adjacencies and LSP counts by level; area 1 in Level 2 at 70 and 80; the attached bit on each border; each `r`'s default; r1 pings r2 and r3 |
| `leak` | `isis: policy.leak` on b1 with 10.203.0.0/24, then `[]` | r1 has 10.203.0.9/32 at Level 1, metric 90, `up_down: true`; c0 still reaches it through b3; then r1 back to its default |
| `summaries` | `isis: policy.summaries` on b2, then s2's grid cut off, then all back | c0 has 10.202.0.0/24 at 30 and 32.0.0.0/20 at 80, not what they cover; with the grid cut off, both go |
| `false-attached` | c0:eth3 down, then r3c3's attached bit on | b3 clears its bit and r3 loses its default; then r3's default goes to r3c3 at 60 through s3, and r3 cannot ping r1 |
| `nearest-attached` | r3c3's attached bit on, then b3:eth4 down | r3 keeps b3 at 10, not r3c3 at 60; with the link down, b3 through s3 at 20, which r3 cannot ping through: a simulator forwards nothing |
| `core-overload` | `isis: policy.overload` on c0, then off | b3 loses area 1 but keeps its attached bit; r3 has a default and cannot ping r1 |
| `backbone-reroute` | b1:eth2 down, then up | b2 reaches area 1 through c0 at 80 instead of 70; r2 still pings r1 |

`leak`, `summaries` and `core-overload` need routescope's `isis:` scenario step. `test/scenario/isis4r_areas_core_lab_test.rb` loads this lab's node files on simulated time and checks every number above. `test/lab/isis4r-areas-core.sh` runs the lab in containerlab or in network namespaces. The design is routescope's `docs/design/isis-areas-core.md`.
