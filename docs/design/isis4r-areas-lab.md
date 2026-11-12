# The isis4r-areas lab

Status: draft, waiting for approval.

## The problem

We want a lab with several IS-IS areas. Each area should hold many Level 1
systems, and the areas should meet over a Level 2 backbone. It shows
three things:

1. what a Level 1-2 router puts into Level 2;
2. what it tells its own area through the attached bit;
3. how the backbone reroutes when a link or a border fails.

The one example lab in this repo, `isis4r-frr`, has two areas and one
system in each. That is too small to show any of this.

## What exists

Read on master at 788822b.

- **`examples/containerlab/isis4r-frr/`** is the only lab here. Its
  layout is a clab file, one folder per node, and a check script,
  `test/lab/isis4r-frr.sh`. The script runs the lab in containerlab or in
  network namespaces, and checks the same things both ways.
- **isisd at Level 1-2** sets the attached bit in its Level 1 LSP Number 0
  when Level 2 reaches another area (`lib/isis/router.rb:275-279`).
  RFC 1142 section 7.2.9.2: "If a level 2 Intermediate system discovers,
  after computing the level 2 routes for metric k, that it can reach at
  least one other area using that metric, it shall - set AttachedFlag for
  metric k to True; - regenerate its Level 1 LSP with LSP number zero".
  When it cannot reach another area, the same section says to set it to
  False.
- **A Level 1-only isisd** installs 0.0.0.0/0 toward the nearest attached
  system (`lib/isis/spf/decision.rb:148-156`).
- **isis4r-sim** (`docs/simulator.md`) runs one real IS-IS system with a
  grid of simulated systems behind it. It takes the grid's `level` and
  `areas`, and per router `attached`, `overload`, `prefixes` and
  `externals`. Its actions include `link.down`, `link.metric`,
  `prefixes.withdraw` and `router.overload`.
- **routescope scenarios** (routescope `docs/scenarios.md`) have the
  conditions this lab needs: `isis_adjacencies`, `isis_lsp` with `att`,
  and `isis_route` with `level`, `metric` and `next_hop`. They also have
  `sim:` steps and `interface:` steps. With more than one simulator,
  every `sim:` step must name its simulator with `node:`.
- routescope's own `isis4r-sim` lab shows one simulator behind one
  border. This lab follows its node commands and its `sim.yml` layout.

## The design

### The lab: `examples/containerlab/isis4r-areas/`

```
     49.0001                 49.0002                 49.0003
  grid 3x3 (L1)           grid 3x3 (L1)           grid 3x3 (L1)
       |                       |                       |
  s1 (isis4r-sim)         s2 (isis4r-sim)         s3 (isis4r-sim)
       | eth3                  | eth3                  | eth3
  b1 (isisd, L1-2) ====== b2 (isisd, L1-2) ====== b3 (isisd, L1-2)
       \\ eth2      eth1      eth2      eth1      eth2 //
        \\=================== L2 backbone ============//
```

Six containers, three areas, 27 simulated systems.

| Node | Program | Image | `routescope.kind` | Level | Area |
|------|---------|-------|-------------------|-------|------|
| b1 | `isisd` | `isis4r:latest` | `isis4r` | 1-2 | 49.0001 |
| b2 | `isisd` | `isis4r:latest` | `isis4r` | 1-2 | 49.0002 |
| b3 | `isisd` | `isis4r:latest` | `isis4r` | 1-2 | 49.0003 |
| s1 | `isis4r-sim` | `isis4r:latest` | `isis4r-sim` | 1 | 49.0001 |
| s2 | `isis4r-sim` | `isis4r:latest` | `isis4r-sim` | 1 | 49.0002 |
| s3 | `isis4r-sim` | `isis4r:latest` | `isis4r-sim` | 1 | 49.0003 |

### Addresses

| Link | Prefix | Ends |
|------|--------|------|
| b1 - b2 | 10.0.12.0/30 | b1:eth1 .1, b2:eth1 .2 |
| b2 - b3 | 10.0.23.0/30 | b2:eth2 .1, b3:eth1 .2 |
| b3 - b1 | 10.0.13.0/30 | b3:eth2 .2, b1:eth2 .1 |
| b1 - s1 | 10.1.0.0/30 | b1:eth3 .1, s1:eth1 .2 |
| b2 - s2 | 10.2.0.0/30 | b2:eth3 .1, s2:eth1 .2 |
| b3 - s3 | 10.3.0.0/30 | b3:eth3 .1, s3:eth1 .2 |

Every link is point-to-point, metric 10, hello 1 s, multiplier 3.

| System | System ID | Loopback |
|--------|-----------|----------|
| b1, b2, b3 | 0000.0000.0001, .0002, .0003 | 10.255.0.1, .2, .3 |
| s1, s2, s3 | 0000.0000.0011, .0012, .0013 | 10.255.0.11, .12, .13 |
| area N grid | system_id_base 0000.000N.0000 | 10.20N.0.1 (r1c1) to 10.20N.0.9 (r3c3) |
| area N r3c3 | | plus 3N.0.0.0/24, 10 prefixes, metric 10 |

Each simulator enters its grid at r1c1, as `isis4r-sim` does.

### What forms, and why

- **Between borders, Level 2 only.** The borders are in different areas.
  RFC 1142 section 7.1.3: "The procedures for establishing an adjacency
  between two level 1 ISs require that there be at least one area address
  in common between their two manualAreaAddresses lists". So the Level 1
  hellos on eth1 and eth2 make no adjacency, and Level 2 does.
- **Border to simulator, Level 1 only.** The simulator runs at Level 1.
- **Each border's Level 2 LSP carries its area's prefixes.** From b2,
  10.201.0.9/32 (area 1's r3c3) costs 10 (b2-b1) + 10 (b1-s1) + 10
  (s1-r1c1) + 40 (four grid hops) = **70**. Through b3 it costs
  **80**.
- **Each border sets the attached bit** in its Level 1 LSP Number 0,
  because Level 2 reaches the other two areas.

### Scenarios: `scenarios/`

routescope runs these, once the folder is copied into `~/labs`.

| File | Does | Checks |
|------|------|--------|
| `baseline.yml` | nothing | each border: 1 Level 1 and 2 Level 2 adjacencies up; `att` on its Level 1 LSP 00-00; b2 reaches 10.201.0.9/32 at Level 2, metric 70, next hop 10.0.12.1 |
| `backbone-link-down.yml` | `interface: b1:eth1` down, then up | b2 reaches 10.201.0.9/32 at metric 80 through b3 (next hop 10.0.23.2), then at 70 again |
| `border-cut-off.yml` | b1:eth1 and b1:eth2 down, then up | b1 clears `att` (RFC 1142 7.2.9.2); b2 and b3 lose area 1's prefixes; all come back |
| `area-prefix-withdraw.yml` | `sim: prefixes.withdraw` on s1, r3c3, 31.0.0.0/24; then advertise | b2 and b3 lose 31.0.0.0/24 at Level 2, then get it back |
| `grid-metric.yml` | `sim: link.metric` on s1, r1c1--r1c2, 100 | b2's metric to 10.201.0.9/32 changes; b1 regenerates its Level 2 LSP |

Each starts and ends with the lab whole, so they run in any order.

### The check script: `test/lab/isis4r-areas.sh`

Same shape as `isis4r-frr.sh`: `clab` or `netns`, the example's own
files, the same checks both ways. It checks adjacencies, the attached
bit, and b2's route to area 1 before and after b1:eth1 goes down.

## What is not in this lab

- **No route leaking and no summaries.** isisd has `policy.leak` and
  `policy.summaries`. Each one can be a later scenario.
- **No FRR.** You asked for isis4r and the simulator.
- **No BGP-LS.**

## Open question

**Nobody here installs the default route the attached bit gives.** Only
a Level 1-only router does that, and the simulated systems do not route.
The lab shows the bit in the LSP, but not its effect. I can add one real
Level 1-only isisd per area, `r1` to `r3`, beside each simulator. That
makes nine containers, and adds a scenario: `r1` follows its default
route to b1, and moves to nothing when b1 is cut off. Should I add them,
in all three areas or in area 1 only?

## Work, after approval

1. The lab folder: clab file, `b1`-`b3/isisd.yml`, `s1`-`s3/sim.yml`,
   the scenarios.
2. `test/lab/isis4r-areas.sh`, run in netns mode on the VM.
3. README: a line pointing to the lab.
4. The full unit suite before the pull request.
