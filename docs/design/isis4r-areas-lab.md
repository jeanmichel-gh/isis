# The isis4r-areas lab

Status: approved 2026-11-12, with one Level 1 router per area added (the
open question at the end, answered yes). Built in #69. The leak and
summaries scenarios went into a separate lab, isis4r-areas-core (#72).

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
- **routescope shows `ABOUT.md`** from a lab folder above the lab's map,
  and its first paragraph in the list of labs (routescope
  `lib/routescope/lab.rb:35-42`, `:112-115`).
- routescope's own `isis4r-sim` lab shows one simulator behind one
  border. This lab follows its node commands and its `sim.yml` layout.

## The design

### The lab: `routescope/labs/isis4r-areas/`

```
     49.0001                  49.0002                  49.0003
  grid 3x3 (L1)            grid 3x3 (L1)            grid 3x3 (L1)
       |                        |                        |
  s1 (isis4r-sim) - r1     s2 (isis4r-sim) - r2     s3 (isis4r-sim) - r3
       |     (isisd, L1)        |     (isisd, L1)        |     (isisd, L1)
       |            |           |            |           |            |
  b1 (isisd, L1-2) -+      b2 (isisd, L1-2) -+      b3 (isisd, L1-2) -+
       |                        |                        |
       +=========== L2 =========+=========== L2 =========+
       |                                                 |
       +========================= L2 ====================+
```

Nine containers, three areas, 27 simulated systems.

| Node | Program | Image | `routescope.kind` | Level | Area |
|------|---------|-------|-------------------|-------|------|
| b1, b2, b3 | `isisd` | `isis4r:latest` | `isis4r` | 1-2 | 49.000N |
| r1, r2, r3 | `isisd` | `isis4r:latest` | `isis4r` | 1 | 49.000N |
| s1, s2, s3 | `isis4r-sim` | `isis4r:latest` | `isis4r-sim` | 1 | 49.000N |

### Addresses

| Link | Prefix | Ends |
|------|--------|------|
| b1 - b2 | 10.0.12.0/30 | b1:eth1 .1, b2:eth1 .2 |
| b2 - b3 | 10.0.23.0/30 | b2:eth2 .1, b3:eth1 .2 |
| b3 - b1 | 10.0.13.0/30 | b1:eth2 .1, b3:eth2 .2 |
| bN - sN | 10.N.0.0/30 | bN:eth3 .1, sN:eth1 .2 |
| bN - rN | 10.N.1.0/30 | bN:eth4 .1, rN:eth1 .2 |
| rN - sN | 10.N.2.0/30 | rN:eth2 .1, sN:eth2 .2 |

Every link is point-to-point, metric 10, hello 1 s, multiplier 3.

| System | System ID | Loopback |
|--------|-----------|----------|
| b1, b2, b3 | 0000.0000.0001, .0002, .0003 | 10.255.0.1, .2, .3 |
| s1, s2, s3 | 0000.0000.0011, .0012, .0013 | 10.255.0.11, .12, .13 |
| r1, r2, r3 | 0000.0000.0021, .0022, .0023 | 10.255.0.21, .22, .23 |
| area N grid | system_id_base 0000.000N.0000 | 10.20N.0.1 (r1c1) to 10.20N.0.9 (r3c3) |
| area N r3c3 | | plus 3N.0.0.0/24, 10 prefixes, metric 10 |

Each simulator enters its grid at r1c1, as `isis4r-sim` does.

### What forms, and why

- **Between borders, Level 2 only.** The borders are in different areas.
  RFC 1142 section 7.1.3: "The procedures for establishing an adjacency
  between two level 1 ISs require that there be at least one area address
  in common between their two manualAreaAddresses lists". So the Level 1
  hellos on eth1 and eth2 make no adjacency, and Level 2 does.
- **Border to simulator and to r, Level 1 only.** Both run at Level 1.
  b1 still reaches its grid more cheaply through s1 than through r1, so
  the metrics below do not change.
- **Each border's Level 2 LSP carries its area's prefixes.** From b2,
  10.201.0.9/32 (area 1's r3c3) costs 10 (b2-b1) + 10 (b1-s1) + 10
  (s1-r1c1) + 40 (four grid hops) = **70**. Through b3 it costs
  **80**.
- **Each border sets the attached bit** in its Level 1 LSP Number 0,
  because Level 2 reaches the other two areas.
- **Each r has a default route to its border**, from the attached bit,
  and knows nothing outside its area. r1 reaches r2's loopback by its
  default route, b1, Level 2 and b2.

### Scenarios: `scenarios/`

routescope runs these, once the lab is installed with
`routescope-labs install isis/isis4r-areas`.

| File | Does | Checks |
|------|------|--------|
| `baseline.yml` | nothing | each border: 2 Level 1 and 2 Level 2 adjacencies up; `att` on its Level 1 LSP 00-00; b2 reaches 10.201.0.9/32 at Level 2, metric 70, next hop 10.0.12.1; each r has 0.0.0.0/0 to its border; r1 pings r2, r3 pings r1 |
| `backbone-link-down.yml` | `interface: b1:eth1` down, then up | b2 reaches 10.201.0.9/32 at metric 80 through b3 (next hop 10.0.23.2), and r1 still pings r2; then 70 again |
| `border-cut-off.yml` | b1:eth1 and b1:eth2 down, then up | b1 clears `att` (RFC 1142 7.2.9.2); r1 loses its default route; r1 pings r2 before, cannot during, and can again after; b2 and b3 lose area 1's prefixes; all come back |
| `area-prefix-withdraw.yml` | `sim: prefixes.withdraw` on s1, r3c3, 31.0.0.0/24; then advertise | b2 and b3 lose 31.0.0.0/24 to 31.0.9.0/24 at Level 2, then get them back |
| `grid-metric.yml` | `sim: link.metric` on s1, s1--r1c1, 100; then 10 | b1 reaches 10.201.0.9/32 at 150, b2 at 160; then 70 again |

Each starts and ends with the lab whole, so they run in any order.

The pings use routescope's `ping` condition, which runs `ping` inside the
node. The isis4r image has it from isis PR #71. A ping that cannot run
reports nothing received, so a `reachable: false` check would pass
without `ping`. Each scenario that expects a ping to fail first expects
one to succeed.

### `ABOUT.md`

The part of this spec that describes the lab: the summary, the
diagram, the nodes and links, what to look for with its two RFC quotes,
and the scenarios. routescope shows it above the lab's map. It points
back here for the design.

### The check script: `test/lab/isis4r-areas.sh`

Same shape as `isis4r-frr.sh`: `clab` or `netns`, the example's own
files, the same checks both ways. It checks the Level 2 adjacencies,
each r's default route in the kernel, and b2's route to area 1 before,
during and after b1:eth1 down. r1 pings r2's loopback: in netns mode
with the host's `ping`, in clab mode when the image has one, and
otherwise it says it skipped the ping.

### The test on simulated time: `test/scenario/isis4r_areas_lab_test.rb`

It loads the lab's nine files, wires them as the clab file does on
simulated wires, and runs them on a manual clock. It checks every number
the scenarios rely on: the adjacencies by level, 60, 70 and 80, the
attached bit, r1's default route, the reroute, the cut-off, the prefix
withdrawal and the metric change. It runs in the unit suite, with no
root and no Docker, so a change to a file that moves a number fails
there first.

## What is not in this lab

- **No route leaking and no summaries.** isisd has `policy.leak` and
  `policy.summaries`. Each one can be a later scenario.
- **No FRR.** You asked for isis4r and the simulator.
- **No BGP-LS.**

## Open question, answered

**Who installs the default route the attached bit gives?** Only a
Level 1-only router does, and the simulated systems do not route. Asked
on 2026-11-12, answered "add the level 1 router": one real Level 1
isisd per area, r1 to r3, is in the design above.

## Work

1. The lab folder: clab file, `b1`-`b3/isisd.yml`, `r1`-`r3/isisd.yml`,
   `s1`-`s3/sim.yml`, the scenarios, and `ABOUT.md`.
2. `test/lab/isis4r-areas.sh`, and the test on simulated time.
3. README: a line pointing to the lab.
4. The full unit suite before the pull request.
