# The simulator

isis4r-sim is an isisd with a simulated IS-IS area behind it: one real
system with real adjacencies, whose databases also hold the LSPs of
simulated systems. Its neighbours flood them and run SPF over them like
any others. The design follows ospfv2's OSPF simulator.

**Status.** The file and its loader (`ISIS::Sim::Topology`) and the
simulator (`ISIS::Sim::Simulator`) exist. The `isis4r-sim` program and its
`sim.*` API methods come next.

## How it works

The simulator's own system is an ordinary `ISIS::Router`, with real
circuits. Each simulated system is an ordinary `ISIS::Originator` that
writes into that Router's databases, one per level the system and the
simulator share. So every simulated LSP is built like isis4r's own: right
sequence numbers, checksums and lifetimes, refreshed in time, split over
LSP Numbers as its buffer size needs.

- A link is an entry in each end's IS reachability, while it is up. A
  one way link leaves out the far end's.
- The LSPs are flooded on the Router's circuits, so a neighbour learns
  them over its adjacency with the simulator like any others.
- Each database keeps the simulated originators as generators, so the
  update process treats their LSPs as this system's own: a newer copy is
  generated past (RFC 1142 7.3.16.1), and a neighbour's purge of one still
  held is answered by generating it again (7.3.16.4 c).
- After a flush, or with aging off, the simulator generates nothing, and
  copies that arrive are held like any other system's.
- `lsp_lifetime` is the Remaining Lifetime each simulated LSP starts
  with, and each is refreshed at three quarters of it, or the usual 900 s
  when that is sooner.

## The file

YAML. Every problem in it is reported at once, each with where it is
(`routers[2].prefixes[0].metric: ...`). An area is read as written, so
`49.0010` stays `49.0010` (`ISIS::ConfigFile`).

```yaml
simulator:
  system_id: 0000.0000.0009
  hostname: s1
  areas: [49.0001]
  level: 1
  metric_style: wide
  interfaces:
    - { name: eth1, ip_addresses: [10.0.14.2], metric: 10 }
  lsp_lifetime: 1200
grid:
  columns: 4
  rows: 4
  metric: 10
  system_id_base: 0000.0001.0000
  loopbacks: 10.200.0.0/24
routers:
  - name: r4c4
    prefixes:
      - { prefix: 30.0.0.0/24, count: 50, metric: 10 }
  - name: edge
    system_id: 0000.0000.0100
    level: 1-2
    attached: true
    loopback: 10.255.1.1
    externals:
      - { prefix: 50.0.0.0/24, count: 200, metric: 20 }
links:
  - { from: s1, to: r1c1, metric: 10 }
  - { from: r4c4, to: edge, metric: 5 }
```

### Sections

| Section | What it is |
|---|---|
| `simulator` | the real system: isisd's own keys (`ISIS::Router`), and `lsp_lifetime` for the simulated LSPs |
| `grid` | rows by columns of systems, `r1c1` to `rRcC`, linked right and down |
| `routers` | more systems, or more on a grid one by its name |
| `links` | links between any two systems, the simulator included by its hostname or `sim` |

### grid

| Key | Meaning |
|---|---|
| `columns` | 1 to 255 |
| `rows` | 1 to 255 |
| `metric` | of every grid link, 10 by default |
| `system_id_base` | `r2c3` is this plus 0x0203; 0000.0001.0000 by default |
| `loopbacks` | a block: a /32 (or /128) per system, row by row, metric 0 |
| `level` | the grid's levels, the simulator's by default |
| `areas` | the grid's areas, the simulator's by default |

### routers

| Key | Meaning |
|---|---|
| `name` | a grid system's name adds to it; any other name is a new system |
| `system_id` | six octets; a new system needs one, a grid system keeps the grid's |
| `hostname` | sent in TLV 137; the name by default |
| `level` | 1, 2 or 1-2; the simulator's by default |
| `areas` | the simulator's by default |
| `attached` | the default metric ATT bit in its Level 1 LSP Number 0 |
| `overload` | the OL bit in its LSP Number 0 |
| `loopback` | an address, advertised as a /32 or /128 at metric 0 |
| `prefixes` | internal prefixes, each `{ prefix, count, metric }` |
| `externals` | external prefixes, the same shape |
| `lsp_buffer_size` | its LSP size budget, to spread prefixes over LSP Numbers |

### prefixes and externals

| Key | Meaning |
|---|---|
| `prefix` | the first block; host bits must be zero |
| `count` | how many blocks of the same length follow it, 1 by default |
| `metric` | 10 by default |

`30.0.0.0/24` with count 3 is 30.0.0.0/24, 30.0.1.0/24 and 30.0.2.0/24.
The first prefix names the group, which is how an action withdraws it.

### links

| Key | Meaning |
|---|---|
| `from` | a system |
| `to` | another system |
| `metric` | 10 by default |
| `one_way` | only `from` lists `to`, so the two-way check (RFC 1142 7.2.8.2) fails on purpose; FRR 8.4.4 routes over it anyway, measured 2026-11-02 |
| `state` | `up` (the default) or `down` |

A link is named `from--to` and found either way round, or by its number
from 1. It is carried at the levels both ends run, and at Level 1 only
when they share an area. A link with no level left is refused.

## Actions

Each changes the topology and generates the LSPs it touches again, and
logs what it did at info. A link is named `from--to`, either way round, or
by its number from 1.

| Action | Does |
|---|---|
| `link.down` | the link's two entries leave both ends' LSPs |
| `link.up` | they come back |
| `link.toggle` | down if up, up if down |
| `link.flap` | down and up `count` times, `interval` seconds each way |
| `link.metric` | a new metric, within the metric style |
| `router.overload` | the OL bit in that system's LSP Number 0, `on` true or false |
| `router.attached` | the default metric ATT bit in its Level 1 LSP Number 0 |
| `prefixes.withdraw` | a prefix group, named by its first prefix, leaves its LSPs |
| `prefixes.advertise` | the group comes back |
| `refresh` | every simulated LSP generated again, at the next sequence |
| `flush` | every simulated LSP purged (RFC 1142 7.3.16.4) |
| `restore` | after a flush, every one generated again past its purge |
| `aging` | `on` false stops refreshes, so the LSPs run out; true generates them at once |
| `neighbor.stop` | the simulator's hellos stop, on one `circuit` or all |
| `neighbor.start` | they start again |

## What it refuses, and what it keeps

It refuses what cannot go in an LSP:

- a metric over what the metric style carries: 63 when narrow or
  transition, 16777215 for a wide link, 4294967295 for a wide prefix;
- a System ID that is not six octets;
- an `lsp_lifetime` over sixteen bits;
- a hostname over 255 octets.

It also refuses what makes the file mean nothing:

- unknown keys;
- two systems with one System ID;
- a link to a system that does not exist;
- a link from a system to itself;
- two links with one name.

It keeps what is odd but sendable, because a simulator exists to send it:

- a one way link;
- a link metric of 16777215, which RFC 5305 section 3 says keeps a link
  out of SPF;
- a prefix metric past RFC 5305's MAX_PATH_METRIC.

A system no link joins to the simulator is a warning, not an error.
