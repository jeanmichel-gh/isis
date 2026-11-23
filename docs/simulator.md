# The simulator

isis4r-sim is an isisd with a simulated IS-IS area behind it: one real
system with real adjacencies, whose databases also hold the LSPs of
simulated systems. Its neighbours flood them and run SPF over them like
any others. The design follows ospfv2's OSPF simulator.

**Status.** The file and its loader (`ISIS::Sim::Topology`), the
simulator (`ISIS::Sim::Simulator`), and the `isis4r-sim` program with its
`sim.*` API methods exist.

## Running it

```sh
sudo isis4r-sim -c /lab/sim.yml -l -
isis-cli sim state
isis-cli sim link.down link=r1c1--r1c2
isis-cli sim router.overload router=r1c1 on=true
```

isis4r-sim takes isisd's options (`docs/isisd.md`), with `-c` naming the
simulated area's file, `/lab/sim.yml` by default, and `--http`, its HTTP
API (below). It answers isisd's API
on the same socket, the simulator's own system answering every `show.*`,
and the `sim.*` methods below as well. Its log says what it started as
and how many systems it simulates, and warns of any system no link
reaches.

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
| `segment_routing` | SR-MPLS (RFC 8667) for the simulated systems, and their blocks by default |

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
| `sids` | with `segment_routing`: r1c1's Prefix-SID index on its loopback, each next system the next, row by row; needs `loopbacks` |

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
| `sid` | with `segment_routing`: its loopback's Prefix-SID index; needs an IPv4 `loopback` |
| `srgb` | its own SRGB, a list of `{ start, size }`, in place of the file's |

### segment_routing

With it, every simulated system with an IPv4 loopback advertises SR-MPLS
as isisd does (`docs/isisd.md`): TLV 242 with its SRGB and SRLB, its
loopback's Prefix-SID when it has a `sid`, and an Adj-SID on each of its
links. The simulator's own system takes `segment_routing` under
`simulator:`, as isisd. No label is installed for a simulated system.

| Key | Meaning |
|---|---|
| `srgb` | a list of `{ start, size }`, 16000 and 8000 by default |
| `srlb` | one `{ start, size }`, 15000 and 1000 by default |

```yaml
segment_routing:
  srgb: [{ start: 16000, size: 8000 }]
grid: { rows: 4, columns: 4, loopbacks: 10.200.0.0/24, sids: 101 }
routers:
  - { name: r4c4, srgb: [{ start: 20000, size: 8000 }] }
```

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

## API

isis4r-sim answers these besides isisd's methods; isisd answers none of
them. Each action answers `{ action, state: { generating, aging } }`, or an
error naming the parameter or value at fault.

| Method | Params |
|---|---|
| `sim.state` | |
| `sim.graph` | |
| `sim.link.down` | `link` |
| `sim.link.up` | `link` |
| `sim.link.toggle` | `link` |
| `sim.link.flap` | `link`, `count`, `interval` |
| `sim.link.metric` | `link`, `metric` |
| `sim.router.overload` | `router`, `on` |
| `sim.router.attached` | `router`, `on` |
| `sim.prefixes.withdraw` | `router`, `prefix` |
| `sim.prefixes.advertise` | `router`, `prefix` |
| `sim.refresh` | |
| `sim.flush` | |
| `sim.restore` | |
| `sim.aging` | `on` |
| `sim.neighbor.stop` | `circuit` |
| `sim.neighbor.start` | `circuit` |

`sim.state` gives the counts, the metric style and the largest link
metric it carries, each of the simulator's interfaces with whether it is
sending hellos, every system with its levels, flags, prefix counts, prefix
groups by their first prefix, withdrawn groups and LSP Numbers, and every
link with its number, state, metric and levels. `sim.graph` gives nodes and links for a map.

## The HTTP API

isis4r-sim also answers HTTP/1.1 on 127.0.0.1:8080, as bgp4r-sim,
vtep4r-sim and bfd4r-sim do (routescope
`docs/design/protocol-conventions.md`, part 4): `--http ADDRESS:PORT`
moves it, `--http off` turns it off. It reads and acts in the daemon's
own loop, as the socket's API does. JSON in and out, one request per
connection.

A POST needs the header `X-ISIS4R: routescope`, compared in lower case;
without it, 403. A refused request is a 4xx with `{"error": ...}`: 400
for a parameter or value at fault, 404 for no such path, 405 for a
method other than GET and POST.

| Path | Does |
| --- | --- |
| `GET /api/status` | the version, the simulator's system, how many systems and links, whether it generates and ages, how many faults, and the paths |
| `GET /api/state` | `sim.state` |
| `GET /api/topology` | `sim.graph` |
| `GET /api/sent` | the faults injected and the octets sent, each with when |
| `GET /api/catalog` | the fault catalog (`ISIS::Fault`, `docs/protocol-testing.md`) and each POST's parameters |
| `GET /api/events` | the events after `since=N`, as the socket's `events.subscribe` replays them |
| `POST /api/fault` | `case`, `router`, `prefix`, `index`: a catalog entry in a simulated system's LSPs |
| `POST /api/plan` | the same, built and answered, injected nowhere |
| `POST /api/fault.clear` | `router`: takes the injected TLVs out, of one system or, without it, every one |
| `POST /api/behave` | `name` and its parameters: runs a behaviour of the catalog, one at a time |
| `POST /api/behave.stop` | ends the behaviour running and undoes what it did |
| `POST /api/send` | `octets` in hex, `circuit`: sends them as they are, on one interface or every one |

And each action of the socket's API, as `POST /api/ACTION` with the same
parameters: `/api/link.down` with `link`, `/api/router.overload` with
`router` and `on`, and so on. Each answers as its `sim.` method does.

A fault replaces the system's Router Capability with the entry's, and
adds the entry's reachability after the system's: a prefix of its own,
`10.255.250.N/32` unless `prefix` says, with index `index`, near the top
of the system's SRGB unless given. The system needs segment routing. It
stays until cleared. A neighbour learns it as any change, and isisd there
makes the entry's finding.

A behaviour (`docs/protocol-testing.md`, "Behaviours") is misbehaviour
over time: `flap` stops and starts the simulator's hellos on a circuit;
`stale_lsp` leaves a simulated system's LSP as it was while its
neighbours report it gone; `srgb_change` moves a system's SRGB, the
simulator's own included. `GET /api/status` names the one running, and
`GET /api/catalog` lists them with what the RFC expects. While
`stale_lsp` holds a system, the actions that would change its LSP are
refused, and `refresh`, `flush` and `restore` pass it by.

```sh
H='X-ISIS4R: routescope'
curl -s 127.0.0.1:8080/api/catalog
curl -s -H "$H" -d '{"case":"srgb_overlap","router":"r2c3"}' 127.0.0.1:8080/api/fault
curl -s -H "$H" -d '{"router":"r2c3"}' 127.0.0.1:8080/api/fault.clear
curl -s -H "$H" -d '{"link":"r1c1--r1c2"}' 127.0.0.1:8080/api/link.down
curl -s -H "$H" -d '{"name":"stale_lsp","router":"r2c3"}' 127.0.0.1:8080/api/behave
curl -s -H "$H" -X POST 127.0.0.1:8080/api/behave.stop
```

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
