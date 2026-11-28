# isisd

isisd runs isis4r as a router: a configuration file, the protocol on the
interfaces it names, and a management API on a Unix socket. isis-cli asks
the API from a shell; routescope asks it from its console.

```sh
sudo isisd -c /etc/isis4r/isisd.yml -l - -d
isis-cli show adjacencies
```

It needs root or `CAP_NET_RAW` to open the interfaces, and
`CAP_NET_ADMIN` to install routes.

## Options

| Option | Meaning |
|---|---|
| `-c, --config FILE` | the configuration, `/etc/isis4r/isisd.yml` by default |
| `-s, --socket PATH` | the API socket, `/run/isis4r/isisd.sock` by default |
| `-g, --group NAME` | the socket's group; the socket is mode 0660 |
| `-l, --log FILE` | the log, `-` for standard output; none by default |
| `-d, --debug` | log at debug, with every PDU decoded and in hex |

## Configuration

YAML. The keys are `ISIS::Router`'s, and its comment lists them all.

An interface key isisd does not know is refused at start, naming the key
and the interface, so a misspelt `bdf: true` stops isisd rather than
leaving BFD off with nothing said. isis4r-sim refuses it the same way in
its `simulator` section.

```yaml
system_id: 1921.6800.1001
hostname: r1
areas: [49.0001]
level: 1-2                  # 1, 2 or 1-2
metric_style: wide          # wide, narrow or transition
prefixes:
  - { prefix: 192.0.2.1/32, metric: 0 }
forwarding: true            # install routes in the kernel
interfaces:
  - name: eth1
    network: point-to-point
    ip_addresses: [10.0.12.1]
    metric: 10
  - name: eth2
    network: broadcast
    priority: 100
```

Segment routing over MPLS (RFC 8667) is off unless `segment_routing` is
there. With it, the LSPs carry TLV 242 (SRGB, SR-Algorithm 0, SRLB), the
Prefix-SID of each prefix with a `sid`, and an Adj-SID per adjacency.
isisd computes the label table after each SPF run (`show.labels`), and
with `forwarding: true` installs it: label routes, and IP routes that push
a label. That needs the host's `mpls_router` and `mpls_iptunnel` modules
and `net.mpls.platform_labels` above the highest label; isisd turns on
MPLS input on its interfaces itself. When it cannot, it logs why and
installs IP routes only. Where both levels give a label, Level 1's is
installed.

What isisd receives of other systems' SR data is checked against RFC 8667
and RFC 8660. Each break is a named finding, logged by its name; the
receive policy says what it does (`docs/protocol-testing.md`). A key
`segment_routing` does not know is refused, with the keys it takes.

```yaml
router_id: 10.255.0.1       # TLV 242's; the first IPv4 /32 prefix if absent
segment_routing:
  srgb: [{ start: 16000, size: 8000 }]    # the defaults
  srlb: { start: 15000, size: 1000 }
  receive_policy: rfc                     # rfc, strict or lenient
prefixes:
  - { prefix: 10.255.0.1/32, metric: 0, sid: 1 }   # index 1, N set
  - { prefix: 10.9.0.0/24, metric: 0, sid: 9, no_php: true }
interfaces:
  - { name: eth1, adj_sid: false }       # no Adj-SID on this one
```

SRv6 (RFC 9352) is off unless `srv6` is there, and needs `ipv6: true`.
With it, isisd sends its locators and their SIDs
(`docs/design/srv6.md`, step 2):

- TLV 242 carries the SRv6 Capabilities sub-TLV, O clear, beside the SR
  sub-TLVs, or with SR-Algorithm 0 alone when there is no
  `segment_routing`. Its Router ID is IPv4: `router_id`, or the first
  IPv4 /32 prefix.
- TLV 27, the SRv6 Locator TLV, carries each locator at metric 0, with
  Prefix Attribute Flags, none set, its End SID (function 0) and, with
  `decap`, its End.DT6 SID (function 1), each with a SID Structure.
- TLV 236 carries each locator at metric 0 too, for routers without
  SRv6 (RFC 9352 section 5).
- Each TLV 22 entry to an adjacency carries an End.X SID, function 2 and
  up, one per adjacency, kept while isisd runs; on a LAN, the entry to
  the DIS carries a LAN End.X SID per neighbour. `end_x: false` on an
  interface leaves its adjacencies without one.

A locator's prefix is the block and the node, and the structure's four
lengths add up to 128 at most (RFC 8986 section 3.1). Two locators must
not overlap, and a locator must not be one of `ipv6_prefixes`. Only
algorithm 0 for now. isisd installs no SID yet, and reads none of other
systems' SRv6 data: that is the design's steps 3 and 4. A key `srv6` does
not know is refused, with the keys it takes.

```yaml
ipv6: true
router_id: 10.255.0.1
srv6:
  locators:
    - name: main
      prefix: fc00:0:1::/48
      structure: { block: 32, node: 16, function: 16, argument: 0 }
  interface: sr0          # the dummy its SIDs will sit on
  decap: true             # an End.DT6 SID per locator; the default
interfaces:
  - { name: eth1, end_x: false }        # no End.X SID on this one
```

BFD (RFC 5880) is per interface, with `bfd: true`. isisd asks bfdd4r,
bfd4r's daemon, for sessions through `BFD::Client`, under the client name
`isisd`; bfdd4r runs beside it, one per network namespace, and the
isis4r image starts it (`with-bfdd4r isisd ...`, its entrypoint). A lab
that sets its own entrypoint puts `with-bfdd4r` first.

```yaml
interfaces:
  - { name: eth1, ip_addresses: [10.0.12.1], bfd: true }
```

On such an interface, while bfdd4r answers:

- every hello carries TLV 148, BFD-Enabled, with MTID 0 and the NLPID of
  each protocol isisd runs, 0xCC and with `ipv6: true` 0x8E (RFC 6213
  section 3). With bfdd4r away, no TLV 148, and nothing goes down.
- With TLV 148 from the neighbour too, BFD is required (RFC 6213 3.1): a
  session to its TLV 132 address (TLV 232 for IPv6), from the
  interface's; the adjacency comes Up only once the sessions are, and
  until then a point to point hello says Down in TLV 240 and a LAN hello
  leaves the neighbour out of TLV 6 (3.2). TLV 148 new on an Up
  adjacency holds its hold time until BFD is Up (section 4).
- Without TLV 148 from the neighbour, as FRR sends none, the adjacency
  comes Up on its hellos (RFC 5882 4.1), and once Up it has a session
  too.
- Either way, an Up session gone Down takes the adjacency Down at once,
  with reason `bfd` (RFC 5882 10.1.2). AdminDown never does (4.2).

`bfd_tlv: true` or `false` on an interface overrides what TLV 148 says,
whatever BFD does, for a test that wants a router that says one thing and
does another; isis4r-sim takes it on its own interfaces.

TI-LFA (RFC 9855) is per interface, with `ti_lfa: link` or `node`: after
each SPF run, every route whose next hops all go through that
interface's neighbour gets a backup, a next hop and the labels to push,
computed before the failure (`docs/ti-lfa.md`). `link` protects against
the link failing; `node` against the neighbour failing, and where
nothing avoids the neighbour, as for its own prefixes, against the link.
It needs `segment_routing`, and a point-to-point interface. `show.routes`, `show.labels` and `show.ti_lfa` show the
backups. With `forwarding: true`, each IP backup is installed beside its
route at a worse priority, and isisd sets `ignore_routes_with_linkdown`,
so the kernel takes it when the link loses carrier. `policy.ti_lfa`
changes an interface's mode while isisd runs.

```yaml
interfaces:
  - { name: eth1, ip_addresses: [10.0.12.1], ti_lfa: link }
```

Link attributes for flex-algo (RFC 9350, RFC 9479) are per interface:
`affinity`, names from the file's `affinity_map`; `delay`, in
microseconds; `te_metric`; and `srlg`. isisd sends them in one ASLA
sub-TLV (16) of the link's TLV 22 entry, with the X bit alone and the L
flag clear: affinity as an Extended Admin Group, the TE default metric,
and the delay as Min/Max (min and max the same) and as the average. It
sends no legacy sub-TLVs (RFC 9479 section 6.1). SRLGs go in TLV 238
with the X bit, the link named by its IPv4 addresses, so `srlg` needs
`ip_addresses`. A group is 0 to 1023, a delay or TE metric 0 to
16777215. `docs/design/flex-algo.md` is the design.

```yaml
affinity_map: { red: 1, far: 40 }
interfaces:
  - { name: eth1, ip_addresses: [10.0.12.1], affinity: [red], delay: 5000,
      te_metric: 100, srlg: [10] }
```

Flex-algo (RFC 9350) is a top-level `flex_algo` list: the algorithms
this system takes part in, each with `algorithm` (128 to 255),
`advertise` (send the FAD, true by default), `priority`, `metric_type`
(`igp`, `delay` or `te`), and the rules `exclude_any`, `include_any`,
`include_all` (colors from `affinity_map`) and `exclude_srlg`. A prefix
gives `algorithm_sids`, an index per algorithm. It needs
`segment_routing`. For each algorithm and level, isisd selects the
winning FAD, the greatest priority then the greatest System ID, among
its own and those it received (RFC 9350 section 5.3). It takes part
when it can run the winner: then SR-Algorithm lists the algorithm, and
each prefix with an index for it gets a Prefix-SID for it, with the
flags of its algorithm 0 one. With no FAD, or one it cannot run, it
stops taking part and withdraws both. A change is an event of kind
`flex_algo`. `show.flex_algo` shows the selection; `policy.flex_algo`
changes a FAD while isisd runs.

For each algorithm it takes part in, isisd computes the algorithm's own
tree after each SPF run (RFC 9350 section 13). A system whose
SR-Algorithm does not list the algorithm is pruned. A link is pruned by
the FAD's rules, in the RFC's order: an excluded color, an excluded
SRLG, no color of include-any, not every color of include-all, then no
value for the FAD's metric type (never taken as 0). The metric is the
IGP metric, the minimum delay or the TE metric, as the FAD says; a delay
or TE metric of 16777215 is a last resort and still used. The attributes
are those of the ASLA with the X bit. The two-way check is algorithm
0's. The prefixes are those with a Prefix-SID for the algorithm, inside
the level. Each algorithm gets a label table of its own, from its
Prefix-SIDs and the same SRGBs, installed beside algorithm 0's; a
prefix the algorithm does not reach has no label route, so a packet
with its label is dropped (section 14.1). No IP route comes from an
algorithm. A change of an algorithm's route is an event of kind
`flex_algo_route`.

With `ti_lfa` on an interface, each algorithm's routes get TI-LFA
backups too, computed on the algorithm's own graph (RFC 9855 section
8): its systems, its surviving links at its metric, its Node-SIDs, and
only the Adj-SIDs of surviving links with B clear. A repair through a
system with no Node-SID for the algorithm is unprotected, `no_sid`. As
algorithm 0's label backups, they are computed and shown, not yet
installed. `show.ti_lfa` has a row per algorithm.

```yaml
segment_routing: {}
affinity_map: { red: 1 }
flex_algo:
  - { algorithm: 128, metric_type: delay, priority: 200 }
  - { algorithm: 129, exclude_any: [red] }
prefixes:
  - { prefix: 10.255.0.1/32, metric: 0, sid: 1, algorithm_sids: { 128: 101, 129: 201 } }
```

`show.flex_algo` on a system, `b`, that takes part in 128 without
advertising it, the FAD coming from `a`, its neighbour at metric 10; its
own loopback is a local route:

```json
{
  "enabled": true,
  "configured": [
    {
      "algorithm": 128,
      "advertise": false,
      "priority": 128,
      "metric_type": "igp"
    }
  ],
  "levels": {
    "1": {
      "participating": [
        128
      ],
      "algorithms": [
        {
          "algorithm": 128,
          "participating": true,
          "winner": {
            "metric_type": "igp",
            "calc_type": 0,
            "priority": 100,
            "origin": "0000.0000.000a",
            "hostname": "a"
          },
          "supported": true,
          "candidates": [
            {
              "origin": "0000.0000.000a",
              "priority": 100,
              "hostname": "a"
            }
          ],
          "routes": [
            {
              "prefix": "10.255.0.1/32",
              "metric": 10,
              "next_hops": [
                {
                  "address": "10.0.12.1",
                  "interface": "ab"
                }
              ]
            },
            {
              "prefix": "10.255.0.2/32",
              "metric": 0,
              "next_hops": []
            }
          ]
        }
      ],
      "findings": []
    }
  }
}
```

`show.labels` on `b`, its Prefix-SID rows: `a`'s loopback has index 1
for algorithm 0 and 101 for 128, both popped toward `a`, its owner:

```json
[
  {
    "level": 1,
    "label": 16001,
    "kind": "prefix_sid",
    "fec": "10.255.0.1/32",
    "op": "php",
    "next_hops": [
      {
        "address": "10.0.12.1",
        "interface": "ab",
        "label": 3
      }
    ],
    "algorithm": 0
  },
  {
    "level": 1,
    "label": 16101,
    "kind": "prefix_sid",
    "fec": "10.255.0.1/32",
    "op": "php",
    "next_hops": [
      {
        "address": "10.0.12.1",
        "interface": "ab",
        "label": 3
      }
    ],
    "algorithm": 128
  }
]
```

A change to this system's own LSP, an adjacency up or down among
others, waits before it goes out. By default the wait is RFC 1142's
fixed hold (7.3.21): at least `minimum_lsp_interval` seconds, 30 when
absent, after the last generation of that LSP Number, the start and
refreshes included. FRR 10.7.1 at its defaults does the same.
`lsp_generation` puts a backoff in its place: the first change after a
quiet time waits `initial`, the next `secondary` from the last, and each
after that twice the one before, up to `maximum`; more than `maximum`
with no change is quiet again. The start and refreshes do not count.
`lsp_generation: {}` or `true` takes the defaults below. The two keys
are not given together. `show.overview` says which is in use. The
design and FRR's measured behaviour are `docs/design/lsp-generation.md`.

```yaml
lsp_generation: { initial: 0, secondary: 1, maximum: 30 }   # seconds; the defaults
```

An area is read as written: YAML would read `49.0010` as the number
49.001, so isisd takes the text of each item under `areas` from the file.

## API

JSON lines over the socket, as ospfd's API:

```text
-> {"id": 1, "method": "show.adjacencies", "params": {}}
<- {"id": 1, "result": [...]}
```

Every method:

| Method | Params | Answers |
|---|---|---|
| `show.overview` | | system ID, hostname, levels, areas, counts per level; `lsp_generation`, how a change to its own LSP is timed; `srv6: true` when SRv6 is configured |
| `show.interfaces` | | each interface per level: network, metric, state, DIS on a LAN |
| `show.adjacencies` | | each neighbour per level: system ID, hostname, state, address, hold; `bfd`, `waiting`, `up` or `down`, when it has a BFD session |
| `show.database` | `level` | each LSP: ID, hostname, sequence, checksum, lifetime, ATT, P, OL |
| `show.topology` | `level`, required | one level's LSDB by node: neighbors, prefixes, interface addresses, flags, reachable, link attributes for flex-algo; a node's SRv6 `locators` and `end_sids`, and a neighbour's `end_x_sids`, as sent, when it has them |
| `show.routes` | `level` | each route: prefix, metric, external, up/down, next hops; `locator: true` and its `algorithm` for a route to an SRv6 locator; with SR its `sid` and each next hop's `label`; with TI-LFA its `backup` (next hop, interface, `labels` top first, `case`, `protects` node or link, `fallback` when a node interface fell back to the link, `path` the repair's routers by hostname to Q, `p` and `q`), `{ ecmp: true }`, or `unprotected` and why |
| `show.labels` | `level` | the SR label table: in-label, kind, prefix or neighbour, op (swap, php, pop), next hops with their out-label (3 is a pop), and the `algorithm`, 0 or a flex-algo's; with TI-LFA an algorithm 0 prefix's `backup` as on its route |
| `show.flex_algo` | | `enabled`, the `configured` algorithms; per level the algorithms this system takes part in, and for each configured one the winning FAD with its origin, whether isis4r can run it, `participating`, the `reason` when not, every FAD offered (`candidates`, the winner first), the `routes` of each algorithm it takes part in (prefix, metric, next hops), and the `findings` on the FADs read |
| `show.ti_lfa` | | `enabled`, the interfaces with `ti_lfa`; per level each protected interface with its neighbour, the mode, how many routes are protected, by ECMP, by the link as a fallback, and unprotected by reason, the `algorithm`, 0 or a flex-algo's, and the last computations' trees and milliseconds, all algorithms together (`docs/ti-lfa.md`) |
| `show.segment_routing` | | `enabled`; the router ID, SRGB, SRLB and Adj-SIDs; per level each system's SRGB and algorithms, with its router ID, SRLB and Node-SID (`sid`, `prefix`, and `label`, the label this router takes it in) when it advertises them, the problems met, the findings by name (`docs/protocol-testing.md`), and the receive policy |
| `show.srv6` | | `enabled`; the locators (name, prefix, algorithm, structure), the `interface` and `decap` setting, the receive policy, this router's SIDs (End and End.DT6 per locator, an End.X per adjacency Up with its interface and neighbour); per level each system's SRv6 Capabilities, algorithms, locators with their End SIDs, End.X SIDs, `ignored` when a strict policy refused them, and the findings by name (`docs/protocol-testing.md`) |
| `show.hostnames` | | system ID to hostname, from TLV 137 |
| `show.log` | `count` | the last events |
| `show.configuration` | | the configuration, keys masked |
| `policy.leak` | `prefixes` | Level 2 routes leaked into Level 1, at both levels |
| `policy.summaries` | `summaries` | Level 1 summaries into Level 2, at both levels |
| `policy.redistribute` | `kinds` | the host route kinds redistributed |
| `policy.overload` | `on` | the overload bit in every level's LSP |
| `policy.flex_algo` | `algorithm`, and any of `advertise`, `priority`, `metric_type`, `exclude_any`, `include_any`, `include_all`, `exclude_srlg` | change a configured algorithm's FAD while running, checked as the file's `flex_algo` is; each level selects again, and the LSPs go out with the new FAD |
| `policy.ti_lfa` | `interface`, `mode` | TI-LFA on one interface while running: `off`, `link` or `node`, checked as the file's `ti_lfa` is; each level runs again, so the backups are computed, installed or withdrawn at once |
| `api.info` | | versions, every method, the last event number |
| `events.subscribe` | `since` | turns the connection into a stream of events |
| `events.unsubscribe` | | ends the stream |

`show.topology` gives one level's LSDB as a topology. It is for a reader
such as a BGP-LS Producer, which needs the graph and not the LSP headers.

```json
{"level": 1, "run": 3,
 "nodes": [
  {"id": "0000.0001.0101.00", "hostname": "r1c1",
   "areas": ["49.0001"], "overload": false, "attached": false,
   "reachable": true,
   "neighbors": [{"id": "0000.0001.0102.00", "metric": 10, "style": "wide",
                  "interface_address": "10.0.12.1",
                  "neighbor_address": "10.0.12.2"}],
   "prefixes": [{"prefix": "10.200.0.1/32", "metric": 0, "up_down": false,
                 "style": "wide"}],
   "interface_addresses": ["10.200.0.1"],
   "ipv6_interface_addresses": []}
 ]}
```

- A node is a system ID and a pseudonode octet. A pseudonode is a node
  of its own.
- All LSP fragments of a node are merged. Purged LSPs are left out. So
  is a node whose LSP Number 0 is missing, as SPF leaves it out
  (RFC 1142 7.2.5).
- `neighbors` come from TLV 22. When no fragment of the node has TLV 22,
  they come from TLV 2, with `style: "narrow"`.
- A TLV 22 neighbor has `interface_address` from sub-TLV 6 and
  `neighbor_address` from sub-TLV 8 (RFC 5305 sections 3.2 and 3.3),
  each only when the entry carries it, the first when it carries
  several. isisd sends both on a point to point circuit with IPv4
  addresses, and only `interface_address` toward a pseudonode.
- `prefixes` come from TLV 135. When no fragment has TLV 135, they come
  from TLV 128 and 130, with `style: "narrow"`.
- `interface_addresses` come from TLV 132 and `ipv6_interface_addresses`
  from TLV 232, in every fragment, LSP Number 0 first, each address once.
  RFC 1195 section 5.2 lets TLV 132 "occur in an LSP with any LSP
  number". A node with none, a pseudonode for one, answers `[]`.
- `areas`, `overload` and `attached` come from LSP Number 0. `attached`
  is true when any ATT bit is set.
- `reachable` is true when the last SPF run at that level reached the
  node. `run` is that run's number.
- SR (RFC 8667), only where the LSPs carry it, so a topology without SR
  reads as before. routescope's `docs/design/bgp-ls-sr.md` is the design:
  a BGP-LS Producer carries these in RFC 9085's TLVs.
  - A node's `sr`, from its Router Capability TLV 242, in any fragment,
    LSP Number 0 first: `srgb` and `flags` from SR-Capabilities (sub-TLV
    2), `srlb` from SR Local Block (22), `algorithms` from SR-Algorithm
    (19). A block is a list of `{start, size}`, in the order sent.
  - A TLV 22 neighbor's `adj_sids` from Adj-SID (31) and `lan_adj_sids`
    from LAN-Adj-SID (32), each as its sub-TLV gives it: `flags`, and
    `label` or `index`, and `neighbor` for a LAN Adj-SID.
  - A TLV 135 prefix's `prefix_sid` from Prefix-SID (3): `flags`,
    `algorithm`, and `index` or `label`.

  ```json
  {
    "sr": {
      "srgb": [
        {
          "start": 17000,
          "size": 8000
        }
      ],
      "flags": [
        "I"
      ],
      "srlb": [
        {
          "start": 15000,
          "size": 1000
        }
      ],
      "algorithms": [
        0
      ]
    }
  }
  ```
- Link attributes for flex-algo, only on a link that has them, as
  `Spf::LinkAttributes` reads them (RFC 9350 section 12, RFC 9479
  section 4.2): from the ASLA sub-TLVs with the X bit; with their L flag
  set, from the legacy sub-TLVs and TLV 138, and then `asla_legacy` is
  true; else, attribute by attribute, from ASLA sub-TLVs with a
  zero-length mask. `affinity` is the groups set, from the Admin Group
  and the Extended Admin Group (RFC 7308 section 2.3.1). `te_metric` is
  the TE default metric. `delay` has `min` and `max` from Min/Max Link
  Delay (34) and `average` from Unidirectional Link Delay (33), each
  only when sent. `srlg` comes from TLV 238 with X, else with a
  zero-length mask. A node's `link_findings` lists what broke RFC 9479
  or RFC 7308 there (`docs/protocol-testing.md`), acted on under
  `segment_routing`'s `receive_policy`, `rfc` without it.

  ```json
  {
    "id": "0000.0000.000b.00",
    "metric": 10,
    "style": "wide",
    "interface_address": "10.0.12.1",
    "neighbor_address": "10.0.12.2",
    "affinity": [
      1,
      40
    ],
    "te_metric": 100,
    "delay": {
      "min": 5000,
      "max": 5000,
      "average": 5000
    },
    "srlg": [
      10
    ]
  }
  ```
- Other sub-TLVs and IPv6 prefixes are not given.
- A level the router does not run answers no nodes.

To follow changes, subscribe to events and read `show.topology` again
after each `spf` event for the level. A refresh also runs SPF, and then
the answer is the same.

An event is one log line above debug, as `show.log` and
`events.subscribe` give it: `seq`, `time`, `level`, `circuit`, `kind`,
`message` and `data`. Two marks are for a viewer such as routescope:

- `kind: "spf"` is one SPF run, with `level`, `run`, `systems`,
  `prefixes`, `reasons` (the first 20) and `more` (how many it left out).
  A reason that names an LSP is written as the `database` event names it,
  `LSP 0000.0001.0101.00-00 sequence 0x000001a7`.
- `kind: "adjacency"` with `data.reason: "bfd"` is an adjacency taken
  Down by BFD. `kind: "bfd"` is a session's change, with `interface`,
  `peer`, `from` and `to`, or bfdd4r going or coming.
- `data.refresh: true`, on an `origination` or a `database` event, says
  the LSP's content is what it was, only a new sequence (RFC 1142 7.3.5).
  It is absent otherwise.

isis4r-sim, the simulator, answers every one of these and its own
`sim.*` methods, listed in `docs/simulator.md`.

The API runs in the router's own loop: a request is answered between two
turns of the protocol, never during one.
