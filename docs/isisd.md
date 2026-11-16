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
isisd computes the label table after each SPF run (`show.labels`) but
does not install it yet (`docs/design/sr-mpls.md`).

```yaml
router_id: 10.255.0.1       # TLV 242's; the first IPv4 /32 prefix if absent
segment_routing:
  srgb: [{ start: 16000, size: 8000 }]    # the defaults
  srlb: { start: 15000, size: 1000 }
prefixes:
  - { prefix: 10.255.0.1/32, metric: 0, sid: 1 }   # index 1, N set
  - { prefix: 10.9.0.0/24, metric: 0, sid: 9, no_php: true }
interfaces:
  - { name: eth1, adj_sid: false }       # no Adj-SID on this one
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
| `show.overview` | | system ID, hostname, levels, areas, counts per level |
| `show.interfaces` | | each interface per level: network, metric, state, DIS on a LAN |
| `show.adjacencies` | | each neighbour per level: system ID, hostname, state, address, hold |
| `show.database` | `level` | each LSP: ID, hostname, sequence, checksum, lifetime, ATT, P, OL |
| `show.topology` | `level`, required | one level's LSDB by node: neighbors, prefixes, interface addresses, flags, reachable |
| `show.routes` | `level` | each route: prefix, metric, external, up/down, next hops; with SR its `sid` and each next hop's `label` |
| `show.labels` | `level` | the SR label table: in-label, kind, prefix or neighbour, op (swap, php, pop), next hops with their out-label (3 is a pop) |
| `show.segment_routing` | | `enabled`; the router ID, SRGB, SRLB and Adj-SIDs; per level each system's SRGB and algorithms, and the problems met |
| `show.hostnames` | | system ID to hostname, from TLV 137 |
| `show.log` | `count` | the last events |
| `show.configuration` | | the configuration, keys masked |
| `policy.leak` | `prefixes` | Level 2 routes leaked into Level 1, at both levels |
| `policy.summaries` | `summaries` | Level 1 summaries into Level 2, at both levels |
| `policy.redistribute` | `kinds` | the host route kinds redistributed |
| `policy.overload` | `on` | the overload bit in every level's LSP |
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
- `data.refresh: true`, on an `origination` or a `database` event, says
  the LSP's content is what it was, only a new sequence (RFC 1142 7.3.5).
  It is absent otherwise.

isis4r-sim, the simulator, answers every one of these and its own
`sim.*` methods, listed in `docs/simulator.md`.

The API runs in the router's own loop: a request is answered between two
turns of the protocol, never during one.
