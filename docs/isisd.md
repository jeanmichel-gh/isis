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
| `show.routes` | `level` | each route: prefix, metric, external, up/down, next hops |
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

isis4r-sim, the simulator, answers every one of these and its own
`sim.*` methods, listed in `docs/simulator.md`.

The API runs in the router's own loop: a request is answered between two
turns of the protocol, never during one.
