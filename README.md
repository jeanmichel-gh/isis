# isis-poc

[![CI](https://github.com/jeanmichel-gh/isis/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/jeanmichel-gh/isis/actions/workflows/ci.yml)

isis4r, an IS-IS router in Ruby, with a daemon (`isisd`), a CLI
(`isis-cli`) and a simulator (`isis4r-sim`). It is built on
[datalink-socket](../datalink-socket) and tested against FRR.

## What works

Phases 1 and 2 of the plan, and the first gate of phase 3:

- Point to point and LAN adjacencies, the RFC 5303 three-way handshake,
  the DIS election and pseudonode LSPs.
- Level 1 and Level 2 databases, flooding, refresh, aging and purge, with
  RFC 5304 authentication.
- SPF for IPv4 and IPv6, ECMP, overload and attached, and routes installed
  through netlink.
- Route leaking, summaries and redistribution.

Segment routing (RFC 8667), advertised but not yet forwarded: with
`segment_routing` in its configuration isisd sends TLV 242 (SRGB, SRLB),
a Prefix-SID per prefix with a `sid`, and Adj-SIDs, and FRR reads them.
The label table is computed after each SPF run (`isis-cli show labels`)
and agrees with FRR's, but is not installed yet (`docs/design/sr-mpls.md`,
PRs 1 to 3 of 5).

Not yet: BFD, graceful restart, multi topology, TE, segment routing as
a router, and Flex-Algo. `CLAUDE.md`, "Where to start", has the phases and their status.

## Run it as a router

`isisd` reads a YAML file and runs isis4r on real interfaces; `isis-cli`
asks it what it knows. [docs/isisd.md](docs/isisd.md) has the file and
the API.

```sh
sudo ruby -Ilib -I../datalink-socket/lib exe/isisd -c isisd.yml -l -
sudo ruby exe/isis-cli show adjacencies
```

In a container, beside FRR, with containerlab:
[routescope/labs/isis4r-frr](routescope/labs/isis4r-frr/isis4r-frr.clab.yml).
`test/lab/isis4r-frr.sh netns` runs the same lab in network namespaces,
with no Docker.

Three areas over a Level 2 backbone, each with a border, a Level 1
router and a simulated grid:
[routescope/labs/isis4r-areas](routescope/labs/isis4r-areas/ABOUT.md).
`test/lab/isis4r-areas.sh netns` runs it in network namespaces.

Three areas around a Level 2-only backbone router, for leaking with the
up/down bit, summaries, the nearest attached system and overload:
[routescope/labs/isis4r-areas-core](routescope/labs/isis4r-areas-core/ABOUT.md).
`test/lab/isis4r-areas-core.sh netns` runs it in network namespaces.

The labs live in `routescope/labs/`, the path every repository uses for
its routescope labs. To run one in routescope, install it into `~/labs`
with routescope's `routescope-labs` command:

```sh
routescope-labs install isis/isis4r-frr
routescope-labs install isis/isis4r-areas
routescope-labs install isis/isis4r-areas-core
```

## Run the demo

No privileges needed. It runs two instances on one in-memory wire.

```sh
ruby -Ilib -I../datalink-socket/lib exe/isis-demo            # each state change and why
ruby -Ilib -I../datalink-socket/lib exe/isis-demo --debug    # plus every hello, decoded and in hex
```

Expected output ends with both sides `up`. `-l FILE` sends the log to a file.

### The point to point handshake, with logs

Two point to point circuits on a simulated wire run the RFC 5303 three-way
handshake on simulated time, so it finishes at once. The adjacency comes
up, then `b` goes silent and the holding time expires, with the reason in
the log.

```sh
ruby -Ilib -I../datalink-socket/lib exe/isis-p2p-sim            # info level
ruby -Ilib -I../datalink-socket/lib exe/isis-p2p-sim --debug    # every decision and PDU, with hex
ruby -Ilib -I../datalink-socket/lib exe/isis-p2p-sim --help     # timing and silence options
```

## Tests

```sh
rake test
# or, without bundler:
ruby -Ilib -I../datalink-socket/lib -Itest test/unit/pdu/lan_hello_test.rb
ruby -Ilib -I../datalink-socket/lib -Itest test/unit/adjacency/circuit_test.rb

# interop against FRR's isisd: needs root, FRR and iproute2 (apt install frr iproute2)
sudo env "PATH=$PATH" ISIS_FRR=1 rake interop

# on Ubuntu 26.04, AppArmor confines isisd to FRR's default paths and the
# tests fail with "Can't create pid lock file". Unload its profile until reboot:
sudo apparmor_parser -R /etc/apparmor.d/isisd

# see the logs of tests that run circuits: info, or debug with every PDU and its hex
ISIS_LOG=debug ruby -Ilib -I../datalink-socket/lib -Itest test/unit/adjacency/p2p_circuit_test.rb -v
```

`test/unit/adjacency/circuit_test.rb` brings two instances to a full
adjacency over a simulated link, and expires it by advancing a manual clock.
`test/unit/link/socket_transport_test.rb` covers the real transport over the
datalink-socket loopback backend.

## Layout

The tree follows the Layout section of CLAUDE.md. Only the files below
exist so far.

```
isis4r.gemspec                  # gem name isis4r
lib/isis4r.rb                   # entry point, requires everything
lib/isis/version.rb             # ISIS::VERSION
lib/isis/common.rb              # errors, and the 6-byte IS-IS system ID
lib/isis/codepoints.rb          # PDU types, TLV types, NLPIDs
lib/isis/runtime/clock.rb       # monotonic clock, and a manual one for tests
lib/isis/runtime/scheduler.rb   # timers as scheduled callbacks on a clock
lib/isis/link/llc.rb            # IS-IS LLC header and AllL1ISs/AllL2ISs MACs
lib/isis/link/socket_transport.rb    # real link over a Datalink::Socket
lib/isis/link/simulated_transport.rb # in-memory link that never waits
lib/isis/tlv/tlv.rb             # TLV framing, Tlv::Unknown, the TLV list
lib/isis/pdu/pdu.rb             # common header, type registry, Unknown, Truncated, Malformed
lib/isis/pdu/psnp.rb            # the PSNP layout, both levels
lib/isis/pdu/capture.rb         # one PDU and whatever followed it
lib/isis/pdu/lan_hello.rb       # the LAN hello layout, both levels
lib/isis/pdu/p2p_hello.rb       # the point to point hello layout
lib/isis/adjacency/adjacency.rb # one neighbor relationship and its state
lib/isis/adjacency/circuit.rb   # one IS instance on one link
test/unit/                      # mirrors lib/isis/, one test file per source file
test/docs/                      # tests that hold docs/ to the code
docs/building-objects.md        # the four ways every node is built
docs/parse-policy.md            # what happens when a length lies
exe/isis-demo                   # two-node adjacency demo over loopback
exe/isis-p2p-sim                # point to point handshake on simulated time, with logs
```

## Boundary with datalink-socket

The generic link-layer plumbing lives in datalink-socket, not here:

- LLC framing is `Datalink::LLC`. This repo only decides that the IS-IS
  SAP (0xFE) means IS-IS.
- The 802.3 length field and NIC-padding trim are `Frame.ieee_802_3` and
  `Frame#sdu`.

What stays here, because it knows it is IS-IS: the PDU structure, the
TLVs, the adjacency FSM, and the timers.

Still pending, for when this runs on a real NIC: datalink-socket does not
yet expose the socket FD, so `Circuit#poll` drains with a timeout instead
of joining an event loop. That is the next thing to move down.

## License

isis4r is copyright (c) 2026 Jean-Michel Esnault. It uses the same terms
as bgp4r. You can redistribute it and/or modify it under either:

1. the GNU General Public License, version 3 or (at your option) any later
   version, in [COPYING](COPYING); or
2. the conditions in [LICENSE.txt](LICENSE.txt).

isis4r is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.

Passive wire capture for RouteScope: see [capture](docs/capture.md).
