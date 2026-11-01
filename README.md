# isis-poc

[![CI](https://github.com/jeanmichel-gh/isis/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/jeanmichel-gh/isis/actions/workflows/ci.yml)

A proof-of-concept IS-IS daemon built on
[datalink-socket](../datalink-socket). It forms a LAN adjacency using
IS-IS Hello (IIH) PDUs, carried over IEEE 802.3 with an LLC header and
sent to the AllL1ISs multicast.

This is step 2 of the roadmap: build the consumer, let it show what belongs
in datalink-socket, then refactor. It deliberately hand-rolls the
link-layer plumbing (LLC framing, the 802.3 length field, polling the
socket). Those are the pieces we will reassess.

## What works

- IS-IS system ID, LLC header, TLVs, and a LAN Hello PDU: encode and parse.
- A circuit that sends periodic Hellos and runs the adjacency handshake.
- The LAN handshake: Down, then Init when a neighbor is heard, then Up
  when the neighbor lists our SNPA in its IS Neighbors TLV.
- Two instances converging over the datalink-socket loopback backend, with
  no privileges.
- An injected clock and scheduler, and a simulated link, so tests run
  protocol time without real waiting.

## Scope

In: one L1 LAN adjacency, the Hello PDU, the Init/Up handshake.

Out, on purpose: SPF, the LSP database and flooding, SNP exchange,
multi-level, authentication, and the designated IS election. Those come
after the refactor.

## Run the demo

No privileges needed. It runs two instances on one in-memory wire.

```sh
ruby -Ilib -I../datalink-socket/lib exe/isis-demo
```

Expected output ends with both sides `up`.

## Tests

```sh
rake test
# or, without bundler:
ruby -Ilib -I../datalink-socket/lib -Itest test/unit/pdu/lan_hello_test.rb
ruby -Ilib -I../datalink-socket/lib -Itest test/unit/adjacency/circuit_test.rb
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
lib/isis/tlv/tlv.rb             # TLV encode/parse
lib/isis/pdu/lan_hello.rb       # LAN Hello (IIH) encode/parse
lib/isis/adjacency/adjacency.rb # one neighbor relationship and its state
lib/isis/adjacency/circuit.rb   # one IS instance on one link
test/unit/                      # mirrors lib/isis/, one test file per source file
exe/isis-demo                   # two-node adjacency demo over loopback
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
