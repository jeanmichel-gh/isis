# isis-poc

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
ruby -Ilib -I../datalink-socket/lib -Itest test/test_pdu.rb
ruby -Ilib -I../datalink-socket/lib -Itest test/test_adjacency.rb
```

`test/test_adjacency.rb` brings two instances to a full adjacency over the
loopback backend.

## Layout

```
lib/isis/system_id.rb   # 6-byte IS-IS system ID
lib/isis/llc.rb         # IEEE 802.2 LLC header (0xFE/0xFE/0x03)
lib/isis/tlv.rb         # TLV encode/parse
lib/isis/pdu.rb         # LAN Hello (IIH) encode/parse
lib/isis/adjacency.rb   # one neighbor relationship and its state
lib/isis/circuit.rb     # one IS instance on one link
exe/isis-demo           # two-node adjacency demo over loopback
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
