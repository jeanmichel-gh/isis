# The LSDB as a topology, for a BGP-LS Producer

Status: draft, waiting for approval.

Part of the BGP-LS lab. Two other specs go with it:
bgp4r `docs/design/bgp-ls-producer.md` and routescope
`docs/design/bgp-ls-lab.md`.

## The problem

We want a BGP-LS Producer (RFC 9552) in bgp4rd. It turns isisd's LSDB
into Node, Link and Prefix NLRIs. RFC 9552 section 3 defines the role:

> "BGP-LS Producer: The term BGP-LS Producer refers to a BGP Speaker that
> is originating link-state information into BGP. BGP Speakers R1, R2,
> ... Rn originate link-state information from their underlying
> link-state IGP protocols into BGP-LS."

bgp4rd runs as a separate process. It can only reach isisd through the
management socket. Today that socket does not give it what it needs.

## What exists

Read on master at acf0f8b.

- The API is JSON lines on `/run/isis4r/isisd.sock`
  (`lib/isis/daemon/api.rb:10-28`, methods at `:39-71`).
- `show.database` gives LSP headers only: level, LSP ID, hostname,
  sequence, checksum, lifetime, length, att, p, ol, purged, self
  (`lib/isis/daemon/views.rb:63-77`). It decodes no neighbors, metrics,
  prefixes or areas.
- `events.subscribe` streams events. A `database` or `purge` event names
  the LSP but does not carry it. Their `level` field is the log severity,
  not the IS-IS level.
- An `spf` event carries the IS-IS level in its data
  (`lib/isis/spf/decision.rb:129-132`, isis #65).
- `Decision#paths` holds the systems SPF reached, per level
  (`decision.rb:44`). The API gives only their count.
- `Lsp#to_hash` decodes all TLVs (`lib/isis/pdu/lsp.rb:142-150`).
- The TLV classes needed exist: 1 (`AreaAddresses`), 2, 22, 128, 135,
  137, 132. There is no class for TLV 134 or 242. No sub-TLVs are
  registered, so those under TLV 22 and 135 decode as `SubTlv::Unknown`.

## The design

### A new method: `show.topology`

```
{"method": "show.topology", "params": {"level": 1}}
```

`level` is required. The answer is one level's LSDB, grouped by node.
All LSP fragments of a node are merged. Purged LSPs and placeholders are
left out.

```json
{"level": 1, "run": 1017,
 "nodes": [
  {"id": "0000.0001.0101.00", "hostname": "r1c1",
   "areas": ["49.0001"], "overload": false, "attached": false,
   "reachable": true,
   "neighbors": [{"id": "0000.0001.0102.00", "metric": 10, "style": "wide"}],
   "prefixes": [{"prefix": "10.200.0.1/32", "metric": 0, "up_down": false,
                 "style": "wide"}]}
 ]}
```

- `id` is the system ID plus the pseudonode octet. A pseudonode is a
  node of its own, with `.01` and up.
- `neighbors` come from TLV 22. When an LSP has no TLV 22, they come
  from TLV 2, with `style: "narrow"`.
- `prefixes` come from TLV 135, or from TLV 128 and 130 when there is
  no TLV 135, with `style: "narrow"`.
- `overload` and `attached` come from fragment 0's header.
  `attached` is true when any ATT bit is set.
- `reachable` is true when the node is in `Decision#paths` for that
  level. A Producer needs this for RFC 9552 section 5.9.
- `run` is the decision's run count. A reader can tell whether the
  answer changed since it last read.
- Sub-TLVs are not given. They are not decoded today.

`show.topology` is read-only. It reads the database and the decision
under the locks the other views take.

### How a reader learns that it changed

No new event. A reader subscribes to events and reads `show.topology`
again after each `spf` event for its level. Each change in the LSDB that
matters causes an SPF run, and `spf` events carry the level.

SPF also runs after LSP refreshes. The reader then gets the same answer,
and its diff is empty. That is about one read every few seconds in the
lab. It is cheap.

### What it does not change

No change to flooding, SPF or origination. One new view and one new
method. `api.info` lists it, as it lists every method.

## Pull request

One: isis `claude/bgp-ls-lab`. This spec, then `Views#topology`, the
`show.topology` method, `isis-cli show topology LEVEL`, and
`docs/isisd.md`.

## Tests

- `Views#topology`, from LSPs built in the test:
  - fragments 0 and 1 of one system merged into one node;
  - a pseudonode as a node of its own;
  - wide TLVs used when present, narrow ones otherwise, with `style`;
  - overload and attached from fragment 0;
  - `reachable` false for a node not in `Decision#paths`;
  - purged LSPs left out.
- The API: `show.topology` without `level` is refused; with a level the
  router does not run, the answer has no nodes.
- `isis-cli show topology 1` prints the answer.
- The full suite: `rake test`.

## Gate

The full suite passes. On the VM, in the running isis4r-sim lab,
`show.topology {"level": 1}` on r1 lists the 16 grid nodes, s1, f1 and
r1. r1c1 lists r1c2 at metric 10.

## Open questions

- Should `show.topology` also carry TLV 132 (interface addresses)? It
  would let the Producer fill Link descriptors 259 and 260. Not needed
  for phase 1.
