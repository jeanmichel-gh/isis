# TI-LFA

Topology Independent Loop-Free Alternate, RFC 9855: for a failure next
to this system, a repair path to each destination it cuts, computed
before the failure. The design is routescope's `docs/design/ti-lfa.md`.

**Status.** isisd computes the backups and shows them: `ti_lfa: link` on
a point-to-point interface, with segment routing (`docs/isisd.md`). It
installs none yet: the backup routes in the kernel, and the switch when
a link fails, come next (the design's step 2b). Node protection is
computed by `Spf::TiLfa` but not configurable yet (step 3).

## In isisd

After each SPF run and its label table, `Spf::Backups` runs TI-LFA for
each adjacency on an interface with `ti_lfa: link`. Each route whose
next hops all go through that neighbour gets:

- **a backup**: the adjacency to the repair's first hop, and the labels
  to push, top first, as RFC 9855 section 7.1 has them. Each segment of
  the repair: a Node-SID as its index in the first hop's SRGB (RFC 8660
  section 2.10.1), or an Adj-SID's label. Then the route's own
  Prefix-SID, as its index in Q's SRGB ("computed according to the
  Segment Routing Global Block (SRGB) of Q", 7.1 rule 2), unless Q
  advertises the prefix itself, where the packet arrives as it would
  with the label popped. A route with no Prefix-SID has the repair's
  labels alone and goes on from Q as IP.
- **ECMP**, when another of its next hops is on another adjacency.
- **unprotected**, with TiLfa's reason, or `no_label` when an SRGB gives
  no label for an index.

A Prefix-SID's label route backs up with its prefix's labels. isisd logs
the summary per interface when it changes, kind `ti_lfa`.

`test/unit/spf/backups_test.rb` runs real routers on simulated wires: in
a triangle, a's backup to b leaves for c with `[20002]`, b's index in
c's SRGB; in a square, `[20004, 22002]`, a node segment to d in c's
SRGB, then b's index in d's.

## The graph

`Spf::Graph` is one level's topology, read from the LSP database as
`Spf::Calculation` reads it, but kept whole for calculations it does not
make:

- a shortest path tree rooted at any node, forward, or backward toward
  it (`tree(root, reverse: true)`);
- with a link or a node removed (`failure:`);
- with every equal-cost parent, unpruned;
- the nodes no equal-cost path of a tree takes through a failure
  (`avoiding`): P-space for a forward tree, Q-space for a backward one
  (RFC 9855 section 2.1).

A link counts when both ends report it (7.2.8.2), each direction at its
own metric, and an overloaded node is never transit (7.2.8.1). It also
keeps each system's Node-SID and each adjacency's Adj-SID, a LAN's
included, which a repair list needs.

## The repair

`Spf::TiLfa.new(graph, root:)`. A failure is a link to a neighbour
(`link(n)`) or the neighbour itself (`node(n)`). `protect(failure)`
answers, for each destination whose primary first hops include the
neighbour:

- **`Ecmp`**: another primary first hop survives; no repair list.
- **`Repair`**: the first hop the packet leaves for, and its segments,
  each a Node-SID or an Adj-SID, along the post-convergence path, SPT
  without the failure (section 3).
- **`Unprotected`**, with why: `no_path`, the failure cuts it off;
  `no_sid`, a segment's system or adjacency has no SID; `too_deep`, more
  than the 30 labels Linux takes; `neighbor`, node protection of the
  neighbour's own address.

The repair, as section 5 lists its forms:

| Case | When | Segments |
| --- | --- | --- |
| `neighbor` (5.1) | the path's first hop is in its own P-space and in Q(D, X) | none |
| `pq_node` (5.2) | a later node of the path is in both | Node-SID of it |
| `p_and_q_adjacent` (5.3) | P, the last of the path in P-space, is followed by Q, the first in Q(D, X) | Node-SID(P), Adj-SID(P-Q) |
| `p_and_q_apart` (5.4) | Q is further on | Node-SID(P), then the Adj-SIDs from P to Q |

The first node of the path in both spaces is taken, so a repair is as
short as these forms allow. When P is the first hop, its Node-SID is
left out: the packet goes there directly. P-space is the first hop's own,
since section 4.1 excludes "neighbors that are not on the
post-convergence path". A pseudonode is never P or Q; across a LAN, the
Adj-SID is the LAN-Adj-SID of the system past it. A shorter list for 5.4
than its Adj-SIDs is left for later.

## Tests

`test/unit/spf/ti_lfa_test.rb`:

- RFC 9855's Figure 1, node N1, gives the RFC's answer, <Node-SID(R1),
  Adj-SID(R1-R2), Adj-SID(R2-R3)> through N2.
- Figure 2, node R3, gives [adj-sid(R7-R8), adj-sid(R8-R4)] toward R7.
- One graph per case, and for each reason.
- **The property.** On 300 random topologies, some links with a
  different metric each way, from one root, for each neighbour as a link
  and as a node: each repair is forwarded hop by hop through every
  router's tables from before the failure, along every equal-cost path.
  It must reach the destination and never cross the failure. With every
  SID present, every destination still reachable must be protected:
  topology independent.

`test/unit/spf/graph_test.rb` reads the graph from the LSPs the simulator
generates for an SR grid, and protects the grid from one of its routers.
