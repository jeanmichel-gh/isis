# TI-LFA

Topology Independent Loop-Free Alternate, RFC 9855: for a failure next
to this system, a repair path to each destination it cuts, computed
before the failure. The design is routescope's `docs/design/ti-lfa.md`.

**Status.** isisd computes the backups, shows them, and with
`forwarding: true` installs each IP backup in the kernel beside its
route: `ti_lfa: link` on a point-to-point interface, with segment routing
(`docs/isisd.md`). When the link loses carrier the kernel takes the
backups itself. Label routes, and a failure the link does not show
(BFD, the hold timer), switch when isisd converges, as before; switching
those sooner is the design's step 2c. Node protection is computed by
`Spf::TiLfa` but not configurable yet (step 3).

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

## In the kernel

With `forwarding: true`, each backup is a second IP route to the prefix,
beside the route, at the route's priority plus 100 (`Netlink::
BACKUP_OFFSET`): 121 for a Level 1 route at 21, 122 at Level 2. It leaves
on the backup's adjacency and pushes its labels with one encap, top
first, as `ip route ... encap mpls 20004/22002` writes them. A backup
whose labels or next hop change is replaced, one no longer computed is
withdrawn, and a flush at start takes both priorities.

isisd sets `ignore_routes_with_linkdown` for IPv4 and IPv6 on `all`,
`default` and each interface with `ti_lfa` (`Router::Host#ti_lfa`). Then
when a link loses carrier, the kernel passes over the routes on it and
takes each backup, with no daemon in the way. Measured on ospflab, Linux
7.0, a veth whose far end goes down: the backup was taken 8 to 75 ms
after, five runs, each check an `ip route get` of its own.

A label route has no metric and no backup in the kernel, so it stays on
the failed link until isisd converges. A failure that leaves carrier up
(BFD, the hold timer) reaches the IP routes the same way: isisd
converges at once and replaces them.

`test/interop/kernel_backup_test.rb` installs a route and its backup
through isisd's own adapter in network namespaces, takes the link down
from the far end, and checks the kernel took the backup, and the route
again when carrier is back. `rake interop` runs it.

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
