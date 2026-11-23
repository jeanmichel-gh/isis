# TI-LFA

Topology Independent Loop-Free Alternate, RFC 9855: for a failure next
to this system, a repair path to each destination it cuts, computed
before the failure. The design is routescope's `docs/design/ti-lfa.md`.

**Status.** isisd computes the backups, shows them, and with
`forwarding: true` installs each IP backup in the kernel beside its
route: `ti_lfa: link` or `node` on a point-to-point interface, with
segment routing (`docs/isisd.md`), or set while it runs with
`policy.ti_lfa`. When the link loses carrier the kernel takes the
backups itself. Label routes, and a failure the link does not show
(BFD, the hold timer), switch when isisd converges, as before; switching
those sooner is the design's step 2c. Node protection falls back to the
link where nothing avoids the neighbour.

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

With `ti_lfa: node` the failure is the neighbour, so the backups avoid
it. A route the node failure leaves unprotected takes the link
failure's backup where there is one, marked `fallback`, as FRR's
`node-protection link-fallback`. The neighbour's own prefixes always
fall back, since nothing avoids the node they are on (TiLfa's reason
`neighbor`). In the test's square, e behind b at 10 and behind d at 30,
e's node backup is d's Node-SID then d's Adj-SID to e, around b; b's own
prefix falls back to the link's `[20004, 22002]`.

Each backup in `show.routes` and `show.labels` also names its repair
path: `path`, the routers from this one to Q by hostname, a pseudonode
as `name.NN`, then `p` and `q`. In the square, e's node backup has
`path` `[a, c, d, e]`, `p` d and `q` e. routescope draws it on the map.

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

## On real routers, against FRR

`test/interop/frr_ti_lfa_test.rb` runs the fault catalog's topologies
(`docs/protocol-testing.md`) on real routers: a network namespace per
system, a veth pair per link, isisd at every system, and the PLR either
isisd or FRR's isisd (`test/support/topology_lab.rb`). It reads each
repair as the routers forward it: from the first hop, a label in a
router's SRGB is a Node-SID, any other that router's Adj-SID. It reads
only once every adjacency is up and the PLR holds every system's latest
LSP; on real routers an LSP took 5 s to cross a line of them, and an
earlier read gave other answers.

isisd gives the RFC's repair for every entry, then the destination's
Prefix-SID in Q's SRGB unless Q is the destination (7.1). The 31-label
repair is too deep, so isisd falls back to the link's: through A0, then
D's label, `fallback`.

FRR 10.5.1 delivers each packet, by another route through the labels:

| Entry | FRR 10.5.1 pushes, read as segments | RFC 9855 |
| --- | --- | --- |
| `ti_lfa_neighbor` | Node-SID(D), via N | the same |
| `ti_lfa_pq_node` | Node-SID(B), Adj-SID(B-D) | Node-SID(B), D's Prefix-SID in B's SRGB |
| `ti_lfa_p_and_q_adjacent` | Node-SID(B), Adj-SID(B-D) | the same |
| `ti_lfa_figure_1` | Node-SID(R1), Adj-SID(R1-R2), Adj-SID(R2-R3), Adj-SID(R3-D) | the same, then D's Prefix-SID in R3's SRGB in place of Adj-SID(R3-D) |
| `ti_lfa_figure_2` | Node-SID(R7), Adj-SID(R7-R8), Adj-SID(R8-R4), Adj-SID(R4-R5), Adj-SID(R5-D) | Adj-SID(R7-R8), Adj-SID(R8-R4), D's Prefix-SID in R4's SRGB |
| `ti_lfa_no_path`, `ti_lfa_ecmp`, `ti_lfa_overload` | no backup | unprotected, or ECMP |
| `ti_lfa_too_deep` | 32 labels: Node-SID(A0), 30 Adj-SIDs, Adj-SID(A30-D) | past the kernel's 30 labels |

So FRR ends a repair with Adj-SIDs all the way to the destination, where
7.1 asks the destination's Prefix-SID in Q's SRGB, and on Figure 2
pushes its first hop's own Node-SID. The test holds FRR to this table on
10.5.1 and skips FRR on another version. `ti_lfa_one_way` stays a unit
test: two real routers report a link both ways or neither.

`sudo env "PATH=$PATH" ISIS_FRR=1 rake interop_ti_lfa` runs it, apart
from `rake interop`, and so does CI's `interop (TI-LFA)` job. It took
8.6 minutes here with both halves, and CI's FRR job from under 4
minutes to 9 to 11 while it ran there (2026-11-22).

## Packets at the PLR

`test/interop/kernel_ti_lfa_test.rb` sends the fault catalog's packets
(`docs/protocol-testing.md`, "Packets at the PLR") at a real PLR during a
repair. The topology is `ti_lfa_pq_node`, isisd everywhere. S installs
its routes, label routes and backups in the kernel, and a host H sits
behind S. S's isisd is stopped (SIGSTOP) before the link to F loses
carrier. So what follows is the kernel's alone, as in the first
milliseconds of a failure, before isisd reconverges. A, the repair's
first hop, and H capture what comes of each. Measured on Linux 7.0:

| Packet | During the repair |
| --- | --- |
| `packet_ip` | reaches A with B's label in A's SRGB, then D's in B's: the repair and 7.1's last label, TTL 63 |
| `packet_prefix_sid` | dropped: its label route still leaves on the failed link |
| `packet_ip_ttl_1` | ICMP time exceeded back to H |
| `packet_mpls_ttl_1` | dropped, with no ICMP |
| `packet_unknown_label` | dropped |
| `packet_adj_sid` | dropped: the Adj-SID's label route leaves on the failed link |

`packet_prefix_sid` is a gap. RFC 9855 6.1 keeps the node segment and
pushes the repair, but a label route has no backup in the kernel: it
switches only when isisd replaces it, after it reconverges. The test
names the gap, and fails when the packet takes the repair, so the day
it closes is seen. `packet_adj_sid` is as decided: isisd does not
protect Adj-SIDs, which RFC 9855 6.2 asks only "for which protection
was enabled".

It is a `kernel_` test, so `rake interop` runs it, and CI's `interop
(FRR)` job, which loads the MPLS modules. It took 33 s here.

## Behaviours

isis4r-sim runs the fault catalog's behaviours (`docs/protocol-testing.md`,
"Behaviours"): a flapping adjacency, a stale LSP and a moved SRGB, each
with what the RFC expects of the PLR. `test/unit/sim/behaviour_test.rb`
runs each against a PLR on the manual clock.
