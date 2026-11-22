# CLAUDE.md

Guide for AI agents working on isis4r. Read this before writing anything.

## Wire capture addition

`exe/isis-capture` emits passive Ethernet capture as JSON lines for RouteScope.
The parser-backed adapter is `lib/isis/wire_capture/`; see `docs/capture.md`.
It does not change daemon or routing behaviour.

## What this is

isis4r is a programmable IS-IS router and protocol testing platform, with
a pure Ruby protocol core (ISO/IEC 10589 and RFC 1195, with the extensions
that matter).

It can operate autonomously as a router, or let a test script control
individual protocol mechanisms while the rest continue normally. The same
packet formats, databases and state machines serve both uses.

Normal operation follows the protocol. Explicit testing controls can
override behaviour, manipulate time, inject failures and send malformed
traffic. Received traffic remains available for exact replay.

**Router functionality and testing control are both core requirements.**
Adding automation must not remove control. Adding testing controls must not
compromise ordinary router behaviour. The controls exist because a speaker
that can only send correct PDUs can only test the happy path, and the happy
path is not where routers break.

Most of this file is about the codec: how a PDU is built, parsed and
replayed. Those rules were written when isis4r was scoped as a test tool,
and they still hold, because the codec serves both uses. Where router
behaviour lives instead is in "Autonomous operation and testing controls"
below. The scope change itself is under Decisions.

## The one rule the rest follow from

**A PDU is a tree of objects, and every node in that tree obeys the same
contract.** A Link State PDU holds a TLV list, which holds TLVs, one of
which holds sub-TLVs, one of which holds a prefix. Nine levels or two, it
makes no difference: each node knows how to build itself from the four
kinds of input below, how to write its own octets, and how to read them
back.

`encode` on the root returns the whole PDU because it walked the tree. No
node knows the shape of the tree above it, and no node knows more about
the node below it than `child.encode` tells it.

Everything below is that rule applied.

### Where the OSPF analogy breaks, and it breaks here

Most people arrive knowing OSPF or BGP, and the vocabulary maps well enough
to be dangerous. LSA to LSP is the mapping that will cost a day, and it is
not for the reason first written here.

**It is not that an LSA is small and an LSP is large.** An OSPF Router-LSA
carries many link descriptions, and an IS-IS reachability TLV carries many
entries, so both are containers and both deserve classes for the things
inside them.

**The difference is that OSPF has a packet layer above the advertisement
and IS-IS does not.** OSPF carries N LSAs inside a Link State Update
packet. An IS-IS LSP is both the packet and the container, with nothing
wrapping it. So the mapping that holds, for **the encoding layers only**,
is:

| OSPF | IS-IS |
|---|---|
| Link State Update packet | LSP |
| LSA | TLV |
| a link description inside a Router-LSA | an entry inside a TLV |

Map LSA to LSP and a layer goes missing. That is the whole hazard, and it
is enough of one: a reader who has it wrong looks for the IS-IS Link State
Update and concludes something is unimplemented.

**Read the table for containment and for nothing else.** An LSA has its own
sequence number and age and is the unit of flooding; a TLV has none of
those and is flooded only as part of whatever LSP carries it. So identity,
sequencing, aging and flooding map LSA to **LSP**, where containment maps
LSA to TLV. Neither row is interchangeable outside the question it answers,
which is why this belongs in a guide labelled as such and not in anyone's
mental model unlabelled.

Classes for entries are wanted, not forbidden. A neighbour entry in TLV 22
and a prefix entry in TLV 135 each have their own fields, their own widths
and their own sub-TLV framing, so each is an object. Write a glossary in
`docs/` if the vocabulary helps, and keep the near-equivalences in it
labelled as hazards rather than conveniences.

## Layout

isis4r is published as a gem, so the library lives under `lib/` and the
gem is named after its entry point. The tree below `lib/` is the design.

```
isis4r.gemspec             the gem: name isis4r, require_paths ["lib"]
Gemfile                    gemspec, plus local overrides for development
lib/isis4r.rb              entry point, requires everything; what
                           `require "isis4r"` loads
lib/isis/version.rb        ISIS::VERSION, read by the gemspec
lib/isis/common.rb         shared helpers: hex dumps, the packed-string
                           mark, Fletcher checksum, System ID and LSP ID
                           formatting
lib/isis/codepoints.rb     the IANA numbers in one place: PDU types, TLV
                           types, sub-TLV types per parent TLV, with the
                           registry's own names beside them
lib/isis/pdu/              one file per PDU layout, which is five and not
                           nine, plus pdu.rb with the common header, the
                           type registry, Pdu::Unknown, Truncated and
                           Malformed, and capture.rb with the capture that
                           owns what follows a PDU
lib/isis/tlv/              one file per TLV, plus tlv.rb with the framing,
                           the registry, Tlv::Unknown and the TLV list
lib/isis/subtlv/           sub-TLVs, grouped by the TLV that carries them,
                           since the same number means different things
                           under different parents
lib/isis/link/             getting bytes on and off a link: LLC framing,
                           and the transports, real over datalink-socket
                           and simulated for tests
lib/isis/runtime/          the injected monotonic clock and the scheduler
lib/isis/adjacency/        hello generation and the adjacency state machines
lib/isis/database/         the per level LSP databases and flooding
lib/isis/receive/          the receive policy: what a received PDU may change
lib/isis/validation.rb     the receive rules, each a named finding with its
                           clause and an action per receive policy
                           (docs/protocol-testing.md)
lib/isis/fault.rb          the fault catalog: crafted inputs, each making
                           one finding (docs/protocol-testing.md)
lib/isis/mpls/             the MPLS label stack, RFC 3032 (LabelStack)
lib/isis/spf/              route calculation; graph.rb and ti_lfa.rb, the
                           TI-LFA computation (docs/ti-lfa.md)
lib/isis/forwarding/       forwarding adapters, one per platform, each
                           declaring its dependencies
lib/isis/router.rb         a whole system from one configuration;
                           router/host.rb, the Linux host it runs on
lib/isis/daemon.rb         isisd: a Router on the real clock, with its
                           management API in daemon/
lib/isis/sim/              the simulator: the simulated area's topology,
                           and the LSPs it originates
lib/isis/config_file.rb    the YAML files, with areas as written
exe/                       command line tools shipped with the gem
test/unit/                 mirrors lib/isis/, one test file per source file
test/docs/                 the tests that hold each guide in docs/ to the code
test/scenario/             router scenarios on simulated time, run with and
                           without controls: pass-through equivalence
test/fixtures/             PDUs captured from real routers, as hex, named
                           for the router and version that sent them
test/functional/           tests that put PDUs on a real interface
test/interop/              against FRR's isisd and SR Linux, in network
                           namespaces and containers: root, then
                           ISIS_FRR=1 rake interop, ISIS_SRL=1 rake interop_srl
docs/                      the guides, each with a test that asserts its
                           load-bearing claims
routescope/labs/           labs of isis4r and FRR, as routescope reads them;
                           test/lab/ runs them. examples/containerlab/
                           holds symlinks to them for one release.
                           test/lab/bases.sh tags the image's base before
                           a build, so Docker Hub is not asked
Dockerfile                 the isis4r image
```

**Everything under `lib/` is namespaced under `isis/`, except the entry
point.** A gem's `lib/` is added to every user's load path, so a file at
`lib/common.rb` would collide with any other gem that ships one. Keep
`lib/isis4r.rb` as the only top level file. The module is `ISIS` and the
gem is `isis4r`.

Elsewhere in this file a path like `isis/validation.rb` means
`lib/isis/validation.rb`.

## Autonomous operation and testing controls

**There is no testing switch.** Each protocol mechanism is an object with a
default implementation, and a script can observe, replace, pause or drive
it. At least these:

| Mechanism | What the default does |
|---|---|
| Scheduling | runs timers on the injected clock |
| Transmission | hands PDUs to the circuit's transport |
| Hello generation | builds and sends hellos at the configured interval |
| LSP origination | builds this system's LSPs from configuration and state |
| Flooding | SRM and SSN handling, retransmission, CSNP and PSNP exchange |
| Receive policy | decides what a received PDU may change |
| SPF | computes routes when a database changes |
| Route installation | hands route operations to a forwarding adapter |
| BFD | asks bfdd4r for sessions and tells the circuits what they do (`Bfd`, `adjacency/bfd.rb`) |

Controls compose at whatever granularity the mechanism has. A test can run
ordinary routing on three circuits and manipulate hellos or flooding on a
fourth. A global "test mode" flag cannot express that, and once it exists
every mechanism grows a branch on it. Do not add one.

### Ordinary production and deliberate overrides

**The codec stays permissive.** Everything under "Building never
validates" still holds, and the encoder never acquires checks "for router
mode". Router behaviour is correct because the **originators** are
correct: the hello generator, the LSP originator and the packing builders
produce valid PDUs by construction, and their tests assert that against the
specification.

**A deliberately wrong PDU is a test override and looks like one**: a
replaced originator, a singleton override on one object, or a hand built
PDU handed to the transmission control. Never a flag on an originator that
makes it produce something invalid. Ordinary production and deliberate
overrides are separate code paths, so neither is reachable by accident from
the other.

### Receive: keep, report, then admit

Three steps, in this order, and kept apart:

1. **Keep.** The received octets are retained exactly, for inspection and
   replay. Always, whatever follows.
2. **Report.** Validation produces findings on its three channels, from
   the octets. It decides nothing.
3. **Admit.** The receive policy decides whether the PDU may affect
   adjacency, database or routing state. Its inputs are the findings, the
   circuit's configuration (levels, area addresses, circuit type) and the
   authentication context (keys, expected types). Findings alone do not
   carry enough to decide, which is why admission is its own step and not
   a property of validation.

**Keeping a PDU is not accepting it.** A capture holds everything that
arrived. The adjacency, the database and SPF see only what the policy
admitted. The default policy follows the specification, with the clause
quoted beside each decision, including where the specification recommends
keeping what a stricter reading would drop, such as an oversized LSP. A
script can replace the policy per circuit.

### Time and execution

Time and execution are two injected things, not one:

* **A monotonic clock** for every protocol time: holding times, LSP
  lifetimes, retransmission intervals, SPF delays. Protocol code asks the
  clock for the time and never reads the system's.
* **A scheduler** for callbacks. A timer is a scheduled callback, never a
  sleep.
* **Wall clock time is for logs only**, never for a protocol decision.

Transports sit at the edge. A real transport over datalink-socket may
block waiting for a frame; that is its job. A simulated transport moves
frames between circuits and lets the scheduler advance time without real
waiting, which is what makes failure tests deterministic and fast.

**Guard it with a test**: a source scan under `lib/isis/` that fails on
direct calls to `Time.now`, `Process.clock_gettime` or `sleep`, with an
explicit list of allowed files. A new exception is a line in that list and
is justified in the pull request that adds it. The guard is
`test/unit/runtime/time_guard_test.rb`. It reads Ruby tokens, so comments
and strings do not trip it, and it fails on an allowed entry whose file no
longer makes the call. Today the list holds one file,
`lib/isis/runtime/clock.rb`, the real monotonic clock, which also answers
the wall time for log lines. The real transport
needs no entry: it blocks inside datalink-socket, not by sleeping.

### Pass-through equivalence

This is how "testing controls must not compromise router behaviour" is
checked rather than promised. Each router scenario runs twice, from the
same initial state, simulated time and random seeds: once with no controls
installed, and once with every control installed and passing everything
through unchanged. The two runs must produce:

* the same ordered packet events, sent and received, per circuit;
* the same protocol state at each step: adjacencies, databases, flooding
  flags;
* the same ordered route operations: installs, replacements, withdrawals.

**Final routes alone are not enough.** A hook that causes one transient
withdrawal or one extra flood ends in the same routes and is still a
defect.

It runs in the suite as `test/scenario/pass_through_test.rb`, with the
pass-through control in `test/support/pass_through.rb`. A new mechanism
object joins the list the test controls, and its class joins the list
the test asserts ran through a control.

### Logging and events

**A person running a test by hand must be able to turn logging on, at
info or debug, and find out from the log what happened and why.** That
is a requirement on every mechanism, not a feature added at the end. A
router that converges in a test but cannot say why it did not converge in
the lab is half a tool. The design is taken from ospfv2, which already
works this way (surveyed at `0ec77c6`). It is built in
`lib/isis/runtime/log.rb`: `Runtime::Log` holds the logger, the bounded
event list and the tracer, and `Log.writer` and `Log.trace_writer` give an
executable its lines. Both circuits, `P2pCircuit` and `LanCircuit`,
log through it.

How ospfv2 does it, and what isis4r copies:

* **The logger is an injected callable**, `->(level, message)`, handed to
  each mechanism like the clock. Not a global, not `$stderr`, not Ruby's
  `Logger` reached for inside protocol code. The levels are `:debug`,
  `:info`, `:warn` and `:error`. The executable decides where lines go and
  in what format: ospfd writes `TIME LEVEL message`, to a file or to
  stderr. With no logger, nothing is written and nothing breaks.
* **Events are kept as well as logged.** In ospfv2 every non-debug line is
  also recorded as an event, with time, level, interface, kind and data,
  in a bounded list that `show ospf events` and the web view read, and is
  published to listeners. Debug lines go to the logger only, so the list
  holds what a person wants to scan and the log holds everything. isis4r
  does the same, so a test can assert on events instead of parsing text,
  and routescope can show them.
* **Packets have their own tracer**, `->(direction, circuit, pdu, peer)`,
  separate from the logger. `--debug` adds hex dumps. Here the dump is
  `to_shex` and the decode is `to_s`, which is what makes a line out of a
  live trace usable as a test fixture.
* **Two switches on every executable**: `-l, --log FILE` with `-` for
  standard output, and `-d, --debug`.

What isis4r adds, because of its own rules:

* **The time on a log line is wall time from the injected clock.** Wall
  time is for logs only, as the time section says, and it comes through
  the clock so the time guard holds. ospfv2's manual clock derives wall
  time from simulated time, so a simulated run logs reproducible times.
* **What to log is the reason, not the fact.** An adjacency going Down
  logs which timer expired or which TLV 240 state arrived. A PDU the
  receive policy refused logs the finding and the clause. A dropped PDU
  with no reason in the log is the exact case this requirement exists for.
  Rough levels: state changes and refusals at info, each PDU and each
  decision at debug. An SPF run is kept at info, as an event of kind
  `:spf`, so a viewer can see each run and its reasons; an LSP event
  that is only a refresh carries `refresh: true` (2026-11-08, for
  routescope's events feed).
* **Logging is observation, so it must not change behaviour.**
  Pass-through equivalence runs with logging at debug and with it off,
  and both must match. A log statement that calls a method with a side
  effect is a defect.
* **A test can install a logger and a tracer** to capture what a scenario
  did, so a failing test can print the log of the run that failed. `TestLogs` in `test/test_helper.rb` gives a test both, feeding the
  test's own sink, and with `ISIS_LOG=info` (or 1) or `ISIS_LOG=debug` (or 2) printing
  them as well, and an unknown value warns. `ruby --debug` is the interpreter's own debug mode and
  shows none of this.

### Control plane and forwarding

The protocol core computes routes and hands **route operations** to a
forwarding adapter. It never touches a kernel itself. So the same core can
compute and inspect routes without installing them, install them into a
host, or drive a richer forwarding environment.

**"Pure Ruby" means the protocol core.** Everything under `lib/isis/`
except `forwarding/` runs on plain Ruby with no native extension. Adapters
are declared per platform, each stating its dependencies. No adapter uses
a native dependency: the Linux adapter speaks rtnetlink over an
AF_NETLINK socket, with the messages packed in Ruby. See Decisions.

## Nine PDU types, five layouts

There are nine PDU types and that is not nine classes. Four of the families
come in a Level 1 and a Level 2 variant whose **field layouts are
identical**, differing only in the PDU type octet itself:

| Family | Types | Layouts | Where the level lives |
|---|---|---|---|
| LAN hello | L1, L2 | one | the PDU type, and a Circuit Type field |
| Point to point hello | one | one, genuinely different | **a Circuit Type field only** |
| LSP | L1, L2 | one | the PDU type |
| CSNP | L1, L2 | one | the PDU type |
| PSNP | L1, L2 | one | the PDU type |

So write five layouts, let the type registry map nine numbers onto them,
and Level 2 stops being a feature anyone asks about. Decide it before the
second PDU, because the alternative is discovered rather than chosen: nine
classes, four of them copies, and "is Level 2 implemented?" asked
separately for every family forever.

**The level is not one parameter, and the hellos are why.** For an LSP, a
CSNP and a PSNP the PDU type number is the only level information, so a
single level argument says everything. A hello also carries a **Circuit
Type** field saying which levels the circuit supports, L1, L2 or both, and
that is a different fact from which hello this is. The point to point hello
has **one** PDU type for both levels, so there the field is the only level
information there is, and a blanket level argument would misrepresent the
packet: it cannot say "both", which is the common case on a point to point
link.

So: a level argument for the three paired non-hello families, and a Circuit
Type field, carried and encoded as a field, for all three hellos. Do not
collapse the two into one setting because they happen to be about levels.

The point to point hello earns its own class for the same reason. It is not
a LAN hello with the DIS parts removed, so do not share a base with the LAN
hellos for the sake of symmetry.

**Two of everything is the shape of the whole protocol**, not a quirk of
the PDU types: two databases, two of most PDU types, two variants of
several TLVs. That is what makes the level worth parameterising. It is not
a licence to assume every level distinction is the same distinction.

## The object contract

Every class in `lib/isis/pdu/`, `lib/isis/tlv/` and `lib/isis/subtlv/` is
built the same four ways and answers the same five questions. Keep all of them
working in every change.

### Four ways in

`initialize` dispatches on what it is handed:

1. **Field values.** `Lsp.new(lsp_id, sequence: 7, lifetime: 1200)`. This is
   how a test says what it means.
2. **A hash.** `Lsp.new(h)` where `h` is what `to_hash` answered.
3. **Wire bytes**, a binary String. This is how a capture comes back to
   life.
4. **Another instance**, re-parsed through its own `encode`. A copy
   constructor that costs one line and catches encoder bugs for free.

**Wire bytes must be recognised by a mark, never by guessing.** A binary
String and a field value String are the same class in Ruby. Mark the
binary one explicitly and branch on the mark. Sniffing the content works
until the day a field value happens to look like octets, and then it fails
somewhere far away from the cause. The mark here is `ISIS::Octets`, a
String subclass, and not bgp4r's `is_packed`: a gem should not add methods
to every user's Strings, and a frozen literal cannot carry that mark.

The dispatch order is written down in `docs/building-objects.md` and lives
in one place, `ISIS::Node`, which every node class includes. A reader who
learns one constructor has learned all of them. The doc's test discovers
every class that includes `ISIS::Node` and fails if the doc does not list
it.

### Five ways out

* **`encode`** returns the complete wire octets of this node and everything
  under it. Nothing else. No length prefix the parent did not ask for, no
  padding, no framing that belongs to a level above.
* **`to_shex`** is `encode` as a hex string. One line of code, and **it is
  the canonical form of an object**: it is what every test asserts on,
  because it is the only representation the specification and the library
  share. See Testing.
* **`parse`** reads octets and fills the instance. It is `encode` run
  backwards and it must be exact: for every octet sequence the class
  accepts, `Klass.new(octets).to_shex` is the hex it was handed. **That
  includes octets that are wrong**, which is what the replay rule below is
  about, and it is the one promise in this list with a mechanism behind it
  rather than a convention.
* **`to_hash`** returns a hash that rebuilds the object through `new`,
  **where it can**. It is a convenience for people writing tests as values
  rather than as hex, not part of the protocol, so a class whose hash
  cannot rebuild it is allowed. What is not allowed is that being
  undocumented. See the `to_hash` section for the one consistent contract.
* **`to_s`** returns the presentation form. **Two kinds of class, two
  different obligations**, and conflating them was an error in an earlier
  version of this file:
  * **An identifier or address class** owes a reversible form. A System
    ID, an LSP ID, an area address, an ISO or IP prefix: for these,
    `Klass.new(obj.to_s)` reproduces the object. That is the pton
    direction, it is a contract, and it is what lets a line from a live
    dump be pasted into a test as a fixture.
  * **A composite** owes a readable dump and nothing more. Nobody parses a
    forty TLV LSP back from its printed form, and requiring it would mean
    inventing a grammar for a debugging aid. Its `to_s` is for a person.
    Its reversible form is `to_shex`, always, and `to_hash` where the
    catalog says that one works.

  Where the line falls is not a judgement call: if the class holds other
  nodes of the tree, it is a composite.

## Composition: how a PDU assembles

This is the part worth getting right, because everything else is cheap to
change and this is not.

### The idiom

**A parent writes framing. A child writes value. The child calls up.**

```ruby
class Tlv
  # Every TLV is type, length, value. This method is the only place in the
  # library that knows that.
  def encode(value)
    n = value.bytesize
    raise ArgumentError, "TLV #{type} value is #{n} octets, max 255" if n > 255
    [type, n, value].pack('CCa*')
  end
end

class Area_addresses < Tlv
  def encode
    super(@areas.collect { |a| a.encode }.join)
  end
end
```

**`bytesize` and not `size`, everywhere a length is written.** `String#size`
counts characters, so it is the octet count only while the String's encoding
happens to be binary. A Dynamic Hostname TLV built from a UTF-8 name is
where that bites: the length octet comes out short, the TLV is framed wrong,
and every TLV after it in the PDU is read at the wrong offset.

**The root cause is the buffer's encoding, and it has a second symptom.**
`String#<<` with an Integer appends a **codepoint**, so on a UTF-8 buffer
every value above 0x7f becomes two octets. On an `ASCII-8BIT` buffer it
appends one octet and is perfectly safe, so this is not a method to ban; it
is the same encoding bug wearing a different face. bgp4r shipped exactly
this and the detail worth keeping is the order: calling `.b` **after** the
expansion relabels the string without undoing it, so the two extra octets
survive and the field comes back long.

So: force `Encoding::BINARY` on every buffer at the point it is created,
use `bytesize` for every length, and the `<<` question answers itself.
Assert the encoding in a test rather than trusting it, because a buffer
that is binary today becomes UTF-8 the moment someone interpolates a name
into it.

The raise follows the library's one rule about refusing: **it refuses when
it cannot produce the octets, never when it disapproves of them.** A value
over 255 octets cannot be expressed in a one octet length, so writing it
truncated would put a different TLV on the wire than the caller asked for.
A digest with no key is the same kind of failure, one section further on.
Neither is a judgement about validity, which nothing here ever makes.
Splitting an oversized value is the builder's job and not this method's.
See the packing section.

`Area_addresses` never writes a length and never writes a type. It knows
what its value is, hands it up, and the base class frames it. Change the
framing once and every TLV in the library changes with it.

The same shape goes one level down for sub-TLVs and one level up for the
PDU header. Three layers, each wrapping the one below, each ignorant of the
others.

**When a field is missing from the wire, find which layer owns it before
you edit anything.** Half the time the field is written by a class two
levels up from where it looks like it belongs.

### What a parent may assume about a child

**Exactly one thing: that `child.encode` returns the child's complete
octets.**

Not its length in advance. Not its type. Not whether it is fixed width.
That single assumption is what lets one TLV list hold nineteen unrelated
classes and a handful of `Tlv::Unknown` objects it has never heard of.

The moment a parent reaches inside a child for a field, the tree stops
being a tree. If a parent genuinely needs something a child has, give the
child a method and let it answer. `Flow spec` in bgp4r had to learn this
the slow way: the container asked the family how long an item was, rather
than computing it from a prefix length it had assumed.

### A length field is a statement about octets that already exist

So the order inside `encode` is always the same:

1. Encode the children. Join them. Now the body exists.
2. Measure the body. Now the lengths are known.
3. Write the header, with those lengths in it.
4. Compute anything that covers header and body together, and splice it in.

Never the reverse. A length written before the thing it measures is a guess
that happens to be right most of the time, which is the worst kind of bug
to own.

### Sub-TLV framing belongs to the parent TLV, not to the sub-TLVs

A sub-TLV is type, length, value, the same shape as a TLV. **How a list of
them is framed is the parent's business, and the two parents that matter
most do it differently.** Verified against RFC 5305:

* **TLV 22, extended IS reachability, section 3.** Each neighbour entry is 7
  octets of system ID and pseudonode number, "3 octets of default metric",
  "1 octet of length of sub-TLVs", then "0-244 octets of sub-TLVs". The
  length octet is **always written**, as zero when there are none, so an
  entry with no sub-TLVs is 11 octets.
* **TLV 135, extended IPv4 reachability, section 4.** "4 octets of metric
  information", then a control octet holding "1 bit of up/down
  information", "1 bit indicating the presence of sub-TLVs" and "6 bits of
  prefix length", then "0-4 octets of IPv4 prefix". The sub-TLV length
  octet is **written only when that presence bit is set**.

So one parent frames its sub-TLVs unconditionally and the other frames
them behind a bit in a field it wrote earlier. Write one `SubTlv` class
and one list, and let each parent decide whether and how the list is
framed. A single "sub-TLVs under a TLV" mechanism gets one of these two
wrong, and the symptom is a one octet offset that shifts everything after
it.

Three more things fall out of those two layouts, and each is a bug waiting:

* **The metric widths differ**, 3 octets in TLV 22 against 4 in TLV 135.
  Same word, two widths, in one RFC, one section apart.
* **TLV 135 packs its prefix to the minimum octets for its length**, so the
  arithmetic is the familiar `(bits + 7) / 8`. Do not assume that holds
  elsewhere. Whether a prefix is packed down or written at full width is a
  per-TLV decision and has to be read each time.
* **The up/down bit lives in the same octet as the prefix length.** A
  control octet that mixes a flag with a width is the shape most likely to
  be read with the wrong mask, so give it its own method and its own test.

### The worked example, an L1 Link State PDU

This is the most intricate `encode` in the protocol. Every other PDU is a
simpler version of it, so get this one right and copy its shape.

```ruby
def encode
  body   = @tlvs.encode                       # 1. the children
  header = encode_header(body.bytesize)       # 2 and 3. lengths over the body
  with_checksum(header + body)                # 4. a field over the whole
end
```

The header is two parts and they are worth separating, because one is
shared by every PDU type and the other is not:

* **The common header**, the same eight octets in every IS-IS PDU: the
  Intradomain Routeing Protocol Discriminator (0x83), the Length
  Indicator, the Version/Protocol ID Extension, the ID Length, the PDU
  Type, the Version, a Reserved octet and the Maximum Area Addresses.
  This belongs in `Pdu` and is written once.
* **The PDU-specific header**, which for an LSP is the PDU Length, the
  Remaining Lifetime, the LSP ID, the Sequence Number, the Checksum and
  the flags octet.

**Two length fields with different meanings sit a few octets apart, and
confusing them is the first bug this library will have.** The Length
Indicator in the common header is the length of the fixed header. The PDU
Length in the LSP header is the length of the whole PDU. Name them apart in
the code, comment both, and write a test that would fail if they were
swapped.

The checksum is the reason step 4 exists. It is computed over a span that
includes part of the header, so it cannot be written until the header is
written, and it cannot be written as part of the header because it covers
itself as zero. So: assemble with a zero checksum, compute over the span,
splice the result back in. Verify the span against the spec before you
write it down. The Remaining Lifetime is deliberately outside it, because
that field is decremented hop by hop and a checksum covering it would be
invalid the moment the PDU moved.

### The LSP flags octet is four fields, and one of them is not one bit

The flags octet at the end of the LSP header holds P, ATT, OL and IS Type.
**ATT is four bits, not one**, with one bit per metric type: error,
expense, delay and default. Nearly every summary of IS-IS calls it "the
attached bit", singular, because in practice only the default metric bit is
ever set. An encoder written from that summary writes the wrong width.

The masks, to be checked against the chosen ISO edition and meanwhile
sourced as below:

| Field | Mask |
|---|---:|
| P, partition repair | `0x80` |
| ATT, error metric | `0x40` |
| ATT, expense metric | `0x20` |
| ATT, delay metric | `0x10` |
| ATT, default metric | `0x08` |
| OL, overload | `0x04` |
| IS Type | `0x03` |

**Those seven tile the octet, and checking that takes two tests.** Bitwise
OR is idempotent, so a union of `0xff` proves coverage and says nothing
about overlap: `0x01 | 0x01 | 0xfe` is `0xff` too. Both checks, neither
alone:

* **Coverage.** The OR of every mask is `0xff`, so no bit is unaccounted
  for.
* **Disjointness.** Every pair of distinct masks ANDs to zero, so no bit is
  claimed twice.

Run both on any bitfield table before trusting it. It is still the cheapest
verification in this file.

**And it establishes structure, not meaning.** A table with the four ATT
masks reversed passes both checks perfectly, because reversing a
permutation of disjoint masks is still a permutation of disjoint masks.
That is the whole failure mode under discussion here, and the check is
blind to it. So tiling tells you a table is coherent. Only the
specification tells you which name goes with which mask.

Provenance. RFC 1142 clause 9.8 was **read** on 2026-10-31 and gives the
layout above, with bit 1 the least significant (clause 9.1): "P - Bit 8",
"ATT - Bits 7-4", with "Bit 4 - the Default Metric", "Bit 5 - the Delay
Metric", "Bit 6 - the Expense Metric", "Bit 7 - the Error Metric",
"LSPDBOL Bit 3", and "IS Type Bits 1 and 2". That is first hand, but it is
the 1990 republication, so it is historical confirmation rather than the
current standard. It agrees with a November 2003 report on the
ethereal-dev list, subject "ISIS ATT bit definition is wrong", which argued
Ethereal had the four in the reverse order.

**Keep the Ethereal story, and keep it in its place.** It is not evidence
for the layout; RFC 1142 is, for 1990. The tiling checks are blind to
exactly the error in question, so they add nothing to it. **The 2002
edition is still unread**, so assert the masks as RFC 1142 gives them and
cite RFC 1142 by name. What the Ethereal story is evidence for is that the
reversal is a failure mode careful people reach, which is the argument for
writing the test at all.

**The test has to assert the mask.** Asserting `0x08` for the default bit
catches a reversal at once, since a reversed encoder writes `0x40`. The
test that misses it is the **round trip**, which passes whenever encoder
and decoder share the mistake, and that is the usual case because one
person writes both in one sitting. The Testing section makes the same point
about ntop and pton. This is the field that proves it.

So: assert each mask against the number the specification gives, from the
specification and not from this table. Then add the round trip. In that
order, and never the round trip alone.

`IS Type` is two bits, `P` and `OL` one each. Four fields, four widths, one
octet. Verify every one before writing the pack string.

### Narrow and wide metrics both exist, and the library sends both

Two encodings of the same concept are live on the wire at once. The
original metric is six bits of value in one octet, in TLVs 2, 128 and 130.
The extended metric is 24 bits in TLV 22 and 32 bits in TLV 135.

**There are four original metric octets per entry, not one, and they do not
share a layout.** Not one octet holding a value, an internal/external bit
and an S bit. Four octets, two layouts. For TLV 2, read in RFC 1142 clause
9.8:

* The **default** metric octet carries the six bit value, the I/E bit at
  bit 7, and "Bit 8 of this field is reserved".
* The **delay, expense and error** metric octets each carry the six bit
  value, the I/E bit at bit 7, and the **S** bit at bit 8: "If this IS
  does not support this metric it shall set the bit S to 1".

So in TLV 2 every one of the four has an I/E bit, and only the high bit
differs. **TLV 128 does not match.** RFC 1195 section 5.3.4, read: the
default octet has bit 8 reserved and bit 7 I/E, "the metric type ...
for all four TOS metrics", while in the delay, expense and error octets
"Bit 7 of this field is reserved". So TLV 128 has one I/E bit for the
entry and TLV 2 has four. That is the per TLV point below, with an
example.

And **S set means the metric is not supported**, which is the reverse of
what the name suggests and is the single most likely thing to be
implemented inverted here. Document the layout per TLV and per metric kind
rather than once for "the narrow metric", because the four are not
interchangeable. RFC 1195 sections 5.3.4 and 5.3.5 are the IP reachability
formats, and RFC 5302 is worth reading alongside them for what later work
does with the same bits.

Which bits are reserved has also moved: later extensions put meaning on
some of them. So a reserved bit here is a keep-and-echo field like any
other, and a mask written once and reused for all four octets is a bug.

**Both are real traffic and both must be sendable, including both at
once.** A router may be configured for either or for both during a
transition, so a tool that can only speak the extended form cannot test the
transition, which is where the interesting failures are. The operational
consequences of mixing them are in RFC 3787, which is worth reading before
deciding what the library should make easy.

Do not let the words mislead: the six bit field is a metric with a small
range, not a different kind of metric. Narrow and wide are the encodings.

## Computed fields: computed on build, replayed on parse

**This is the most consequential decision in the file and it has to be made
before any class is written**, because two rules that both look obviously
right contradict each other. "Lengths and checksums are always recomputed"
and "a parsed object re-encodes byte for byte" cannot both hold for a PDU
that arrived with a wrong checksum. One of them has to give, and which one
decides how every computed field in the library behaves.

**The resolution: a computed field is computed when the object is built
from values, and preserved when it is parsed from octets.**

| Built from | Length Indicator, PDU Length, checksum, auth value |
|---|---|
| Field values | computed, every time, no option to supply one |
| A hash | computed, every time; a hash never carries a computed field |
| **Wire octets** | **kept exactly as they arrived, right or wrong** |
| Another instance | whatever that instance would encode |

So a capture replays byte for byte including its lies, a built object is
correct by construction, and nothing in between guesses.

**A hash does not carry computed fields, even from a parsed object.** A
hash key that sets a checksum or a length is a `checksum:` option under
another name, and the singleton section below forbids that option for a
reason that applies here too: it moves the lie into the library. So
`to_hash` on a parsed object whose computed fields were wrong loses them,
and the catalog records that loss like any other. To replay those fields,
replay the octets.

**That is the same rule as keeping a reserved bit, and for the same
reason**, which is worth noticing because it means the library has one
principle here and not two. A reserved octet arriving as `0xff` is
somebody's test, and a tool that can send a value no specification
describes but cannot replay what it just received is the wrong shape of
tool. A checksum arriving wrong is exactly that, one field over.

### How an edit invalidates a preserved field

**This is the hardest part of the decision above and the place an
implementation will go wrong.** Invalidation follows **content**, not size.
Change a metric, a prefix, a sequence number or a reserved bit and every
length stays identical while the protected octets change, so a checksum
preserved on a size comparison is now a digest of something that is no
longer there. And the edit can be four levels down: a sub-TLV inside a TLV
inside the LSP.

Three mechanisms are possible. **Pick the third.**

| Mechanism | Why not |
|---|---|
| Immutable children, so an edit rebuilds the parent | Fights the whole purpose: a tool for building odd PDUs wants `lsp.tlvs[3].metric = 999` to work |
| Children notify their parent on change | Every setter must remember to, and the one that forgets fails silently as a stale checksum |
| **Parent keeps the octets it parsed and compares** | Nothing to forget |

**The third needs no cooperation from any child.** At encode time the
parent re-encodes and compares against what it retained. Identical means
nothing under it moved, so the preserved fields are replayed. Different
means something did, so they are recomputed. A new setter cannot defeat it,
because it never asked the setter for anything.

It is also the only one of the three consistent with the composition rule:
the parent assumes `child.encode` and nothing more. The other two require a
second channel between child and parent that the rule says does not exist.

**Nesting then costs nothing.** Each level compares its own span against
what it kept, so a metric changed inside a sub-TLV shows up as a differing
span at every level above it, with no propagation to implement and nothing
to get wrong. That is the test to write: edit a field several levels down
and assert the root recomputed.

### One retained input per calculation, not one per object

Two computed fields means **two retained inputs**, because the checksum and
the digest cover different octets and normalize different fields. One
shared span cannot express what follows.

| Calculation | Covers | Normalized to zero first |
|---|---|---|
| LSP checksum | from the LSP ID to the end of the PDU | the Checksum field |
| RFC 5304 digest | the whole PDU, header included | Checksum, Remaining Lifetime, Authentication Value |

**The two are ordered, not parallel, and that is the whole of this
section.** The digest normalizes away both the checksum and its own value,
so it depends on neither output. The checksum's span contains the
Authentication TLV, so it depends on the digest's output. A one way
dependency, so no loop, but the order is not optional:

```text
digest first  ->  its bytes land in the Authentication TLV
              ->  checksum input built WITH those bytes in place
              ->  checksum
```

That is the step order the authentication section already gives. The
comparison has to follow it: **build the checksum's input from the PDU with
the final authentication bytes inserted**, never from the PDU as parsed.

**So a common header edit reaches the checksum, transitively.** The header
is outside the checksum's span, so for an **unauthenticated** LSP a
same-size header edit leaves the checksum alone. For an **authenticated**
one the chain runs header, digest, Authentication TLV, checksum span, and
the checksum must be recalculated. The header is outside the checksum's
coverage; the digest it changed is not.

**A Remaining Lifetime edit still invalidates neither**, and that survives
the chain: it is outside the checksum's span and the digest normalizes it
away, so the digest is unchanged, so the authentication bytes are
unchanged, so the checksum's input is unchanged. That is what makes aging a
stored LSP possible at all when the library has no key.

**Normalization is what keeps a calculation from triggering itself.** The
digest's input zeroes the Checksum and the Authentication Value, so the
digest is stable under both outputs. The checksum's input zeroes the
Checksum field, so it is stable under its own. Without that, writing one
output changes the other's input and the pair never settles.

So the retained input is always the **normalized** bytes, never the raw
ones. Five tests, and the last catches a loop:

1. A same-size edit several levels down recomputes both.
2. A same-size common header edit on an **unauthenticated** LSP leaves the
   checksum unchanged.
3. The same edit on an **authenticated** LSP recomputes the digest and
   then the checksum.
4. A Remaining Lifetime edit recomputes neither, authenticated or not.
5. **Two consecutive `encode` calls return identical octets.** A
   self-triggering pair passes the first four and fails this one.

Test 2 against test 3 is the pair that proves the dependency is modelled
rather than assumed away in either direction.

The cost is one extra encode per calculation per `encode`. That is the same
price the packing section already accepted, for the same reason: at IS-IS
item counts it does not register.

Three further consequences to design in rather than discover:

* **`recompute!` and `preserved?` are public.** A caller replaying a
  capture wants to know whether what it is about to send is the original
  arithmetic or ours, and a caller editing one wants to force the issue.
  Neither should have to infer it.
* **The exactness promise is about the fields, not about luck.** A parsed
  object re-encodes identically because it kept the fields, not because
  the recomputation happened to agree. Write the test with a capture whose
  checksum is deliberately wrong, so it cannot pass by agreement.
* **A test still has to be able to build a wrong PDU from scratch**, not
  only replay one, because that is the input a router's parser is most
  likely to mishandle.

Resolve that the way bgp4r does, and do not resolve it by adding a
parameter. Override the method at runtime on the one object you are lying
with:

```ruby
lsp.define_singleton_method(:encode) do |*a|
  s = super(*a)
  s[8, 2] = [9999].pack('n')   # a PDU Length that is not true
  s
end
```

The class stays correct, the send path is the ordinary one, and the lie
lives in the test that wanted it. Patching the encoded String and sending
that works too, since the link layer takes a String and writes it
unchanged.

Write a `checksum:` or `pdu_length:` option and you have moved the lie into
the library, where it will eventually be set by accident.

## Parse, and the three things it must declare

### Whether it consumes

If `parse` reads with `slice!` it empties the String it was handed. That is
fine, and it is efficient, but it is a property of the class and the caller
has to know it.

**Pick one convention and hold it.** The recommendation: **every `parse`
consumes exactly its own octets and leaves the rest.** That makes a list
loop trivial, which matters because IS-IS is nothing but lists:

```ruby
until s.empty?
  @tlvs << Tlv.factory(s)   # each one takes its own bites
end
```

bgp4r did not hold one convention, and it costs a line in its guide and an
afternoon every few months. The symptom is memorable:
`assert_equal(octets, Klass.new(octets).encode)` fails while both sides
print the same hex, because the left side was emptied before the comparison
ran. Compare encoded hex, not the input you passed.

### What it needs that is not in its own octets

**This is the structural difference between IS-IS and a protocol like BGP,
and it has to be designed for rather than discovered.**

The common header carries an **ID Length** field, and it decides how wide
a System ID is wherever one appears below. The Source ID in the header
itself. An LSP ID, which is a System ID plus a pseudonode octet and an LSP
Number octet. The LAN ID in a hello. A neighbour record in TLV 2. None of
those octets say how long they are. The header said, once, at the top of
the PDU.

So the ID length is a **parse-time input**, threaded from the header down
into every node that needs it, exactly the way a flow spec component needs
its AFI in bgp4r. Design that in from the first commit:

* `Pdu.factory(octets)` reads the common header and holds the ID length.
* Everything it builds takes the ID length as an argument.
* A class that does not need it does not take it.

**It does not scale everything that looks like an identifier, and getting
that wrong is worse than not threading it at all.** A neighbour entry in
TLV 6 looks like a case for it and is not:
TLV 6 is the IS Neighbours TLV carried in LAN hellos and its entries are
six octet **LAN addresses**, which are MAC addresses of the link and have
nothing to do with the System ID or with ID Length. TLV 2 is the one whose
entries are System ID based. Two TLVs with nearly the same name, one scaled
by ID Length and one not.

So the third bullet above is the load bearing one. Work out per field
whether it is a System ID or an address that merely looks like one, write
the answer in the class, and do not pass the ID length to a class that does
not need it: a class that accepts it will eventually use it.

**Keep the list of parse-time inputs short and write it down.** Today it is
the ID length, as `id_width:`. It reaches a TLV through `Tlv.factory` only
if the class names it in `PARSE_INPUTS`, and wire octets take it as a
keyword, `Klass.new(octets, id_width: 8)`. The first class to need it is
TLV 240, whose Neighbor System ID is ID Length octets wide and whose own
length cannot say which: 11 octets is a six octet ID alone or a two octet
ID with a circuit ID after it. The second is TLV 9, whose LSP entries are
ID Length plus ten octets each, so the same octets read as a different
number of entries at a different width. Both take the same one input.
`docs/building-objects.md` has the rule. If a second input appears, that is
a design event worth a paragraph in the guide, not a quiet extra argument.

**The ID Length encoding is a trap and must be verified in the spec, not
recalled.** The field does not mean what it appears to. A value of zero
means the default of six octets, and one particular value means a null
System ID rather than a length. Read ISO 10589, write the mapping in one
method, and put the quoted sentence in a comment beside it.

### What it does when a length lies

A length field is written by someone else, so it can say anything. **The
parse policy is seven rules, written once in the base classes, and every
list loop in the library obeys them.** Without them the loop idiom above is
a hang waiting for the right capture.

1. **An enclosing boundary is always passed down, and it always wins.** A
   TLV knows how many octets its PDU has left; a sub-TLV knows how many its
   TLV has left. A declared length larger than that boundary is **clamped
   to the boundary**, never followed. Following it reads another object's
   octets, or past the end of the buffer, and reports a field that was
   never sent.
2. **A clamp is recorded, not silently absorbed.** The object keeps the
   length as declared, so `encode` replays it, and the discrepancy becomes
   a finding. That is the same keep-the-declared-length rule the `Unknown`
   classes follow, applied to a class that is implemented.
3. **Every parse consumes at least one octet, or the loop stops.** A TLV
   header is two octets, so a remainder of one cannot be a TLV and becomes
   a tail. A declared length of zero still consumes the two header octets,
   so it makes progress whether or not that type permits it, which is a
   separate question; a bug that consumes nothing must not spin.
   Put the backstop in the loop, not in the hope that no class has that
   bug.
4. **Octets left over at the end of a container are kept as a tail**, not
   dropped and not treated as a failure to parse the container.

5. **A layout that cannot read its whole fixed header does not build one.**
   The rules above cover a PDU whose TLVs are cut short. A capture can stop
   inside the header itself, halfway through a Sequence Number, and then
   the recognised layout has fields it never received. Reconstructing the
   header from what it did parse **synthesises octets that never arrived**,
   which is the one thing the replay rule forbids. So: keep the available
   octets as a truncated representation of that PDU, note how far the read
   got, and let `encode` return exactly those octets and no more. A
   truncated LSP is not an LSP with some fields unset.
6. **The declared PDU Length and the captured boundary are two different
   numbers, and they go wrong in four ways.** Rule 5 covers only one of
   them, an incomplete **fixed header**, so do not route the rest there.
   * **Header incomplete.** Rule 5. No layout is built.
   * **Header complete, declared length runs past the capture.** The
     ordinary bounded body parser, rules 1 to 4, with the boundary being
     what actually arrived rather than what was declared. The layout is
     built, the TLVs that arrived are parsed, the shortfall is a finding.
     This is the common case in a real capture and it needs no special
     machinery.
   * **Declared length shorter than the capture.** Octets arrived after
     this PDU ended: another PDU, link padding, or capture slack.
   * **Declared length shorter than the fixed header the layout
     requires**, zero included. This one has no honest reading at all: the
     PDU claims to be smaller than the fields it must contain. Build an
     explicitly malformed representation holding whatever arrived, and
     **never let the value reach arithmetic**, because `declared minus
     header_length` is negative and a negative body length is a crash or a
     loop depending on where it lands. Clamp at the point of reading, not
     at the point of use.
7. **The replay promise is about the consumed slice, not the declared
   length**, and those are different numbers often enough that equating
   them is a bug. A PDU replays **exactly the octets it actually
   consumed**, whatever its length field claimed, and it retains the
   declared value separately so `encode` can write that claim back. The
   three cases:

   | Situation | Consumed | Retained |
   |---|---|---|
   | Declared exceeds what arrived | only what arrived, within the boundary it was given | the declared value, written back as it was |
   | Declared below the required header | whatever arrived, as malformed | the declared value, and no arithmetic uses it |
   | Declared valid, extra octets follow | the declared extent | nothing extra; the remainder is not this PDU's |

   **Octets past a PDU's declared end belong to the level above it.** That
   is what keeps "keep the excess separately" from contradicting "every
   object replays its input exactly", which it did as written. Both
   promises hold once they are scoped: a PDU replays its consumed slice, and
   a capture or frame object above it owns the remainder and replays the
   complete input it was handed.

   So the outermost object is not a PDU. Something has to hold a tail at
   that level, which means the design needs a capture representation above
   `Pdu` rather than treating a PDU as the root. That is rule 4 applied one
   level further out, and it is cheaper to put there now than to retrofit
   when the first pcap with two PDUs in a buffer arrives.

Those seven are what make "it must be exact" achievable on input nobody
checked. State them in `docs/`, and write the truncation tests first: a TLV
whose length overruns its PDU, a sub-TLV whose length overruns its TLV, a
one octet remainder, a PDU cut off mid-TLV, a PDU cut off inside its fixed
header, and a declared length shorter than the capture.

Each should produce an object that replays its input exactly. **Most should
also produce a finding, and not all**: a TLV with a declared length of zero
makes progress and is a seventh test worth writing, but whether it is legal
is specific to the type, so it belongs in the per-TLV rules and gets a
finding only where that type's own clause says so. Do not write a blanket
assertion that every odd length is an error.

## Keep what you cannot read

**When parsing cannot interpret something, keep it whole and write it
back.** A capture from a router that speaks something isis4r does not must
survive the round trip and go back out byte for byte. This is not a
nicety: it is what lets the library be pointed at real traffic on day one.

Three levels, so three classes:

* `Pdu::Unknown` for a PDU type not implemented. **Opaque octets, and it
  does not parse TLVs out of them.** The temptation is to trust the common
  header's Length Indicator, treat everything past it as a TLV area, and
  hand back an Unknown full of `Tlv::Unknown`s. Do not: for a PDU type
  nobody implemented, nothing establishes that the body is TLVs at all,
  nor where they begin, and the Length Indicator is a field written by the
  sender like any other. Parsing on that assumption invents structure and
  reports fields that were never sent. Keep the octets, say which type
  number arrived and how many octets followed, and stop.
* `Tlv::Unknown` for a TLV type not implemented, keyed by type so the dump
  says "TLV 199, 14 octets" rather than nothing. This one **is** framed,
  because the TLV framing is type, length, value for every type, known or
  not, so its extent is readable without understanding it.
* `SubTlv::Unknown` for a sub-TLV under a TLV that is implemented, same
  reasoning, with the extent bounded by the parent.

The difference between the first and the other two is the whole point:
**an extent you can read without understanding the contents is the licence
to frame.** A TLV has that and an unknown PDU body does not. The same test
decides every future case.

Each builds all the ways above and each **keeps the declared length even
when it disagrees with the value it found**, so a malformed capture can be
replayed as malformed. A class that silently repairs what it read has
destroyed the evidence.

The same rule applies inside a class that is implemented:

* **Trailing octets** a TLV cannot interpret are kept and written back.
* **Reserved bits** that arrived set are kept and echoed, not zeroed.
  Writing zero is right when building from field values, since that is what
  the spec asks an encoder for. Echoing is right when replaying, since a
  reserved octet arriving as `0xff` is somebody's test and the tool must be
  able to send it back.

Carry the extra information in the hash only when it is unusual: no kept
tail, no `:tail` key; no reserved bit set, no `:bits` key. An ordinary
object then hashes exactly as it always did, and the hash stays readable.

## to_hash, and the one thing to do differently from bgp4r

**A TLV list hashes as a list, not as a map keyed by type.**

bgp4r keyed its path attribute hash by attribute type, which was reasonable
there, and then had to bolt on a `:duplicates` key when it turned out two
attributes of one type can arrive. The fix works and the reasoning behind
it is sound, but the shape was wrong from the start.

**In IS-IS, repetition is not the exception. It is the design.** A TLV
value is at most 255 octets because the length is one octet, so anything
larger is sent as several TLVs of the same type. A router with forty
neighbours sends many TLV 22s as a matter of course. A hash keyed by type
cannot hold that and should never be asked to.

So:

```ruby
{ :pdu => :l1_lsp,
  :lsp_id => '1921.6800.1001.00-00',
  :sequence => 7,
  :tlvs => [ { :area_addresses => ['49.0001'] },
             { :protocols_supported => [:ipv4, :ipv6] },
             { :extended_ip_reachability => [ ... ] },
             { :extended_ip_reachability => [ ... ] } ] }
```

Order is preserved, repetition is free, and nothing has to be bolted on
later.

### The one hash contract

Stated once, because "every hash round trips" plus a list of exceptions is
two contracts and reads as a contradiction. There is one:

**The hash is a convenience for writing tests as values instead of as hex.
It is not part of the protocol and nothing on the wire depends on it. Where
it can rebuild the object it must, and where it cannot, the catalog says
so.**

What follows from that, and all of it is enforced rather than asked for:

* A class whose hash rebuilds the object has a test proving it, in its own
  test file, exercising every field the class carries.
* A class whose hash cannot has an entry in the catalog naming what it
  loses, with a reproduction and a decision.
* A class in neither place fails the suite, so a new class has to be
  measured and decided rather than assumed.
* **The rule is one way.** A gap may stay a gap. A round trip that works
  must not stop working, because other people's tests are built on it.

Keep the catalog as a file the suite reads, measure it against the library
on every run, and print the counts from it rather than writing them in
prose. A number written in prose is a number that will be wrong.

Why a gap is tolerable at all: a hash is an argument to `initialize`, so
what has to come back is the instance state, and a field that no key sets
cannot survive. Every gap is an instance of that one sentence, which is
why the answer is a recorded reason rather than a campaign.

## Building never validates

**This library must be able to put octets on a wire that no standard
allows.** Any PDU type, any TLV in any order, a TLV inside a PDU that
forbids it, a length that lies, a checksum that is wrong, a TLV 1 with no
area in it, the same TLV forty times.

So:

* No check in a constructor that refuses something merely invalid.
* No check in `encode`.
* No check in `to_hash`.

A constructor may refuse an input it **cannot represent at all**, such as an
integer too large for the field it goes in, because the alternative is
silently sending a different value than the caller asked for. It may never
refuse a combination that is simply wrong by the spec.

Where a constructor does refuse, **the octet level route stays open**:
building from wire bytes, and an `Unknown` of the right level, must always
work. There is no input the library cannot express.

## Validation

Validation exists, and it lives in exactly one place, and it runs only on
what was received.

* One file, `isis/validation.rb`. A rule is added there with the clause it
  comes from, never in the class it is about.
* **It decides nothing.** What a finding does to adjacency, database or
  routing state is the receive policy's job, under "Autonomous operation
  and testing controls".
* It reports findings. It does not raise, except under an explicit strict
  policy a caller asks for.
* **An `errors` finding, and only that channel, means the sender got
  something wrong.** The other two channels below mean something else and
  must never be reported as the peer's fault. A conformance tool that
  reports its own missing code as the peer's error gives a confident wrong
  verdict about a correct router, which is the worst failure a tool of
  this kind has.

**So there are three channels and not two.** The second one is the usual
omission; the third is the one that makes this library's verdicts
defensible at all.

| Channel | Means | Example |
|---|---|---|
| `errors` | the sender violated a clause | a TLV type the standard forbids in this PDU |
| `gaps` | isis4r has no code for this | a valid TLV type nobody implemented yet |
| `inconclusive` | the octets do not support a verdict | a PDU the capture cut short, or a rule needing a TLV that is not in this PDU |

The third is not fastidiousness. **A truncated capture looks exactly like a
truncated PDU**, and the library cannot tell them apart from the octets, so
calling it a protocol error is a guess presented as a result. The same
applies to any rule that needs more context than the thing being checked:
if a check needs a second TLV, or another PDU, or session state, and it is
handed one TLV, the honest answer is that it did not run. bgp4r met this
from the other direction and left its cross-attribute checks unimplemented
rather than approximate them, which was right.

Keep the channels independent: run the checks on the raw octets, before and
regardless of whether the decoder succeeded. Then a PDU that is both
malformed and undecodable gets an entry in each, and neither waits on the
other.

**A finding carries where it came from.** The clause for an `errors` entry,
the missing class for a `gaps` entry, and what was missing for an
`inconclusive` one. A finding nobody can trace back is an opinion.

**Do not invent an error response the spec does not specify.** If ISO 10589
says what a receiver does with a malformed PDU, implement that and quote
it. If it does not, record that it does not. Copying what one router
happens to do is not the same as the spec saying it, and one implementation
agreeing with you is not a quorum.

## The 255 octet limit is a packing problem, not an encoding one

A TLV value longer than 255 octets cannot be encoded. That is a fact about
the framing, and the TLV class should refuse it, because it genuinely
cannot represent it.

**Splitting content across several TLVs is a separate job and belongs in a
separate object.** A builder takes the content and returns a list of TLVs
that carry it. The TLV class stays dumb and the splitting rules, which
differ per TLV type, stay in one readable place.

The same separation applies one level up: fitting TLVs into a PDU is the
builder's job, not the PDU's.

**The limit for an LSP is not the link MTU.** An LSP is flooded, so it has
to be receivable everywhere it will go, not merely sendable on the
interface it leaves by. Read in RFC 3719 section 5, and worth getting
exactly right because the terms point in opposite directions:

* **`originatingL1LSPBufferSize` and `originatingL2LSPBufferSize`** are
  "two private management parameters" bounding the largest LSP this router
  will **generate**, per level.
* **`ReceiveLSPBufferSize`** is what a router will **accept**. ISO 10589
  gives it as **1492 octets**, an architectural value and **not a
  ceiling**: RFC 3719 section 5 discusses configuring it higher for
  networks that support larger LSPs, noting that it enlarges the LSP
  database, otherwise bounded at 256 times 1492 per level, and that it
  "must be done with care".
* The rule is `originatingL1LSPBufferSize <= ReceiveLSPBufferSize`, and
  the same for L2, and each originating size must also not exceed the MTU
  of the links at that level.
* **The consistency requirement is on `ReceiveLSPBufferSize`**, which must
  be "a consistent value throughout the network". The originating sizes do
  **not** all have to be identical. They each have to fit.

**TLV 14 advertises the originating size, not the receive capacity.** It
lets a receiver detect a mismatch with its own capacity, so the
recommendations are to
include it when generating LSPs, to check it on receipt, and to report a
value above the local `ReceiveLSPBufferSize`. A mismatch causes routing
loops and black holes because LSPs do not propagate fully.

**One recommendation there bears directly on this library's receive side**:
do not discard an oversized PDU by default. Storing and processing it may
keep a misconfigured network coherent. So an oversized PDU is a finding and
not a reason to drop, and the default receive policy admits it. That is
also the only behaviour that lets the library be used to watch what a
router does with one.

So the builder takes **two** budgets and keeps them apart: an originating
LSP size budget, checked against the **configured** receive capacity and
the applicable circuit MTUs, and a link framing budget, which bounds what
any single transmission can carry. They fail differently. The first
produces an LSP somebody refuses to store. The second produces a frame
nobody can send. Hellos and the sequence number PDUs are bounded by the
second only, since they are never flooded.

**Both budgets are configuration handed to the builder, and 1492 is a
default rather than a limit this library imposes.** Anything else would
contradict the rule that building never validates: originating a 9000
octet LSP to watch a router refuse it is a test somebody will want, and the
encoder has no business preventing it. So the number lives in the builder's
configuration, the default matches the architectural value, and raising it
is a caller's decision.

**`encode` does not enforce configured operational size budgets.
Representability checks still apply**, and the two are different kinds of
limit. A budget is somebody's policy about what is sensible to originate,
so the encoder ignores it. A one octet length field that cannot hold 300 is
arithmetic, so the encoder raises, exactly as the TLV framing does. The
library's one rule about refusing covers both cases from the same side: it
refuses when it cannot produce the octets, never when it disapproves of
them.

**The builder encodes each child once, keeps the bytes, and measures them.
It does not predict sizes with arithmetic.** Predicting contradicts the
composition rule two sections up: if the only thing a parent may assume
about a child is that `child.encode` returns its octets, a parent that
predicts a child's length has assumed something else. It also means two
implementations of every layout, the encoder and the size formula, which
drift.

bgp4r predicts, and the reason does not transfer. A BGP prefix is
`1 + (len + 7) / 8` octets and a full table is about a million of them, so
re-encoding per candidate is the difference between a second and an hour.
An IS-IS PDU holds tens or hundreds of TLVs and is bounded by the link MTU,
so encoding each once and summing `bytesize` is exact, simpler, and fast
enough that the question does not arise. Measure the finished PDU once as
well, so a slip raises instead of putting an oversized PDU on the wire.

Where a size genuinely is needed before the bytes exist, give the class a
method that answers it **by encoding and measuring**, not by a parallel
formula. One implementation, and it cannot disagree with itself.

**And a third level above that, which is the one with a field attached to
it.** When a router's advertisements will not fit in one LSP, they go out
as several, distinguished by the LSP Number, the last octet of the LSP ID.
So there are three packing problems stacked:

| Level | Overflows at | Carried by |
|---|---|---|
| Content into a TLV | 255 octets of value | repeated TLVs of one type |
| TLVs into a PDU | the LSP size budget, or the link framing budget | nothing, it has to fit |
| Advertisements into LSPs | one LSP | the LSP Number |

Three builders, one per row, and none of them in an encoding class. The
rows are independent: a TLV that repeats because of row one has nothing to
do with an LSP that splits because of row three, and conflating them
produces a splitter that cannot explain its own output.

**Call it the LSP Number in code.** Routers and operators call it the
fragment, which is the useful word in conversation and the wrong one here,
because the specification calls it the LSP Number and because it has
nothing to do with IP fragmentation: there is no reassembly, each LSP is
independent, floods on its own and ages on its own. A reader who takes
"fragment" literally goes looking for a reassembly step that does not
exist. Accept the word in prose and in a comment. Keep it out of the field
name.

## Authentication is a fixup, like the checksum

The authentication TLV covers the PDU that contains it, including its own
value field. So it is the same shape as the checksum: assemble, compute
over the span, splice in. Two fixups in a defined order, and the order
matters. Write down which runs first and why, and put a test on a PDU that
carries both.

**Only part of the TLV value is zeroed, not the TLV.** Read in RFC 5304:
TLV type 10, whose "first octet of the value is used to specify the
authentication type", with "the remainder of the TLV value ... known as the
Authentication Value". For HMAC-MD5 the type is 54, the value is 16 octets
and the TLV length is 17. Before computing, the **Authentication Value** is
zeroed while the authentication type octet stays set to 54 and the length
stays 17: "the Authentication Type is set to 54 and the length of the TLV
is set to 17 before authentication is computed". RFC 5310 adds a Key ID,
which likewise stays populated.

So the thing that gets prepared is a field inside the value, and the
preparation is the **algorithm's** to specify. RFC 5304 zeroes it. RFC
5310's generic cryptographic authentication prepares it differently, and
its sections 3.3 and 3.4 are where to read that; it is not read here yet.
Write the fixup to ask the algorithm what to put there, splice, compute,
splice the result. Write it that way while only one algorithm exists, or
the second has to be threaded around a zeroing step buried in the PDU.
Cleartext authentication is a third case and shares none of this.

### The order, and which half of it is the RFC's

1. Assemble every field and any padding, so the octets exist.
2. Ask the algorithm to prepare the Authentication Value in place, leaving
   the type, length and any Key ID populated.
3. **Zero the LSP Checksum and the Remaining Lifetime.** RFC 5304 section
   2: "Checksum and Remaining Lifetime fields are set to zero (0) before
   authentication is computed." **The two are zeroed for different
   reasons.** Remaining Lifetime is decremented during normal flooding, so
   a digest covering it would fail at the next hop. The **checksum is not
   modified in transit**: RFC 1142 clause 7.3.11, read, says "The
   checksum shall never be modified by any other system", and clause
   7.3.14 has a receiver of an LSP with an incorrect checksum "overwrite
   the Checksum and Remaining Lifetime with 0" and treat it as expired.
   It is zeroed because the checksum covers the digest, so the
   digest must not cover the checksum, which is the circular dependency
   the previous section is about.
4. Compute the digest, write it into the Authentication Value, restore the
   real Remaining Lifetime.
5. Compute the LSP checksum and write it in.

**Steps 1 to 4 are RFC 5304's. Step 5's position is not, and the
difference matters.** The RFC specifies that the Checksum field is zeroed
during authentication and restored on receipt, and it gives **no
sender-side ordering** between the two computations. Checksum last is a
derivation, and the reason is that the checksum covers the Authentication
TLV's own octets, so computing it before the digest is written would
checksum a field about to change. Cite the derivation as a derivation.

### An authenticated capture that is edited without a key

Preserving the digest on an unmodified capture is right. Once protected
content changes, the library cannot produce a valid one without the key,
and all three quiet answers are wrong: keeping the stale digest claims a
validity the PDU does not have, zeroing it sends something nobody asked
for, and recomputing with no key is not possible.

**So it reports.** Encoding an edited authenticated PDU with no key raises,
naming the field and saying a key is needed.

**And the escape route cannot be the singleton override.** That override
calls `super` first and patches the result, so against a method that raises
it never runs at all: the one case it would be invented for is the one case
it cannot reach.

Two routes that do work, and they answer different questions:

* **`replay`** returns the octets the object was parsed from, exactly, with
  no encode step and so nothing to raise. This is the whole of "send me
  that capture again", it needs no key by construction, and the link layer
  takes a String. It is the right answer for an unedited capture and it
  should be the documented default for replay work.
* **`preserve_authentication!`** is the explicit opt-in for the edited
  case: encode with the retained digest even though the protected octets
  moved. The method name is the point. A test that calls it is on record as
  sending a PDU whose digest is wrong on purpose, which is a real test and
  should look like one.

The singleton override keeps its place for a PDU **built** from values,
where nothing raises and patching the encoded result is the cleanest way to
lie about a length or a checksum. Three routes, three jobs: replay an
original, send a knowingly stale digest, or fabricate a wrong field.

**The rule that generalizes**, stated in full once here and used in the
idiom and packing sections. The library refuses only when it **cannot
produce the octets**, never when it disapproves of them. A value too large
for its field and a digest with no key are both the first kind. Nothing
anywhere is the second kind.

The replay rule still holds for the untouched case: a parsed PDU keeps the
authentication value it arrived with, so a capture with a bad digest can be
sent again exactly as it came, which is the whole reason anyone points this
library at a router.

## Codepoints

Keep them in one file, with the registry's own names beside the numbers.

**The IANA "IS-IS TLV Codepoints" registry is the index**, and it is
reachable from this sandbox. So "check the registry" is a real instruction
and not a wish. Two things about fetching it: search and follow a result
link, because a URL assembled by editing a path tends to be refused; and a
third party mirror is worth less than one read of the defining document,
because mirrors go stale silently.

**The base spec is the awkward one.** RFC 1195 and the extension RFCs are
free. ISO/IEC 10589 is not an RFC and is not always to hand. When it is not
available, say in the comment that the claim is second hand and from where,
rather than writing it as though it were read. A claim nobody can check
reads as verified, which is how a wrong one survives.

Three documents, and which one a citation came from matters:

* **ISO/IEC 10589:2002, second edition**, is the base standard. Paid.
  **INCITS/ISO/IEC 10589:2002 (R2022)** from the ANSI store is the
  identical national adoption, so either is the same text. R2022 means
  reaffirmed in 2022 and is not a newer edition of the protocol.
* **RFC 1142** is free and is the same protocol republished in **1990**,
  twelve years before the edition above. It is sound for the algorithm and
  the vocabulary. It is **not** a source for a clause number, because the
  numbering and the content both moved. Cite it as RFC 1142 by name and
  never as "ISO 10589 section N".
* **RFC 1195** is Integrated IS-IS, which is where IP enters the protocol
  at all. Most of what this library encodes for IP traces to here or to the
  extension RFCs, not to the base standard.

**Checking a citation means reading the section, not the title**, and this
file is where that was learned the hard way. Three citations in a set of
notes about this protocol were called misplaced here on the strength of
their titles. Then they were read:

* **RFC 5120, cited for packet terminology.** Its title is M-ISIS, Multi
  Topology. Its **section 1.2 is "Definitions of Terms Used in This
  Document"** and defines CSNP, DIS, IIH, LSP, PSNP and SPF outright. The
  citation was correct and the criticism was wrong.
* **RFC 9681, cited for PDU families and for IS-IS running over the link
  layer.** Its title is IS-IS Fast Flooding. Its section 5.2 opens "There
  are three classes of PDUs sent by IS-IS", section 5.1 covers PSNPs
  acknowledging LSPs on point to point networks, and **section 8 says in
  so many words that IS-IS does not run over IP but directly over the link
  layer**. Correct on all three counts, and wrong again.
* **RFC 5303, cited for LAN adjacency behaviour.** Title and content agree:
  "Three-Way Handshake for IS-IS **Point-to-Point** Adjacencies". This one
  was genuinely misplaced.

One of three. **The failure was not carelessness about whether the RFCs
existed; it was substituting the title for the section**, which is the
identical shortcut to writing a clause number from memory and produces the
same confident wrong result. A title tells you what a document is mostly
about. A citation is a claim about one passage.

So: fetch the section and quote it, or write "unverified" beside the
reference. There is no third option, and "the title says otherwise" is not
one. The same check went the other way on RFC 3563 below, where the
expectation was that the citation would be wrong and reading it showed it
was right.

A citation that is real, relevant sounding and about something else is
still worse than a missing one. That part stands. What changed is who is
most likely to produce one.

**Cite the clause in a comment when you implement wire format logic**, and
open the document to check the number rather than writing it from memory. A
wrong citation is worse than none, because it reads as verified and sends
the next reader to the wrong page.

## Testing

### Hex is the canonical form of an object

**In a test, an object is its encoded value as a hex string.** Give every
class a `to_shex`, and assert on that.

The reason is not convenience. **Hex is the only representation the
specification and the library share.** A clause describes an encoding field
by field, with widths and bit positions. A reader can turn that description
into a hex string by hand. Nobody can turn it into a Ruby object. So the
expected value in a test is hex written out of the document, and the
assertion compares it against what the library produced:

```ruby
# The Area Addresses TLV: type 1, length, then each area as a length
# octet followed by that many octets. Area 49.0001 is 3 octets, so the
# value is 03 490001 and the TLV length is 4.
def test_one_area
  assert_equal('010403490001', Area_addresses.new('49.0001').to_shex)
end
```

That expectation came from the clause, not from the library. When it fails,
one of two things is wrong: the code, or the reading. Both are worth
finding. A test that asserts on whatever the library already prints finds
neither, and passes forever.

**That very example was written wrong here first**, as `010449010001`,
dropping the per-area length octet the comment above it describes. The
prose was right, the hex did not match the prose, and a reader checking the
hex against the clause caught it. **Spell the field breakdown out in the
comment for that reason**: without it the wrong hex looks as plausible as
the right one, and nobody can check either.

Three rules follow.

* **Never assert object equality.** Two objects can be equal and encode
  differently, and `==` is a method somebody has to write and get right.
  Hex is definitive and needs no code to be trusted.
* **Never assert against the input String.**
  `assert_equal(octets, Klass.new(octets).encode)` fails when `parse`
  consumed its argument, and both sides print the same thing while it
  fails, which costs an hour every time. Compare `to_shex` with `to_shex`.
* **Say where an expectation came from**, because they are not worth the
  same. Ranked:
  1. **A worked example in the specification.** Its hex is the document's
     own, so it is independent of this reader's understanding of the
     document, which is the thing under test. Use these wherever they
     exist, and quote the clause beside them.
  2. **A capture from a real router.** Proves somebody else agrees.
  3. **Hex you worked out from the clause yourself.** Still worth far more
     than asserting what the library prints, since it checks the code
     against the document. But write in the test that the expectation is
     your arithmetic, so the next reader knows which side to doubt first.

  The ranking is not theory. On a protocol with worked examples, hand
  written expectations get written wrong often, and the document's hex is
  what catches them. **When a hand written expectation and the library
  disagree, print both sides before concluding anything**: it is the
  expectation about half the time.

### Both directions, ntop and pton

`inet_ntop` and `inet_pton` name the two directions, and **every identifier
and address class owes both**. That is the scope, not every class that has
a `to_s`: a composite's `to_s` is a dump for a person to read and owes no
reverse direction, for the reasons under the object contract. System ID,
LSP ID, area address, LAN address, ISO and IP prefix. Those are the ones
this section is about.

* **ntop, network to presentation.** Octets in. `Klass.new_ntop(octets)`
  builds the object and `to_s` gives the human form. Six octets become
  `1921.6800.1001`. Eight become `1921.6800.1001.00-00`.
* **pton, presentation to network.** The human form in.
  `Klass.new('1921.6800.1001')` builds the object and `encode` gives the
  octets back.

**Each direction needs its own test, and the round trip needs a third.**

```ruby
def test_ntop
  assert_equal('1921.6800.1001', System_id.new_ntop([HEX].pack('H*')).to_s)
end

def test_pton
  assert_equal(HEX, System_id.new('1921.6800.1001').to_shex)
end

def test_round_trip
  assert_equal(HEX, System_id.new_ntop([HEX].pack('H*')).to_shex)
end
```

The round trip is not either of the other two. It passes when both
directions are wrong in the same way, which is the commonest way for them
to be wrong, since one author writes both in one sitting. So it is the
third test and never the only one.

**The direction with a name gets tested. The direction without one gets
assumed.** bgp4r names `new_ntop` explicitly in a dozen classes and has no
`pton` method anywhere: that direction is the ordinary constructor followed
by `encode`, which does not look like a direction and so does not get a
test of its own. Name both here.

**IS-IS gives you nothing to lean on for either half.** For IP there is a
standard library call and both directions are somebody else's problem. A
System ID, an LSP ID with its pseudonode and LSP number, a variable length
area address, an ISO prefix: every one of those presentation forms is code
written in this library, both ways. Printing can be right while parsing is
wrong, and only a pton test says so.

**A presentation form that cannot be parsed back is a bug, however well it
prints.** When `to_s` feeds `new`, a dump from a live session can be pasted
straight into a test as a fixture, which is the most useful thing a library
of this kind produces. When it cannot, every fixture has to be hand built
from hex.

**The presentation forms are conventions and not specification, so this is
the one place to copy routers rather than the document.** ISO 10589
describes octets. It does not say that a System ID prints as three
dot-separated groups of four hex digits, or that an LSP ID appends its
pseudonode and LSP number after a hyphen. Those come from vendor command
lines. Pick what real routers print, because the whole value of `to_s`
feeding `new` is pasting a line out of a router dump, and say in a comment
that the form is a convention with no clause behind it. That keeps the next
audit from going looking for one.

### The rest

* One test file per source file, same name with `_test.rb`, in the matching
  folder under `test/unit/`.
* Write class names out in full in a test file, and `include` into the test
  class, never at the top level. A top level `include` leaks into `Object`
  and every file loaded afterwards sees those names, so a test written that
  way passes in the suite and fails on its own.
* The mirror image is just as real: a file that does not require what it
  names passes in the suite, because an earlier file required it, and fails
  alone. **The two traps fail in opposite directions and one run cannot
  catch both.** Run a file you changed on its own and in the suite.
* A test method defined after `private` never runs and nothing says so. If a
  count looks low, compare it against `grep -c 'def test_'`.

### Prove the test proves something

When you add a test for a fix, break the fix and watch the test fail.

**A sabotage that passes means the sabotage missed, or the test is weak.**
Both happen. Check which before believing the result:

* Assert on the thing you actually changed.
* Prefer deleting a line to mutating a value, because a lenient constructor
  will absorb a mutated value and the test is then right to pass.
* Be suspicious of an assertion that could pass by luck. Asking for a free
  port on one loopback address and binding it on another passes whether or
  not the code reads the argument, because the two are almost always free
  together. Find the assertion that cannot pass by accident.

## Documentation

Write a guide for anything intricate: the PDU header, the TLV framing, the
ID length threading, the checksum span.

**Then assert its load-bearing claims with a test**, and make the test
**discover** rather than compare against a list. A guide that lists the TLVs
goes stale the day someone adds one. A guide whose test reads the registry
out of the library and cross-checks the document in both directions cannot:
a new TLV class fails the suite until the document mentions it.

Prove that guard works by sabotaging it in both directions. A table test
that passes when the table is empty is not a guard.

## Where to start

Four phases, each with gates. **Every gate ends with a working behaviour
shown against an independent implementation before the next layer goes
on**, except the first, which is offline by design. Two isis4r speakers
agreeing proves only that they agree: bgp4r had a capability field
inverted for years because both ends made the same mistake and cancelled
it out.

Record status here as it moves, because a plan that lives only in a chat
is lost when the chat is.

**Status by gate, measured 2026-11-21.** Update this table in the pull
request that moves a gate. The paragraph after it has the detail.

| Phase | Gate | Status |
| --- | --- | --- |
| 1, minimal speaker | 1 offline | Done |
| | 2 hellos | Done, FRR 8.4.4 and 10.5.1, 2026-10-31 |
| | 3 LSP and SNP exchange | Done, FRR 8.4.4, 2026-11-01 |
| 2, basic router | 1 LAN | Done, FRR 8.4.4, 2026-11-01 |
| | 2 two levels | Done, FRR 8.4.4, 2026-11-01 |
| | 3 routes computed | Done, FRR 8.4.4, 2026-11-01 |
| | 4 routes installed | Done, FRR 8.4.4, 2026-11-01 |
| 3, enhanced router | 1 policy | Done, FRR 8.4.4, 2026-11-02 |
| | 2 failure handling (BFD, RFC 8706) | BFD built, FRR 10.2.1 then 10.7.1, 2026-11-21; RFC 8706 not started |
| | 3 topologies and TE | Not started; TLV 22 sub-TLVs 6 and 8 only, 2026-11-15 |
| 4, modern platform | SR-MPLS, SRv6, Flex-Algo, fast reroute | SR-MPLS designed and approved 2026-11-16 (`docs/design/sr-mpls.md`); its codec built 2026-11-16 (PR 1 of 5), against an FRR 10.2.1 LSP; origination built the same day (PR 2), FRR 10.2.1 reading isis4r's SRGB, Prefix-SID and Adj-SIDs; the label table and its API too (PR 3), agreeing with FRR's on a four-router line; and forwarding (PR 4), traffic crossing FRR and isis4r on labels in `routescope/labs/isis4r-sr`. And the simulator (PR 5): a simulated grid advertises SIDs and SRGBs, which FRR reads. SR-MPLS's five pull requests are done. The rest not started |

Not started was measured by searching `lib/` and `exe/`: nothing for
RFC 8706, multi topology, TLVs 222 or 229, or TE.

**BFD, 2026-11-21** (routescope `docs/design/bfd-clients.md`, step 6b).
`bfd: true` on an interface gives its circuits the `Bfd` mechanism, which
asks bfd4r's bfdd4r for sessions through `BFD::Client`, client name
`isisd`; `Daemon#step` polls it as it polls the API, and the image runs
`with-bfdd4r isisd`. Its hellos carry TLV 148 (`tlv/bfd_enabled.rb`,
RFC 6213 section 6) while bfdd4r answers, and `adjacency/bfd_circuit.rb`
holds RFC 6213 3.1's variables and 3.2's and 4's rules for both kinds of
circuit. Two readings where the RFCs pull apart, written there with
their mechanism: the Down in TLV 240 and the MAC left out of TLV 6 apply
only to an adjacency not yet Up, since on an Up one they drop it at the
peer by RFC 5303's table and so defeat section 4; and AdminDown counts
as usable (RFC 5882 4.1, "the adjacency MUST be allowed"). FRR does
not implement RFC 6213: 10.5.1's isisd binary has no TLV 148 code, and
10.2.1's and 10.7.1's hellos carry none (captured in the lab). So with FRR BFD is never
required: an Up adjacency on a BFD circuit still gets a session, and a
failure takes it down, reason `bfd` (RFC 5882 10.1.2). The gate,
measured 2026-11-21 on FRR 10.2.1 in `routescope/labs/isis4r-bfd` with
`test/lab/isis4r-bfd.sh`: BFD Up on both, and with 100% loss on the
link the adjacency Down on both in 0.69 to 0.92 s, reason `bfd` on
isisd, five runs in a row, each side timed from its peer's netem. Not in CI: 300 ms times 3 leaves little room under a
second. The gate also sets each end's session AdminDown, and neither
may change the adjacency (RFC 5882 4.2). The lab runs FRR 10.7.1 since
2026-11-21 (isis4r-bfd: r1 Down 0.78 to 0.93 s, f1 0.66 to 0.79 s, four
runs): 10.2.1's isisd dropped the adjacency on r1's AdminDown and sent
TLV 240 Down, and isisd followed RFC 5303's table; 10.7.1's bfdd tells
its isisd Admin Down, and it does not act. `routescope/labs/bfd-lab`,
three isis4r routers with BFD on every link and bfd4r-sim (routescope
`docs/design/bfd-lab.md`, step 8a), measures 100% loss on a link at
isisd's default 30 s hold: failover 2.5 to 2.8 s with BFD, 28.8 to
30.5 s with the sessions AdminDown (2026-11-22). Not yet: timers per interface (bfdd4r's defaults), BFD for
IPv6 against an independent router, and a second peer that sends TLV
148. The TE gate is not
met by the link addresses below: they are two of RFC 5305's sub-TLVs,
sent without traffic engineering, and no TE attribute is carried.

**Left in the core**, found in the code's own comments:

* Jitter on the LSP refresh timer, clause 10.1
  (`database/originator.rb`).
* Jitter on the hello, PSNP and CSNP timers, clause 10.1
  (`adjacency/lan_circuit.rb`, `adjacency/p2p_level.rb`).
* Hello padding: to maxsize on a LAN, clause 8.4.1
  (`adjacency/lan_circuit.rb`), and on the first point to point IIH,
  clause 8.2.3 c.
* The purge of a corrupted LSP, RFC 1142 clause 7.3.14 e. isis4r drops
  an LSP whose checksum is wrong and starts no purge
  (`database/update_process.rb`, in `receive_lsp`).
* Interface subnets are not advertised. isisd puts only its config's
  `prefixes` in its LSPs; FRR also advertises each interface's subnet.
  So in the isis4r-frr lab, r1 learns its own link subnets from f1 and
  f2 and installs them through them, metric 21 and 22. The kernel's
  connected route still wins. Measured 2026-11-14; found in the lab
  review, not in a code comment.

**Done in the core, 2026-11-14:** a database too large for one SNP.
`send_csnp` sends a complete set of CSNPs, each within
originatingLxLSPBufferSize octets, their ranges contiguous from all
zeros to all ones (RFC 1142 7.3.15.3, section 9.10), spaced by
minimumBroadcastLSPTransmissionInterval on a LAN. `send_psnp` sends what
fits and goes on next time from the next LSP (7.3.15.4). Before, one
oversized CSNP made isis4r-sim exit with `Errno::EMSGSIZE` on a 1500 octet
link; measured against FRR 10.5.1 with 326 LSPs
(`test/interop/frr_sim_test.rb`).

**Left around it:**

* The bgp-ls-export gate on the VM, the 16 grid nodes, is not verified.
* The gem has not been published.

**Done around it, 2026-11-14:** what routescope reads from isisd and
isis4r-sim is copied in `test/support/routescope_vocabulary.rb`, and
`test/unit/daemon/routescope_vocabulary_test.rb` holds the API to it, so
a change that removes or renames a key routescope reads fails here
(routescope `docs/design/api-contract.md`, part 3).

**Done around it, 2026-11-15:** `show.topology` gives each node's
`interface_addresses`, from TLV 132, and `ipv6_interface_addresses`,
from TLV 232, from every LSP of the node (`docs/isisd.md`). That was the
open question of `docs/design/bgp-ls-export.md`, which blocked BGP-LS
TLVs 259 and 260 for IS-IS in bgp4r's Producer; reading them there is
bgp4r's change.

**Done around it, 2026-11-15, later:** BGP-LS TLVs 259 and 260 come from
TLV 22 sub-TLVs 6 and 8, not from TLV 132 (RFC 9552, read by the bgp4r
session). `lib/isis/subtlv/extended_is_reachability.rb` has both, under
TLV 22 only. The originator sends them in each wide entry: on a point
to point circuit, this end's first TLV 132 address in sub-TLV 6 and the
neighbour's, from its hellos, in sub-TLV 8; toward a pseudonode, sub-TLV
6 alone, since RFC 5305 section 3.3 asks for sub-TLV 8 "on
point-to-point adjacencies". A change in the neighbour's hello
addresses regenerates the LSP. `show.topology` gives each neighbour
`interface_address` and `neighbor_address` when the entry has them.
Measured on FRR 10.5.1: without MPLS-TE it sends no sub-TLV in TLV 22;
with `mpls-te on` it sends sub-TLV 8 alone, with or without
`link-params enable` on the interface; and it shows isisd's two as
"Local" and "Remote Interface IP Address(es)"
(`test_link_addresses_both_ways`).

**Noted for later, from the owner, 2026-11-13.** Not designed yet;
routescope's `CLAUDE.md`, "Where the work is going", holds the full note.

* One CLI for IS-IS, BGP and OSPF in Cisco syntax (IOS XE is the likely
  OS, once its public command references are checked). `isis-cli` would
  join `ospf-cli` and `bgp4r-cli` behind it.
* CI runs only the jobs a change's paths need.
* Review and document every lab in `routescope/labs/`.
* A change to documents alone may have its own pull request: CI no
  longer costs money (2026-11-15, the repository is public). A small
  note may still ride with a code change on the same topic.

**History, 2026-10-31 to 2026-11-14.** The status table above is the
current state. This paragraph is the record of how each gate was met,
in the order the work was done, so "began" marks where work on a gate
started and a later sentence says when it was met. The tree follows the Layout above but
only partly fills it: `isis4r.gemspec`, `lib/isis4r.rb`,
`lib/isis/version.rb`, `lib/isis/common.rb` (errors, `SystemId` and the
ISO 8473 checksum),
`lib/isis/codepoints.rb`, `lib/isis/runtime/` with the clocks, the
scheduler and the log, `lib/isis/link/` with the LLC helpers and the socket and
simulated transports, `lib/isis/tlv/tlv.rb` with the TLV framing, the
registry, `Tlv::Unknown` and the TLV list, the first TLV classes, 1, 2, 6, 8,
9, 10, 22, 128, 129, 130, 132, 135, 137, 232, 236 and 240, with `lib/isis/tlv/narrow_metrics.rb`
for the four original metric octets TLVs 2 and 128 share and lay out
differently, with `lib/isis/subtlv/subtlv.rb` holding the
sub-TLV framing, the per parent registry, `SubTlv::Unknown` and the list
a parent frames as its layout asks, and with `AreaAddress` in `common.rb`, `lib/isis/pdu/pdu.rb` with the
common header, the type registry, `Pdu::Unknown`, `Truncated`, `Malformed`
and the computed length mechanism, `lib/isis/pdu/psnp.rb`, the first
layout, `lib/isis/pdu/lsp.rb`, the LSP for both levels with its checksum
replayed on parse and recomputed when the span moves, and the flags octet
asserted mask by mask against RFC 1142, and RFC 5304's HMAC-MD5 digest in
`Pdu::Layout` for every layout, computed before an LSP's checksum,
replayed on parse, and refused without a key once what it covers moves,
with `replay` and `preserve_authentication!` as the two ways round that, `lib/isis/pdu/csnp.rb`, the CSNP
for both levels, `lib/isis/pdu/p2p_hello.rb`, the point to point hello, `lib/isis/pdu/capture.rb`, `lib/isis/pdu/lan_hello.rb`, the LAN hello
for both levels, with `lib/isis/pdu/circuit_type.rb`, the Circuit Type field
the hellos share, and
`lib/isis/adjacency/` with `LanCircuit`, a broadcast circuit at one
level running RFC 1142 clauses 8.4.1 to 8.4.4 on the injected scheduler:
LAN hellos, adjacencies from initialising to Up when the neighbour lists
this system's LAN address, and the DIS election, with each transition and
each change of DIS logged with its reason; `lib/isis/receive/authentication.rb`,
the authentication step both circuits share;
the RFC 5303 three-way table, and `P2pCircuit`, a point to point
circuit running the handshake on the injected scheduler and logging every
transition and refusal with its reason. `P2pCircuit` also runs RFC 1142
clause 7.3.15's update process on `lib/isis/database/database.rb`, the
Level 1 database with per circuit SRM and SSN flags: a CSNP when the
adjacency comes up, PSNPs every partialSNPInterval for what SSN marks,
LSPs with SRM set sent every minimumLSPTransmissionInterval until
acknowledged, and the LSP and SNP receipt rules of 7.3.15.1 and 7.3.15.2.
`lib/isis/database/originator.rb` builds this system's Level 1 LSP from
configuration and the circuits' adjacencies, with TLVs 1, 129 and 132,
and 22 and 135, or 2 and 128, or all four, as its metric style says: generated at sequence 1 on start, again on an adjacency Up or
Down no sooner than minimumLSPGenerationInterval, refreshed every
maximumLSPGenerationInterval, and moved past a newer copy of itself, per
RFC 1142 clauses 7.3.5, 7.3.6, 7.3.16.1 and 7.3.16.2. `exe/isis-p2p-sim` runs two of them on
simulated time with `--log` and `--debug`, for watching the handshake and
its logs by hand. `ISIS::Octets` and `ISIS::Node` in `common.rb` carry the
wire mark and the constructor dispatch. `docs/building-objects.md` and
`docs/parse-policy.md` are held to the code by `test/docs/`. **Phase 1 gate
1 is met**. The header fields were read in RFC 1142 clause 9 and agree
with Wireshark and FRR, except octets 7 and 8, where the editions differ
(see the list at the end). **Gate 2 is met against FRR**, measured 2026-10-31 with FRR
8.4.4's isisd, and again on 10.5.1: `test/interop/frr_p2p_test.rb` brings the point to point
adjacency up on both sides, holds it for over three holding times without
a flap, expires it on each side when the other goes silent, and forms
none on an area mismatch. It runs in CI as `interop (FRR)`, a job the `ci`
check waits for. The LAN hello is on the contract, and replays a hello
captured from FRR 8.4.4 byte for byte. That closes gate 2's list.
`exe/isis-demo` runs two `LanCircuit`s on datalink-socket's loopback
wire with `--log` and `--debug`. **Gate 3
began**: the LSP and CSNP layouts parse, replay and rebuild an LSP and a
CSNP captured from FRR 8.4.4 byte for byte, the LSP's checksum included,
and TLV 9 reads the CSNP's entries at the PDU's ID Length. TLV 135
parses, replays and rebuilds FRR's, from an LSP FRR 8.4.4 regenerated
about 30 seconds after the adjacency came up, under its default
lsp-gen-interval of 30 s, with TLV 22 and TLV 135 in it. Its control octet's two flags are 0x80 and 0x40 by the order RFC 5305
section 4 lists them in; FRR's LSP has both clear, so no capture has
confirmed those two yet. TLV 22 parses, replays and rebuilds FRR's
from the same LSP; its neighbour ID is seven octets as RFC 5305 section 3
gives it, so it does not take the ID Length. **The
receiving half of the gate is shown against FRR 8.4.4**:
`test_isis4r_learns_and_acknowledges_frrs_lsp` has isis4r store FRR's
LSP at FRR's sequence and checksum and acknowledge it, after which FRR
stops sending it. **So is the sending half**:
`test_frr_learns_isis4rs_prefix` has FRR hold isis4r's LSP at isis4r's
sequence and checksum and install 192.0.2.1/32 through isis4r, a prefix
that exists only in isis4r's TLV 135. Measured on FRR 8.4.4, and on
10.5.1 on 2026-11-15, under FRR's default lsp-gen-interval of 30 s: FRR
holds isis4r's LSP within a second of the adjacency, but installs the
route about 30 seconds later, when it regenerates its own LSP with isis4r
in its TLV 22, since its SPF needs the link in both LSPs. The lab now
sets lsp-gen-interval 1 on FRR, and the route comes within a second of
the adjacency; that test alone keeps FRR's default
(`frr_lsp_gen_interval: nil`), so the 30 s case is still run.
`test_frr_learns_isis4rs_prefix_with_narrow_metrics` does the same with
FRR on `metric-style narrow` and isis4r sending TLVs 2 and 128, and fails
when isis4r sends wide. TLVs 2 and 128 parse, replay and rebuild FRR's,
from an LSP FRR 8.4.4 sent with `metric-style narrow`. Measured on the way: on a point to point circuit FRR
8.4.4 does not flood its own LSP when the adjacency comes up; it lists it
in a CSNP and sends it when a PSNP asks or a CSNP omits it. FRR 8.4.4's HMAC-MD5
LSP, CSNP, PSNP and point to point hello replay, and with every computed
field thrown away and the key given, isis4r writes each one again byte
for byte. `P2pCircuit` takes a `hello_key` and an `area_key`, and the
originator an `area_key`: what is sent carries TLV 10 first, and what
arrives is refused, with the clause, unless its digest checks out (RFC
1142 8.2.4.1 c, 7.3.15.1 a 3 and 7.3.15.2 a 3, and RFC 5304 section 2).
**Gate 3 is met against FRR 8.4.4**, measured 2026-11-01: with matching
keys FRR installs isis4r's prefix and isis4r stores FRR's LSP; a wrong
hello key forms no adjacency on either side; a wrong area key leaves the
adjacency up and each side without the other's LSP. Measured on the way:
FRR 8.4.4's first LSP after start can go out with no TLV 10 although its
area password is configured, and isis4r refuses that one. **Phase 2 gate
1 began**: `test/interop/frr_lan_test.rb` brings a broadcast
adjacency up with FRR 8.4.4, has both sides agree on the Level 1 DIS and
its LAN ID whichever side wins, follows a DIS change made by raising
FRR's priority with no adjacency going down, and expires FRR when it goes
silent, after which isis4r, alone, elects no DIS. Measured on the way:
FRR's first LAN hellos carry a LAN ID of zeros until its own election.
The update process now lives in `lib/isis/database/update_process.rb`,
shared by both circuits, with the broadcast variants of RFC 1142 clause
7.3.15 where it says "non-broadcast". `LanCircuit` runs it: CSNPs from the
DIS every completeSNPInterval, PSNPs from the others, LSPs one per
minimumBroadcastLSPTransmissionInterval. With an originator, its LSP names
the DIS's LAN ID (7.3.7), and while DIS it generates the pseudonode LSP
through `lib/isis/database/pseudonode.rb` (7.3.8). Measured 2026-11-01 on
FRR 8.4.4: with either side as DIS, both databases hold the same LSPs at
the same sequences, the pseudonode included, and FRR installs isis4r's
prefix. Measured on the way: FRR 8.4.4 installs that route even when
isis4r's LSP names no pseudonode, so the test asserts the TLV 22 line FRR
holds. Purges are in, RFC 1142 clause 7.3.16.4: with a scheduler the database
expires an LSP whose lifetime runs out and removes a purge's header
after ZeroAgeLifetime, or MaxAge for one this system starts; the update
process handles received purges, purges on LSP confusion (7.3.16.2) and
on an LSP with this system's ID that it does not generate (7.3.15.1 c);
and a resigning DIS purges its pseudonode, a new one its predecessor's
(7.2.3). A purge is the header alone with its checksum computed again,
which is what FRR 8.4.4 sends, byte for byte
(`test/fixtures/frr-8.4.4-l1-lsp-purge.hex`); with an area key it
carries TLV 10 (RFC 5304 section 2). A corrupted LSP is dropped and not
purged, although RFC 1142 7.3.14 e asks for a purge. **Phase 2 gate 1 is
met against FRR 8.4.4**, measured 2026-11-01:
`test_databases_agree_through_a_dis_change_to_frr` and `..._to_isis4r`
have the databases agree through a DIS change either way, the old DIS's
pseudonode a purge on both sides. **Phase 2 gate 2 began**: the
originator and the pseudonode take their level from their database, so a
`LanCircuit` at Level 2 with a Level 2 database runs the same update
process with Level 2 LSPs, IS type 3 (RFC 1142 9.9), and Level 2 SNPs.
Measured 2026-11-01 on FRR 8.4.4 with `is-type level-2-only`: the Level 2
databases agree with isis4r as DIS and through a DIS change to FRR, and
FRR installs isis4r's prefix at Level 2. **A system at both levels on a
LAN** runs a `LanCircuit` per level on one interface, each with its own
database and originator: the hellos carry circuit type 3 (`circuit_type:
:l1l2`, RFC 1142 9.5 and 9.6) and the originators IS type 3 (`is_type: 3`,
9.8). Measured 2026-11-01 against FRR 8.4.4 as `level-1-2`: an adjacency
at each level, which FRR reports as circuit type L1L2, and each level's
databases agree on their own. Measured on the way: FRR 8.4.4 forms both
adjacencies even when the hellos say circuit type 1 and 2, so the test
reads FRR's own report of the type. **A point to point circuit at both
levels** has one adjacency and a `P2pCircuit::Level` per level
(`lib/isis/adjacency/p2p_level.rb`), each with its own database,
originator and update process; the adjacency serves the levels both sides
run, or Level 2 only with no area in common (RFC 1142 8.2.4.2, whose
Tables 4 to 7 the text lost). Measured 2026-11-01 against FRR 8.4.4: both
levels on one adjacency, each level's databases agreeing; and with no area
in common, the Level 2 databases agree while neither side's Level 1 LSP
reaches the other. Measured on the way: FRR 8.4.4 lists a point to point
adjacency at both levels as one line at level 3, and lists the area
mismatched one at level 3 too. **Several LSP Numbers** (RFC 1142 7.3.4):
the originator fills LSP 0 with TLVs 1, 129 and 132 and then the
reachability TLVs in order, each LSP to its buffer size, measured by
encoding, and goes on in LSP 1, 2 and so on, each with its own sequence.
A change regenerates only the LSPs whose content changed, stores them all
before flooding any, and purges an LSP Number no longer needed. Measured
2026-11-01 against FRR 8.4.4: with a 300 octet budget and 62 prefixes,
FRR holds all four of isis4r's LSPs at isis4r's sequences and installs
the prefix only the last one carries. Measured on the way: filling in
order moves entries to a higher LSP Number when TLV 22 grows, which the
clause calls undesirable, and the test shows it. **Area addresses at Level 2** (RFC 1142 7.2.11): given the Level 1
database, a system at both levels lists in its Level 2 LSP the union of the
area addresses in the Level 1 LSPs with LSP Number 0, the lowest three if
there are more (7.1.5), and generates it again when the union moves.
Measured 2026-11-01 against FRR 8.4.4 with two nets, 49.0001 and 49.0002:
FRR holds isis4r's Level 2 LSP with both and its Level 1 LSP with 49.0001
alone. Measured on the way: FRR 8.4.4's own Level 2 LSP lists only its
manual areas, so it does not do 7.2.11. That closes the items gate 2
lists. **The lab runs a second FRR** behind the first (`frr2:` in
`FrrLab#start`, `test/interop/frr_two_routers_test.rb`), and with it
**Phase 2 gate 2 is met against FRR 8.4.4**, measured 2026-11-01: isis4r
Level 1 in 49.0001, the first FRR Level 1 and 2, the second Level 2 only
in 49.0002; isis4r's Level 1 database and the first FRR's hold the area's
two LSPs, the second FRR's Level 2 database holds the two Level 2 LSPs,
and nothing crosses either way. Measured on the way: FRR 8.4.4's Level 2
LSP carries only its own prefixes, not its area's, and its Level 1 LSP
sets the attached bit. **Phase 2 gate 3 began**:
`lib/isis/spf/spf.rb` is RFC 1142 Annex C.2's calculation for one level
and the default metric, over TLVs 22 and 2 for links and 135 and 128 for
IPv4 prefixes: equal cost paths pruned to maximumPathSplits by 7.2.7's
order, the two-way check (7.2.8.2), overload (7.2.8.1), LSP Number 0
rules (7.2.5), a pseudonode first at one distance, and RFC 5305's
maximum metrics. `lib/isis/spf/decision.rb` runs it when the database
stores an LSP or a circuit's adjacencies or DIS change, keeps the routes,
and logs each change at info; it installs nothing. Next hops carry the
neighbour's address from its hellos' TLV 132. Measured 2026-11-01 against
FRR 8.4.4: on a point to point link and on a LAN with either side as DIS,
isis4r reaches FRR's loopback at FRR's prefix metric plus its own link
metric, through FRR's address; with FRR's link metric at 30 the routes
differ each way, as 7.2.8.2 allows; and the route goes when FRR stops.
Measured on the way: FRR 8.4.4 lists the shared subnet through isis4r and
not its own copy, and `show isis route` has no json form. Fixed on the
way: a point to point adjacency leaving Up by the neighbour's TLV 240,
not by its holding timer, did not tell its levels, so the originator kept
the neighbour in TLV 22. With the second FRR, all Level 1, isis4r's routes match
the FRR in the middle: each prefix it reaches through the far FRR, isis4r
reaches at its metric plus 10 through it, and each it reaches through
isis4r, the far FRR reaches at its metric plus 10. Measured on the way:
FRR 8.4.4 lists a prefix it advertises itself through a neighbour, so
those are left out of the comparison. **Equal cost paths against FRR**:
with a second link from isis4r straight to the far FRR, at 20 on both
ends, isis4r reaches the far loopback through both FRRs at the metric the
middle FRR's table and the far FRR's LSP both give, the far FRR reaches
isis4r's prefix over both paths, and when isis4r's link goes down the
route keeps the other. Fixed on the way: an interface going down made the
socket raise ENETDOWN and stopped isis4r; `SocketTransport` now answers as
a silent link, and counts what it absorbed. **Overload against FRR**:
the originator takes `overload:`, and an `overload=` that generates LSP
Number 0 again, the only one carrying the bit (RFC 1142 7.3.19.1, 7.2.5).
In a triangle where the cheap path runs through one system, FRR routes
around an overloaded isis4r and still reaches its prefix, and isis4r
routes around an FRR with `set-overload-bit`, measured 2026-11-01 on FRR
8.4.4. Measured on the way: FRR 8.4.4 drops an `isis metric` over 63
from its startup file. **The nearest attached Level 2 system**
(7.2.9.1): the calculation finds the nearest systems whose LSP Number 0
sets the default metric's ATT bit, and at Level 1 the decision adds
0.0.0.0/0 toward them (RFC 1195 sections 1.2 and 1.3). Measured
2026-11-01 against FRR 8.4.4: with the first FRR at both levels and
attached, isis4r has a default route to it at 10; all in one area, none.
**IPv6** (RFC 5308): TLVs 232 and 236 on the object contract, with
236's control octet asserted mask by mask (U 0x80, X 0x40, S 0x20, the
rest reserved and echoed); hellos carry the link-local address in TLV
232 and LSPs the global ones; the originator sends TLV 236 in every
metric style; the calculation reads TLV 236 into the same tree, and an
IPv6 route goes through the neighbour's link-local address. The interop
test `test_ipv6_routes_both_ways` needs a kernel with IPv6, which the
sandbox it was written in lacks, so it was first run in CI; there
`ISIS_SKIP_IPV6=1` is not set and the test must pass. Fixed on the way,
2026-11-15, once FRR's LSPs came within a second: FRR 10.5.1's first
hellos carry no TLV 232, which it adds when veth0 gets its link-local
address, after the adjacency is Up, and isis4r ran SPF only on an LSP
or an adjacency change, so its IPv6 next hop had no address until FRR's
next LSP. A circuit now tells the Decision Process when an Up
neighbour's hellos change TLV 132 or 232. **isis4r sets
ATT itself** (7.2.9.2): at both levels, its Level 2 Decision Process
sets the Level 1 originator's AttachedFlag after each run, true when it
reaches a system whose LSP Number 0 lists no area address of its own
Level 2 LSP's, and the originator puts the default metric's ATT bit,
0x08, in Level 1 LSP Number 0 alone; at Level 1 an attached system adds
no default route, its nearest Level 2 system being "Self". Measured
2026-11-01 against FRR 8.4.4, isis4r at both levels in 49.0001 between a
Level 1 FRR and a Level 2 FRR in 49.0002: FRR shows ATT 1/0/0 for
isis4r's Level 1 LSP and installs a default route to it; when the link
to 49.0002 goes, ATT clears and the default route goes. **External
routes**: TLV 130 (RFC 1195 section 5.3.5) on the object contract as TLV
128's layout under its own type, with the up/down bit of RFC 5302 read
from bit 8 of the default octet in both; the calculation reads TLV 130 at
either level (RFC 5302 section 2.2) and ranks each prefix by RFC 5302
section 3's order, internal metric type before external and up/down
clear before set, then for the external type the external metric before
the internal cost (RFC 1195 section 3.4), then the distance; and the
originator takes `external_prefixes:`, sent in TLV 130 in the narrow
styles, I/E set for the external type, and in TLV 135 in the wide one.
Measured 2026-11-01 against FRR 8.4.4: FRR installs isis4r's TLV 130
prefixes through isis4r, the internal type at its metric plus 10, and
isis4r reaches FRR's redistributed connected prefix. Measured on the
way: FRR 8.4.4 never sends TLV 130, putting redistributed routes in TLV
128 at either level, so the reading of TLV 130 is held only to our
arithmetic; and it reads an external type metric of 7, 0x47, as 71, its
low seven bits. **Phase 2 gate 3 is met against FRR 8.4.4.** **Phase 2
gate 4 began**: `lib/isis/forwarding/forwarding.rb` turns each change
in a Decision Process's routes into a route operation, install, replace
or withdraw, a route this system advertises itself counting as absent,
and `lib/isis/forwarding/netlink.rb` applies them in pure Ruby: rtnetlink
over an AF_NETLINK socket, RTPROT_ISIS, one next hop or RTA_MULTIPATH,
each level at its own priority, Level 1 lower (7.2.12), and a flush of
its own routes. The runner, with `forwarding: true`, flushes at start and
on stop. Measured 2026-11-01 against FRR 8.4.4: a host behind isis4r
pings FRR's loopback on the route isis4r installed and FRR's route back
to the host's subnet, over IPv4 and, in CI, over IPv6; when FRR's isisd
stops, and when isis4r stops, none of isis4r's routes is left in its
kernel. **A link failure moves forwarding**, on the equal cost triangle
with a host behind isis4r: the kernel holds the far loopback over both
next hops; the far end of isis4r's direct link goes down, which leaves
isis4r's end up without carrier, a next hop the kernel would go on
using; when the adjacency expires isis4r replaces the route with the one
path left, the host still reaches the loopback, and no route of
isis4r's is left on that link. Measured on the way: a new namespace
starts with forwarding off and zebra leaves it so, so the lab turns it
on in the FRRs' namespaces when there is a host; and the lab needs
`ping`, from iputils-ping. **Pass-through equivalence runs in the
suite**: `test/scenario/pass_through_test.rb` runs one scenario, A and B
on a point to point link at both levels and B, C and D on a LAN at Level
1, both putting the area into Level 2, A with a summary, B leaking
its Level 2 routes into Level 1, and C redistributing host routes that
change, through an overload, a
cut and restored link and a silenced DIS, four ways: plain, with every
control installed, with logging at debug, and with both. A control is a
method replaced on the object that runs a mechanism, so
`test/support/pass_through.rb` replaces every method of every mechanism
object, the scheduler, transports, circuits, point to point levels, BFD,
databases, originators, pseudonodes, decision processes, leaks,
summaries, redistributions, the forwarding adapter and the log, with one that calls the original. The four runs
must give the same packets per circuit, sent and received in order, the
same adjacencies, databases with their SRM and SSN flags, and routes at
each half second, and the same route operations; the test also shows
every kind of mechanism ran through its control. Shown by sabotage: a
debug line with a side effect, a control that sends one extra hello, one
that shifts a timer by a millisecond, and one that withdraws and
reinstalls routes that end the same each fail it. **Phase 2 gate 4 is
met against FRR 8.4.4**, measured 2026-11-01, with IPv6 traffic shown in
CI. **Phase 2 is complete.** **Phase 3 gate 1 began, with route
leaking** (RFC 5302 section 2): `lib/isis/spf/leak.rb` is a mechanism
object that, after each Level 2 run of a system at both levels, chooses
the Level 2 routes its policy allows, none by default (section 4: "it is
RECOMMENDED that L2 routes not be advertised into L1 by default"), and
hands them to the Level 1 originator, which sends them with the up/down
bit set: TLV 128, or 130 for the external type, at most 63, when narrow;
TLV 135 when wide; TLV 236 for IPv6. A new policy chooses again at once
from the last routes. The runner reads `leak:`, and a control file a
test writes while it runs (`FrrLab#isis4r_control`). Measured 2026-11-02
against FRR 8.4.4, isis4r at both levels between a Level 1 FRR and a
Level 2 FRR in 49.0002: with the policy changed to leak 198.51.100.0/24,
FRR holds the far loopback in isis4r's Level 1 LSP marked "Down" and
installs it at 30 through isis4r; changed back to nothing, FRR drops both
the advertisement and the route. **The area into Level 2, and
summarization** (RFC 1195 section 3.2): `lib/isis/spf/summary.rb`, after
each Level 1 run at both levels, hands the Level 2 originator the
area's prefixes at their Level 1 route metrics, 63 at most when narrow,
the external type in TLV 130, leaving out routes with the up/down bit
(RFC 5302 section 4), this system's own and the default route; each
configured summary, { prefix:, metric: }, goes in place of what it
covers when it covers at least one reachable address, at its configured
metric or, with none, the lowest it covers, which is our choice. New
summaries choose again at once. The runner reads `summaries:` from its
config and its control file. Measured 2026-11-02 against FRR 8.4.4: the
Level 2 FRR in 49.0002 reaches the Level 1 FRR's loopback only through
isis4r's Level 2 LSP, at 30; a summary of 198.51.100.0/24 at 15 replaces
it at 25 and the /32 is withdrawn; taken away, the /32 comes back and
the /24 goes. **Redistribution through adapters**:
`lib/isis/database/redistribution.rb` is a mechanism object that reads
the host's routes from a source, `Forwarding::Netlink#routes` on Linux,
at start, every interval on the scheduler and at once when its kinds
change, and makes those of the kinds it takes, `:connected` (protocol
kernel, not IPv6 link-local) and `:static` (protocol boot or static),
from the main table, unicast or blackhole, the originator's external
prefixes, which `external_prefixes=` now generates again; an IPv6 one
goes in TLV 236 with X set (RFC 5308 section 2). Nothing is taken by
default. The runner reads `redistribute:` from its config and its
control file. Measured 2026-11-02 against FRR 8.4.4: a blackhole route
added in isis4r's namespace reaches FRR at its metric plus 10; deleted,
FRR withdraws it; added again and then no longer redistributed by a
policy change, FRR withdraws it again. **Phase 3 gate 1 is met against
FRR 8.4.4**: a change of leak, summary or redistribution policy each
withdraws the obsolete advertisement and route at FRR. **routescope
integration began**, in the order below: first, the originator takes
`hostname:` and sends it in TLV 137 in LSP 0 (RFC 5301 section 3), since
routescope's map finds an IS-IS neighbour by its hostname. Measured
2026-11-02 against FRR 8.4.4: FRR lists isis4r by that name in `show isis
hostname` and `show isis neighbor`. A purge carries no TLV 137, so the
database keeps the name its LSP had until the header goes, and isisd
lists the purge by it, as FRR 8.4.4 does; RFC 5301 section 4 leaves how
long a mapping lasts open. Then `lib/isis/router.rb`: an
`ISIS::Router` builds a whole system from one configuration, the
databases, originators and Decision Processes per level, a circuit per
interface, a LAN circuit per level on a broadcast one, and the leak and
summary at both levels; `Router::Host` gives it the Linux links, netlink
and the route source. The interop runner now runs through it, and the
interop suite passes unchanged. Then `exe/isisd`, `lib/isis/daemon.rb`:
a Router from a YAML file on the real clock, with `-l` and `-d`, and its
management API (`lib/isis/daemon/api.rb`), JSON lines over a Unix socket
in ospfd's shape, served from the router's own loop and thread, so a
request is answered between two turns of the protocol: what it shows
(`daemon/views.rb`), policy changes, and an event stream. `exe/isis-cli`
asks it. `docs/isisd.md` lists every method, held to the API by
`test/docs/isisd_test.rb`. Measured 2026-11-02 against FRR 8.4.4
(`test/interop/frr_isisd_test.rb`): isisd from its file brings the
adjacency up, names FRR by its hostname, and shows FRR's LSP at FRR's
sequence and the route to FRR's loopback. Measured on the way: YAML
reads an area 49.0010 as the number 49.001, so isisd reads the areas as
the file wrote them. routescope reads isisd through this API. A
`Dockerfile` builds the isis4r image, its unit tests run in it, and
`routescope/labs/isis4r-frr` puts isis4r between a Level 1 FRR and
a Level 2 FRR. `test/lab/isis4r-frr.sh` runs that lab's own files and
checks the routing through isis4r, in containerlab (the CI job `lab
(containerlab)`) or in network namespaces with no Docker. Measured
2026-11-02 in namespaces, on FRR 8.4.4: both adjacencies up, f1's default
route through isis4r, f2's route to f1's loopback through it, and f1
pinging f2's loopback. The image is built only in CI, since this
sandbox reaches no container registry; there, measured 2026-11-02, it
builds, 760 tests pass in it, and the lab passes every check under
containerlab with FRR 10.2.1. **The simulator began**, after
ospfv2's (`docs/simulator.md`): `lib/isis/sim/topology.rb` reads the
simulated area's file, the simulator's own isisd settings, a grid, more
systems, prefix groups expanded by count, and links carried at the levels
both ends run, and reports every problem in it at once, with where it is.
It refuses what cannot go in an LSP and keeps what is odd but sendable.
`lib/isis/config_file.rb` reads every YAML file, isisd's included, with
each list under `areas` as written. `lib/isis/sim/simulator.rb` runs a
topology: the simulator's own system is an ordinary Router, and each
simulated system an ordinary Originator writing into its databases, with
a link as an entry in each end's IS reachability. A database now keeps
generators besides its circuits' own, so the update process treats a
simulated LSP as this system's: a newer copy generated past (7.3.16.1), a
neighbour's purge answered (7.3.16.4 c), except after a flush or with
aging off. The originator takes `lifetime:` for the simulator's short
lifetimes. The actions, link down, up, flap and metric, overload,
attached, prefix groups withdrawn and advertised, refresh, flush,
restore, aging and the simulator's hellos, are tested on simulated time
against a Router. Measured 2026-11-02 against FRR 8.4.4
(`test/interop/frr_sim_test.rb`): through one adjacency with the
simulator, FRR holds all eight LSPs of a 2x3 grid, names each system by
its hostname, and reaches the far corner at 50. Measured on the way: FRR
8.4.4 routes over a link only one end lists, so it does not apply the
two-way check of 7.2.8.2 there, which isis4r's SPF does. `exe/isis4r-sim`
runs a topology file as a daemon: `ISIS::Daemon` given a topology builds
the simulator, whose Router answers isisd's API, and the API answers the
`sim.*` methods too, one per action (`docs/simulator.md`), which
`isis-cli sim ACTION KEY=VALUE` calls. Measured 2026-11-02 against FRR
8.4.4 (`test_frr_follows_the_actions`): through the API, a metric change,
two links down, an overload, a withdrawn group, a flush and a restore
each reach FRR's routes. `sim.state` also says which interfaces send
hellos, each system's prefix groups, each link's number and the metric
style, which routescope's simulated area panel reads; `neighbor.start` on
a circuit already sending leaves it alone, where it used to start a
second hello timer. routescope's IS-IS scenario conditions and its sim
actions for isis4r-sim are built (routescope #35 and #36). Not yet in
the originator: jitter on the refresh timer (clause 10.1). Not yet in the update process: PSNP jitter. A database too large
for one CSNP or PSNP is sent as a set (2026-11-14). Not yet done in the hellos: the padding RFC 1142 clause
8.2.3 c asks for on the first IIH, and hello timer jitter. The gem has not been
published. It is licensed as bgp4r is, GPLv3 or later, or the conditions in
`LICENSE.txt`. Update this paragraph when that changes.

### Phase 1, minimal speaker

Router: one L1 point to point adjacency, local advertisements, database
synchronization. Testing: exact replay, narrow and wide codecs,
authentication, the injected clock, scripted packet exchange.

1. **Offline.** The common header, the TLV framing, the three Unknowns and
   the parse policy, with the truncation tests. A captured PDU of an
   implemented type parses into its layout and re-encodes byte for byte; a
   PDU of an unimplemented type comes back opaque and re-encodes byte for
   byte. The clock, the scheduler and the simulated transport exist, and
   the source scan guard passes. No network.
2. **Hellos.** The point to point hello and the RFC 5303 three way
   handshake. TLVs 1, 8, 129, 132 and 240. The existing LAN hello moves
   onto the object contract. Gate: an independent router brings the
   adjacency up and holds it, and losing the neighbour expires it.
3. **LSP and SNP exchange.** The LSP with its checksum, sequence number,
   lifetime and flags. TLVs 2, 22, 128 and 135, so narrow and wide both;
   TLV 9 in CSNPs and PSNPs; TLV 10 with the RFC 5304 fixup. Repeated TLVs
   follow RFC 9885: accept every part, and never split a sub-TLV across
   parts when packing. The default receive policy for LSPs. Gate: the
   independent router learns the advertised IPv4 prefix, a missing LSP is
   requested and received ones acknowledged, and authentication succeeds
   and fails as configured.

### Phase 2, basic router

Router: LAN adjacency and DIS, L1 and L2, IPv4 and IPv6 SPF, ECMP, route
installation and withdrawal. Testing: override individual protocol
actions; inject loss, delay, duplicates, malformed PDUs and topology
changes.

1. **LAN.** LAN hellos at both levels, DIS election and replacement,
   pseudonode LSPs. Gate: adjacency and database agreement with an
   independent router on a broadcast LAN, through a DIS change.
2. **Two levels.** Separate L1 and L2 databases, L1/L2 operation,
   flooding, refresh, aging, purge, several LSP Numbers. Gate: databases
   agree with independent routers across an L1 area and the L2 backbone,
   and the level boundaries hold.
3. **Routes computed, not installed.** SPF, next hops, ECMP, IPv4 and IPv6
   (TLVs 232 and 236), overload and attached handling. Gate: computed
   routes match the independent router's on the same topology.
4. **Routes installed.** The first forwarding adapter, and pass-through
   equivalence running in the suite. Gate: hosts exchange IPv4 and IPv6
   traffic through isis4r, and a link failure changes forwarding with no
   stale entries left.

### Phase 3, enhanced router

Router: policy, multi topology, TE information, BFD integration, restart
support. Testing: scripted transitions and failures, state inspection,
comparison against expected routes and peer behaviour, reproducible
scenarios.

1. **Policy.** Leaking, summarization, redistribution through adapters.
   Gate: a policy change withdraws obsolete advertisements and routes at
   the independent peer.
2. **Failure handling.** BFD feeding adjacency and SPF, and restart
   signalling per RFC 8706. Gate: restart tests tell retained forwarding
   from lost forwarding.
3. **Topologies and TE.** Multi topology and TE attributes. Gate: different
   topologies give the intended different paths, and TE attributes survive
   origination, flooding and decoding at the peer.

### Phase 4, modern router platform

Selected capabilities, each its own gate: SR-MPLS (RFC 8667), SRv6 (RFC
9352), Flex-Algo (RFC 9350), fast reroute, advanced convergence. A
capability is done when it shows correct encoding, correct state and
calculation, correct forwarding where that applies, and interoperation
with an independent implementation. Advertising an SRv6 locator alone is
not SRv6 support. Experimental mechanisms, such as fast flooding in RFC
9681, stay out of the default profile.

Fast reroute is TI-LFA (RFC 9855), specified in routescope's
`docs/design/ti-lfa.md` (approved 2026-11-21). Its step 0 builds the
conventions it stands on, one pull request each: SR findings and receive
policies in `validation.rb` (0a, #97), the `ISIS::Fault` catalog (0b,
#100), the label stack codec and the `to_hash` catalog (0c, #101),
`isis4r-sim`'s HTTP API with `/api/fault` (0d, #102), and
`test/integration` renamed `test/interop`, the conventions' name for the
tier (0e, #103). Step 1, the computation (`Spf::Graph`, `Spf::TiLfa`,
`docs/ti-lfa.md`), for a link and for a node (#104). Step 2a: isisd
computes and shows the backups, `ti_lfa: link` per point-to-point
interface (`Spf::Backups`, `show.ti_lfa`, #107). Step 2b: the IP
backups in the kernel at the route's priority plus 100, and
`ignore_routes_with_linkdown`, so carrier loss switches them with no
daemon (`test/interop/kernel_backup_test.rb`). Step 2c, the switch on a
failure carrier does not show, is measured first. Step 3:
`ti_lfa: node`, node protection with link fallback. Step 5b:
`policy.ti_lfa`, the mode changed while isisd runs.

Testing: unusual extension combinations, compatibility and scale, and
experimental mechanisms exercised on request. "Up to date" is a maintained
compatibility statement, not a promise to implement every extension.

## Labs and interop

The gates above need an independent router. The plan is to follow what the
sibling projects already do, and not to invent a third way. Surveyed
2026-10-31 at ospfv2 `0ec77c6` and routescope `265156a`. **Both tiers are
built**: the namespace harness, and routescope's drivers `Isis4r` and
`Isis4rSim`, measured 2026-11-15 at routescope `327d6fd`. Record
decisions here as they are made.

**Two tiers, and they do different jobs.**

1. **A namespace harness, for the gate tests.** ospfv2 has
   `test/support/frr_lab.rb`: two network namespaces joined by a veth
   pair, FRR run natively in one, the implementation in the other. It
   needs root, iproute2 and FRR, runs only when `OSPFV2_FRR=1` is set, and
   runs on GitHub runners with FRR installed from apt (the `interop-frr`
   job in ospfv2's `ci.yml`). isis4r copies the pattern with `isisd` in
   place of `ospfd`, gated by `ISIS_FRR=1`, under `test/interop/`. So a
   gate is shown in CI against FRR, and the same test runs on a Linux VM
   by hand. **Built**: `test/support/frr_lab.rb` sets up the namespaces and
   FRR, and `test/support/isis_runner.rb` runs isis4r inside its
   namespace on the real clock, writing its state as JSON and its log at
   debug with a PDU trace, and reading a control file a test writes to
   change policy while it runs. A failing test prints both sides' logs.
   `sudo env "PATH=$PATH" ISIS_FRR=1 rake interop` runs them, each file
   in a process of its own, `ISIS_INTEROP_JOBS` at a time (all by
   default). Newer sudo ignores `-E` with a warning, and `env` passes
   what the tests need. **The lab sets FRR's `lsp-gen-interval` to 1 s**,
   as isis4r's `minimum_lsp_interval` is there. FRR's default is 30 s
   (`frr-isisd.yang`, 10.5.1), under which FRR names a new neighbour in
   its LSP up to 30 s after the adjacency, and most tests waited for
   that. The line goes before `net`: FRR schedules its first LSP when it
   reads `net`, at the interval it has then. `frr_lsp_gen_interval: nil`
   keeps FRR's default, which `test_frr_learns_isis4rs_prefix` does.
   Measured 2026-11-15 on FRR 10.5.1, one machine, per file before and
   after: isisd 32 to 4 s, LAN 232 to 59 s, point to point 535 to 187
   s, simulator 106 to 63 s, two routers 349 to 84 s; the suite 1253 s
   one file after another before, 187 s five at a time after.

2. **routescope, for labs a person watches and drives.** routescope does
   not build labs. It is a web console over labs that docker compose or
   containerlab bring up, reached by `docker exec`, with one driver per
   node kind, scenarios with `expect:` conditions, capture, and link
   down, up, delay and loss on containerlab links. A lab is a folder with
   `lab.yml` or `NAME.clab.yml` and one config per node.

**Four harness facts about isisd**, measured 2026-10-31. The first three
on FRR 8.4.4 and 10.5.1, the fourth on an Ubuntu VM with FRR 10.5.1:

* **isisd drops to `frr:frr` before it writes its pid file**, so it
  cannot write into a run directory the harness made as root. It exits
  with `Can't create pid lock file ... (Permission denied)`. Running under
  sudo does not help, because the daemon drops privileges itself. The
  harness creates the directory because it writes the configs beside it,
  so it chowns the run, config and log directories to `frr`. Left
  uncreated, isisd would make the directory itself, owned by `frr`.
* **isisd has no `-S`.** bgp4r's harness keeps `bgpd` as root with
  `-S, --skip_runas`. isisd rejects it: `invalid option -- 'S'`. So that
  trick does not transfer.
* **`-u root -g root` fails too**, with `privs_init: user(root) is not
  part of vty group specified(frrvty)`. The chown is the way.
* **AppArmor confines isisd on newer Ubuntu**, and gives the same pid file
  error with the chown in place, plus `failed to mkdir
  "/var/lib/frr/<name>"`. Ubuntu's `apparmor` package ships
  `/etc/apparmor.d/isisd` (26.04 does, 24.04 does not). CI's
  `ubuntu-latest` became 26.04 between 6 and 9 November 2026, so the
  `interop (FRR)` job unloads the profile before the tests; the runner
  is thrown away after the job.
  It allows only FRR's default paths, `/run/frr/isisd.pid`,
  `/etc/frr/isisd.conf` and `/var/log/frr/`, and the lab uses
  `/run/frr/<name>/`, `/etc/frr/<name>/` and a temporary directory. zebra
  has no profile, so zebra starts and isisd does not. Check and fix:

  ```sh
  sudo grep isisd /sys/kernel/security/apparmor/profiles   # isisd (enforce)
  sudo apparmor_parser -R /etc/apparmor.d/isisd            # unload until reboot
  sudo apparmor_parser -r /etc/apparmor.d/isisd            # load it again
  ```

  Unloading lifts the confinement for isisd only, and only until the next
  reboot or AppArmor reload. The harness does not do it for you, since a
  test should not change a host's security settings. It detects the
  profile instead: `FrrLab.available?` refuses with that command in the
  message. With the profile unloaded, all five tests pass on 10.5.1.

When a daemon will not start, the harness raises with the daemon's own
output, which is where these messages appear. With `ISIS_FRR=1` set, a lab
that cannot run fails the tests rather than skipping them, because a skip
shows its reason only under `-v` and a CI job of skips is green.

**A second independent implementation: Nokia SR Linux**, decided
2026-11-15. With FRR alone, a reading isis4r and FRR share passes every
gate, which is the bgp4r failure the gates exist to prevent. Candidates,
measured that day on a 6 core arm64 VM with containerlab 0.83:

| | SR Linux 26.7.2 | Holo v0.9.0 |
| --- | --- | --- |
| IS-IS | p2p, LAN, L1/L2, wide and narrow (`metric-style`), HMAC-MD5, IPv4 and IPv6, from its YANG | the same, from its source (`MetricType` standard, wide, both; TLVs 132, 232, 236; RFC 5304) |
| p2p with isis4r | adjacency, each LSP at the originator's sequence and checksum, each prefix installed: the gate test passes | the same, by hand |
| Licence | proprietary, free image, no licence needed for this | MIT |
| Images | `ghcr.io/nokia/srlinux`, amd64 and arm64, versioned tags; 3.14 GB, pulled in 30 s | `holod` and `holo-bundle` amd64 only, versioned only at v0.8.0; holo-cli untagged since v0.5.0, and its master no longer speaks v0.9.0's gRPC; built here in 215 s plus 76 s |
| Start | 25 s for `containerlab deploy` to a node that takes config | 0.8 s to holo-cli answering |
| State | `sr_cli -d "... \| as json"`; `show` tables keep their column headings as keys | ietf-isis YANG as JSON through holo-cli or gNMI, with each LSP's raw octets |

**Why SR Linux.** Holo's leading contributor (1076 commits) has at
least 100 commits in FRR's `isisd`, 2018 to 2023 (GitHub API), so Holo is
a second codebase but not clearly a second reading of the specification,
and a second reading is the point. SR Linux shares no code or authors
with either that we know of, runs from one pinned image on the CI's
amd64 and on arm64, and routescope already has its node kind. What it
costs: 25 s per lab, 3 GB, and docker with containerlab. Holo stays the
choice for a third, or for a lab that needs many routers fast; its raw
LSP octets in state would let a test compare bytes.

`test/support/srl_lab.rb` deploys one SR Linux node with containerlab,
its `ethernet-1/1` joined to a host end that the lab moves into isis4r's
namespace as `veth0`, commits its configuration with `sr_cli`, and runs
isis4r as FrrLab does. `test/interop/srl_p2p_test.rb` is one test,
since the lab takes most of the time: the adjacency up on both sides,
each LSP held at the originator's sequence and checksum, and each side's
prefix installed through the other. `sudo env "PATH=$PATH" ISIS_SRL=1
rake interop_srl` runs it, and CI's `interop (SR Linux)` job; `rake
interop` now runs the `frr_*` files only.

**What routescope needed to show an isis4r lab**, from its
`docs/protocols.md` and code. Every one was an additive change in
routescope, which its own rules require (`ospfv2/docs/console-plan.md`).
All five are there, measured 2026-11-15 at routescope `327d6fd`: `isis4r`
and `isis4r-sim` in `Lab::KINDS`, the drivers `Isis4r` and `Isis4rSim`
reading isisd's API, IS-IS tables and events from FRR's isisd, and an
`isis` capture profile on the `isis4r-capture` image (`exe/isis-capture`).

* a node kind for isis4r in `Lab::KINDS`, and a driver in `drivers.rb`
  that reads isis4r's state, which means isis4r needs a state API to read;
* IS-IS commands and parsers in the FRR driver, for `isisd`;
* a definition of a node being up for IS-IS, which today means an OSPF
  neighbour or a BGP session;
* IS-IS scenario conditions: adjacency, LSDB, routes;
* a capture that is not OSPF's. It runs `ospfv2 capture`, filtered on IP
  protocol 89 with an OSPF dissector, and IS-IS is not IP at all. It needs
  an LLC filter and an isis4r dissector.

**IS-IS is not IP, and the labs have to allow for it.** It runs directly
over the link layer with LLC framing. A veth pair or a containerlab link
carries raw Ethernet, so the transport works there (measured: the
harness runs over one). The real transport opens a raw socket through datalink-socket, so
an isis4r node needs root or `CAP_NET_RAW` in its namespace or container.
Anything in a lab that assumes an IP address on the link for the protocol
to work is OSPF's assumption, not ours.

**Order.** The namespace harness came with phase 1 gate 2, because that
gate needs FRR. routescope support came later, once there was state worth
looking at, in routescope's repository.

## Rules for agents

* Work on a branch named `claude/<short-topic>`. Never push to master.
* One topic per pull request. Small diffs.
* Run the full unit suite before opening a pull request. CI runs it again
  on every supported Ruby, in `.github/workflows/ci.yml`, and the one check
  a merge waits for is `ci`. It passes only when every matrix job passed.
  Add a Ruby version to the matrix, not to the branch rules.
* New behaviour needs a test. A fix needs a test that failed before it.
* If you find a bug you are not fixing, say so in the pull request.
* **Work out what the code was built to do before concluding it is wrong.**
  A shape that looks odd is more often a decision whose reason was never
  written down than a defect. Say "I do not know why this is like this"
  rather than "this is wrong" until you have answered the first.
* **A decision not to do something has to record the mechanism, not the
  verdict.** "Cannot be done readably" is a conclusion. What a later reader
  needs is the premise it came from and the bar it was measured against,
  because the conclusion is the half that turns out to be wrong.
* **Measure rather than recall.** Counts, timings, what a router does, what
  a registry says. If a command can print it, do not write it in prose. If
  prose must carry it, say when it was measured.
* Keep this file true in the pull request that makes it false. A stale entry
  is worse than no entry, because it sends the next reader after work that
  no longer exists.

## Decisions

Architecture decisions, dated, with the premise each came from. Unlike the
Corrections below, nothing here was a mistake. These are choices, and a
later decision may change one.

**2026-10-31. Scope: a programmable router with testing controls.**

* Before: isis4r was scoped as "a protocol testing tool before it is a
  protocol implementation". That was deliberate, and it is why the codec
  rules in this file are permissive.
* Now: router functionality and testing control are both core
  requirements.
* Premise: a router that keeps every mechanism controllable is a stronger
  test platform than a packet tool, because a test can run real routing on
  some circuits while manipulating others.
* Consequence: the codec rules stand unchanged. Added: no global test
  switch, correct originators, receive policy separate from validation, an
  injected clock and scheduler, pass-through equivalence, and a forwarding
  boundary. All under "Autonomous operation and testing controls".

**2026-10-31. Logging is a requirement.**

* Before: logging was not mentioned.
* Now: every mechanism logs through an injected logger, and keeps events
  a test can read. See "Logging and events".
* Premise: a protocol test that fails on a real router is debugged from
  its log. Without a reason in the log, the only way to find out is to
  rerun it under a debugger, which is not possible against FRR on a VM.

**2026-10-31. License: the same terms as bgp4r, for now.**

* GPLv3 or later, or the conditions in `LICENSE.txt`, at the user's
  choice. The gemspec declares `GPL-3.0-or-later` and `Ruby`.
* Premise: consistency with bgp4r while the commercial model is
  undecided. Loosening the license later is easy; tightening it only
  affects versions released afterwards.
* Consequence: keeping a commercial dual license open needs the right to
  relicense every contribution. Decide on a contributor agreement before
  accepting outside code.

**2026-11-01. Forwarding adapters: no native dependency; netlink in pure
Ruby.**

* Before: open. Against a native dependency: "pure Ruby" is part of what
  the library is, and a native extension changes how it installs and
  where it runs. For one: route programming is netlink on Linux and a
  routing socket on BSD, both possible in pure Ruby and both large.
* Now, decided by the owner: the Linux adapter, for Phase 2 gate 4,
  opens an AF_NETLINK socket through Ruby's `Socket` and packs the
  rtnetlink messages (RTM_NEWROUTE, RTM_DELROUTE) in Ruby. No adapter
  uses a native extension, FFI or an external binary. An iproute2
  adapter was chosen first and dropped the same day, before any code,
  in favour of going straight to netlink.
* Premise: netlink in pure Ruby keeps the whole library native-free and
  needs no `ip` binary or process per operation. It is larger than
  shelling out, but it is the lasting answer, so it is written once.
* Consequence: the adapter takes route operations (install, replace,
  withdraw) and nothing netlink specific, so a BSD routing socket
  adapter can sit behind the same interface later.

**2026-11-21. bfd4r, as datalink-socket; Ruby 3.2.**

* The owner's decision (routescope `docs/design/bfd-clients.md`): the
  gemspec depends on `bfd4r`, the Gemfile takes it by path,
  `../bfd4r`, the Dockerfile as a build context (`--build-context
  bfd4r=../bfd4r`), and CI checks it out beside isis.
* bfd4r required Ruby 3.3, and bundler refused it on 3.2. The owner's
  decision: bfd4r comes down to 3.2 (bfd4r #10), and isis drops 3.1.
  Premise, measured in the ruby images: bfd4r's unit tests pass 228 of
  228 on 3.2, and error on 3.1, where `Thread::Queue#pop(timeout:)` does
  not exist.

## Corrections

Every rule above is the rule as it stands. This is what was believed first,
collected here so the rules read as rules. It is kept because a correction
without its mechanism gets re-litigated, and moved out of the rules because
twenty two of them inline buried the contract.

| Believed first | Actually | Rule now in |
|---|---|---|
| An LSA is a leaf, an LSP is a container | Both are containers; the missing layer is OSPF's Link State Update. **For containment only**, LSA maps to TLV; identity, sequencing, aging and flooding map LSA to LSP | OSPF analogy |
| ATT is one bit | Four, one per metric type | LSP flags octet |
| OR-ing masks to `0xff` proves no overlap | OR is idempotent; needs union **and** pairwise AND, and neither proves the mapping | LSP flags octet |
| A test setting only the default ATT bit misses a reversal | It catches it; the **round trip** is what misses it | LSP flags octet |
| The narrow metric is one octet with a value, an I/E bit and an S bit | Four octets in two layouts, and S set means **not** supported | Narrow and wide metrics |
| In those four, delay, expense and error carry an S bit and a reserved bit | In TLV 2, RFC 1142 gives all four an I/E bit. In TLV 128, RFC 1195 gives only the default one an I/E bit, and bit 7 of the others is reserved | Narrow and wide metrics |
| Invalidation follows size changes | It follows content changes at any depth; compare retained normalized bytes | How an edit invalidates |
| One coverage span | Two, and they are **ordered**: digest, then checksum | One retained input per calculation |
| A common header edit leaves the checksum | Only unauthenticated; otherwise it reaches the checksum through the digest | same |
| ID Length scales TLV 6's entries | TLV 6 carries LAN addresses; TLV 2 is the System ID one | Parse-time inputs |
| Declared length over the capture is the truncated-header case | Four distinct cases | Parse rule 6 |
| A PDU replays its declared length | Its **consumed slice**, which need not match | Parse rule 7 |
| The link MTU is the LSP budget | Configured receive capacity and circuit MTUs; 1492 is a default, not a ceiling | Packing |
| TLV 14 advertises receive capacity | It advertises the **originating** size | Packing |
| The builder predicts sizes arithmetically | It encodes once and measures | Packing |
| Checksum and Remaining Lifetime are zeroed for the digest because both mutate in transit | Only the lifetime does; the checksum is a circular dependency | Authentication, step 3 |
| The singleton override can keep a stale digest | It calls `super`, which raises first; use `replay` or `preserve_authentication!` | Authenticated edit without a key |
| All authentication prepares its value by zeroing | Algorithm dependent, and only the Authentication Value, not the TLV | Authentication |
| An unknown PDU can be framed into `Tlv::Unknown`s | Opaque; nothing establishes its body is TLVs | Keep what you cannot read |
| `to_s` must feed `new` for every class | Identifier and address classes only | Five ways out |
| The Area Addresses TLV for 49.0001 is `010449010001` | `010403490001`; the per-area length octet | Hex is canonical |
| RFC 5120 and RFC 9681 were cited for the wrong thing | Both citations were correct; they were judged by title, not read | Codepoints |
| A hash may carry a computed field when parsing found an unusual one | That is a `checksum:` option by another name; computed fields stay out of the hash and are replayed from octets | Computed fields |
| `value.size` for a length field | `bytesize`, and `String#<<` expansion is encoding dependent | The idiom |

**Three kinds, and knowing them is worth more than the list.** Almost every
row is one of:

1. **A field read narrower than it is.** ATT, the narrow metric octets,
   `size` against `bytesize`. The summary everybody repeats is the singular
   one, and the encoder written from the summary is wrong by a nibble.
2. **A universal rule written before its exceptions were known.** One
   coverage span, `to_s` reversibility, replay equals declared length, size
   based invalidation. Each read as clean doctrine and each had a case it
   could not express.
3. **A check that validates structure mistaken for one that validates
   meaning.** The tiling check, and both misjudged citations. Structure is
   cheap to check and it is never the question.

A new rule in this file is worth one pass against those three before it is
written down as settled.

## Things to verify before writing them down

Written from memory while planning, so each is a lead and not a fact. Check
each against the document and replace this list with what you found.

**Read in RFC 1142, 2026-10-31.** The user supplied the text, so clause 9
and clause 7.3 were read first hand, and checked against Wireshark
(`epan/dissectors/packet-isis.c`, `packet-isis.h`, `packet-isis-hello.c`)
and FRR (`isisd/isis_pdu.c`, `isis_pdu.h`). RFC 1142 is the 1990
republication, so each of these is confirmed for that text and not for the
2002 edition:

* **ID Length**, clause 9.5: 1 to 8 is the length, 0 means six octets, 255
  means a null ID, "All other values are illegal". Wireshark agrees; FRR
  accepts only 0 and 6. Used in `Pdu.id_width`.
* **PDU type** in bits 1 to 5, bits 6 to 8 reserved, and the numbers 15,
  16, 17, 18, 20, 24, 25, 26 and 27, one per clause from 9.5 to 9.13.
* **Length Indicator** is "Length of the fixed header in octets", in every
  PDU clause. **PDU Length** is "Entire Length of this PDU, in octets,
  including header". FRR's fixed header sizes, 8 plus 19, 12, 19, 25 and 9
  for six octet IDs, match the clause figures.
* **Circuit Type**, clause 9.5: low two bits, six reserved; 0 is a
  reserved value and "the entire PDU shall be ignored", 1 is Level 1 only,
  2 Level 2 only, 3 both. The same field in the point to point hello,
  clause 9.7. **Priority**: bits 1 to 7, bit 8 reserved.
* **Point to point hello fixed header**, clause 9.7: Circuit Type, Source
  ID, Holding Time, PDU Length, Local Circuit ID, in the order of the
  clause's field descriptions. The figure in the supplied text was
  flattened by extraction and cannot settle the order alone. FRR's
  `struct isis_p2p_hello_hdr` and Wireshark's dissector use the same
  order, so the three agree.
* **LSP flags**, clause 9.8, quoted in the flags section above.
* **LSP checksum**, clause 7.3.11: "computed over all fields in the LSP
  which appear after the Remaining Lifetime field", so Remaining Lifetime
  is outside it, and "shall never be modified by any other system".
* **TLV 6 entries**, clause 9.5: "6 octet MAC Address", fixed, so ID
  Length does not touch them.
* **TLV 2 metric octets**, clause 9.8, quoted in the metrics section.
  The clause's figure lost its field order in extraction; the field
  descriptions, and FRR 8.4's `pack_item_oldstyle_reach`, put the four
  metric octets before the Neighbour ID. FRR reads that ID as seven
  octets whatever the ID Length; isis4r follows the clause, ID Length
  plus one.

**Where RFC 1142 and the implementations differ: octets 7 and 8.** RFC
1142 calls them ECO and User ECO, "transmitted as zero, ignored on
receipt". Wireshark and FRR read them as Reserved and **Maximum Area
Addresses**, which is the later layout. The code follows the
implementations, since that is what routers send, and zero is the default
either way. Maximum Area Addresses, and zero meaning three, stay second
hand from Wireshark until the 2002 edition is read.

**Point to point IIH procedure, clauses 8.2.3 to 8.2.5**, read for
`P2pCircuit`: the acceptance tests of 8.2.4.1 (ID Length), the area
comparison of 8.2.4.2, which for a Level 1 system deletes the adjacency
on no common area, and the holding timer of 8.2.5. **Table 4 itself, the
Level 1 action table, did not survive the text extraction**, so refusing
a Level 2 only neighbour follows FRR's `process_p2p_hello` and is second
hand. The AllISs destination MAC for point to point hellos is FRR's too,
from `isis_pfpacket.c`, which cites RFC 5309 section 4.1; RFC 5309 is not
read here.

**Also worth knowing for the receive policy.** RFC 1142 clause 7.3.14 says
a control PDU larger than ReceiveLSPBufferSize "shall be treated as if it
had an invalid checksum". RFC 3719 section 5 recommends against discarding
it. The default policy follows RFC 3719, and should quote both.

Still unread:

* **Everything above in ISO/IEC 10589:2002.** RFC 1142 numbering is not
  the 2002 numbering, so none of the clause numbers above converts.
* **Maximum Area Addresses**, and whether zero means three.
* Which TLVs are legal in which PDU, which is validation's business and not
  the encoder's.
* **RFC 5310 sections 3.3 and 3.4**, for how generic cryptographic
  authentication prepares the Authentication Value, which is cited in the
  authentication section and has not been read here. The design only needs
  to know that the preparation is the algorithm's, which holds either way,
  but the second algorithm cannot be written without it.
* **The NLPID numbers** in `Tlv::ProtocolsSupported`. RFC 1195 section
  5.3.1 says only "as assigned by ISO/TR 9577". 0xcc and 0x81 are what
  Wireshark and FRR use, and 0x8e for IPv6 is RFC 5308's, not read here.
* **The RFCs named in the phases.** RFC 8667, 9350, 9352 and 8706 are cited
  by title for scope, not read here. RFC 9885 was read in part, sections 4
  and 5 on what a Multi-Part TLV is and how it is received; the per TLV key
  definitions it defers to other documents are not read. Check each
  before implementing it.

Already settled, with where each came from, so nobody pays for it twice.
Each of these cost a fetch, and two of them overturned what this file
confidently said:

* **TLV 22 and TLV 135 field widths and sub-TLV framing**, quoted verbatim
  from RFC 5305 sections 3 and 4 in the composition section above. First
  hand.
* **RFC 5120 section 1.2** is "Definitions of Terms Used in This Document"
  and defines CSNP, DIS, IIH, LSP, PSNP and SPF. Read.
* **RFC 9681** is IS-IS Fast Flooding. Section 5.2 gives the three classes
  of PDU, section 5.1 covers PSNPs acknowledging LSPs on point to point
  networks, and section 8 says IS-IS runs directly over the link layer
  rather than over IP. Read.
* **RFC 3563** is the ISOC/IETF and ISO/IEC JTC1/SC6 cooperative
  agreement, Informational, later updated by RFC 6233. Its section 2.1
  does list core IS-IS mechanisms, but only to divide the two bodies'
  scope, and its own security section calls it a non-protocol document. So
  it is a correct citation for what the mechanism categories are named and
  a useless one for how any of them works. Read, against the expectation
  that it would turn out to be a misuse.
* **RFC 5303** is point to point adjacencies, by title and by content, so
  it does not support a claim about LAN behaviour. Sections 3.1 and 3.2
  read through datatracker for TLV 240 and the handshake: type 240,
  length 1 to 17, state 0 Up, 1 Initializing, 2 Down, then a 4 octet
  Extended Local Circuit ID, an ID Length Neighbor System ID and a 4 octet
  Neighbor Extended Local Circuit ID. Its verified errata 2587 to 2593
  renumber the ISO clauses it cites, 8.2.4 to 8.2.5, and leave the state
  table as it was.
* **RFC 3719 section 5**, quoted in the packing section: the two
  originating buffer sizes as "private management parameters", the rule
  that each must be at or below `ReceiveLSPBufferSize` and within the link
  MTUs, `ReceiveLSPBufferSize` given as **1492** octets by ISO 10589, a
  default that RFC 3719 allows raising with care, the
  consistency requirement being on that value and not on the originating
  sizes, TLV 14 carrying the **originating** size for receivers to check,
  and the recommendation not to discard oversized PDUs. Read.
  * **It also exposes a numbering collision worth knowing.** RFC 3719
    points at **ISO 10589:2002 section 9.8** for the originating buffer
    size TLV, while this file carries a citation to **RFC 1142 section
    9.8** for the LSP flags masks. Two different subjects under the same
    number, in two documents twelve years apart. That is the RFC 1142
    numbering hazard recorded under Codepoints, arriving with a concrete
    example: never convert an RFC 1142 section number into an ISO 10589
    one.
* **RFC 1195 section 5.3.5**, TLV 130: "CODE - 130", a multiple of 12,
  entries laid out as TLV 128's, the default octet with bit 8 zero and
  bit 7 I/E, the others with S and a reserved bit 7, then the address and
  mask; "present in level 2 LSPs". Read through datatracker, 2026-11-01,
  with section 3.4 on external metrics: "the lowest value of the external
  metric is preferred regardless of the internal cost to reach the
  appropriate exit point".
* **RFC 1195 section 3.2**, "Hierarchical Abbreviation of IP
  Reachability", read 2026-11-02 through datatracker: a Level 2 system
  announces "Any address obtained from a level 1 LSP which is not
  superceded by the manually configured information", at the sum of its
  metric and "the distance from the level 2 router to the appropriate
  level 1 router", the minimum over the routers announcing it, and 63
  when the sum is "greater than 63"; a summary is announced "if they
  correspond to at least one address which is reachable in the area",
  with a manually configured metric, and "metric values are not
  considered when determining if a given configured address supercedes"
  one.
* **RFC 5302** sections 2 to 4, read 2026-11-01: the high bit of the
  default metric in TLVs 128 and 130 is the up/down bit, which "L1L2
  routers MUST set ... for prefixes that are derived from L2 routing";
  TLV 130 is allowed in Level 1 LSPs (2.2); "metrics of the external
  metric-type should never be seen in TLV 128" (2.1); and section 3's
  six step order of preference, internal metric type first and
  L2->L1 inter-area after intra-area at each type.
* **RFC 1195 section 5.3.1** for TLV 129, "one octet per protocol", and
  TLV 132, "four octets per address", with a hello carrying TLV 132 "once
  only" and "up to a maximum of 63 IP addresses". Read through the
  datatracker copy, since rfc-editor.org is blocked. Quoted in the
  classes.
* **The order of the digest and the checksum**, measured 2026-11-01:
  with every computed field thrown away and the key given, isis4r writes
  FRR 8.4.4's HMAC-MD5 LSP byte for byte by computing the digest with the
  Checksum and Remaining Lifetime zeroed and then the checksum over the
  digest. That is the derivation in the authentication section, now
  agreeing with an independent router. Still a measurement, not a clause.
* **RFC 5304** has no test vectors, so the digests in
  `test/fixtures/frr-8.4.4-*-hmac-md5.hex` are the independent values,
  and `ISIS.hmac_md5` is checked against RFC 2202's HMAC-MD5 test cases.
* **RFC 5304** on the Authentication TLV, quoted in the authentication
  section: TLV 10, first value octet is the authentication type, remainder
  is the Authentication Value, type 54 and length 17 for HMAC-MD5, and
  "Checksum and Remaining Lifetime fields are set to zero (0) before
  authentication is computed". Read.
  * **And what it does not say**, which is the useful half: it gives **no
    sender-side ordering** between computing the digest and computing the
    LSP checksum. The five step procedure in that section is RFC 5304's for
    steps 1 to 4 and a derivation for step 5. Do not promote the
    derivation to a citation later just because it is correct.