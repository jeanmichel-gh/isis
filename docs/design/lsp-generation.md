# When isisd generates its own LSPs

Status: approved by the owner 2026-11-22: option 3, with the defaults
proposed here. "Decisions" at the end records the answers.

## The problem

routescope's bfd-lab (isis #111, `routescope/labs/bfd-lab`) measures
failover with and without BFD on three isis4r routers. It found, on
2026-11-22, that isisd holds a change to its own LSP until 30 s after
its last LSP:

- After an adjacency came back up, r1's LSP went out 27 s later.
- When a link then failed, the LSP saying so was held a further 16 to
  21 s. r3 kept sending replies the old way, and failover took about
  20 s with BFD, where it takes 2.5 s on a quiet network.

bfd-lab's two loss scenarios now wait 60 s before the loss to avoid it
(its `ABOUT.md`). That hides the delay. It does not remove it. BFD
detects a failure in 900 ms, and isisd can then sit on the news for up
to 30 s.

This document says what isisd does today, what the standard says, what
FRR does, measured, and the options.

## What isisd does today

From `lib/isis/database/originator.rb` at c2db2d7.

**The two intervals.** Two constants, from RFC 1142's annex defaults:

```ruby
MAXIMUM_LSP_GENERATION_INTERVAL = 900
MINIMUM_LSP_GENERATION_INTERVAL = 30
```

The configuration key `minimum_lsp_interval` sets the minimum
(`Router#originator`). The labs under `routescope/labs` set it to 1,
but for bfd-lab, isis4r-bfd and isis4r-frr, which keep 30 s
(2026-11-22). The maximum has no configuration key.

**What triggers generation.** Four paths, all in `Originator`:

| Path | When | Waits for the minimum interval? |
| --- | --- | --- |
| `start` | the router starts | no |
| `changed(reason)` | an event that may change the content | yes |
| `refresh` | the refresh timer, every 900 s | no |
| `receive_own` | a newer copy of our own LSP arrived (7.3.16.1, 7.3.16.2) | no |

`changed` is called on: an adjacency up or down at a level
(`p2p_level.rb`, `lan_circuit.rb`), a neighbour's addresses changed,
the LAN ID or the DIS changed, the circuit's addresses changed, the
prefixes changed (leaked, summarised, or redistributed), injected TLVs, and the simulator's link and prefix
actions. A BFD session that goes Down takes the adjacency down
(`bfd_circuit.rb`), so it reaches `changed` by the adjacency path, the
same as a hold time that runs out.

**How `changed` times it.** There is one timestamp per `Originator`,
`@generated_at`, set by every generation that produced an LSP:

```ruby
wait = @generated_at ? @generated_at + @minimum_interval - @scheduler.now : 0
```

If `wait` is positive, one timer is set for it, and further events
while it runs are folded into it (`return if @pending`). When it fires,
the LSPs are built again, and only those whose content changed go out
(7.3.6). Otherwise they are built at once.

So, today:

1. **A first change goes out at once** only if no LSP went out in the
   last 30 s.
2. **`start` counts.** The LSP made at start sets `@generated_at`. The
   first adjacency comes up seconds later, and its LSP waits for the
   rest of the 30 s. That is bfd-lab's 27 s.
3. **A refresh counts.** A refresh every 900 s sets `@generated_at` too,
   so for 30 s after each refresh any change is held.
4. **The wait does not shrink with quiet.** It is always measured from
   the last generation, with no backoff and no reset.
5. **One timestamp covers every LSP Number** of a level. A change to LSP
   Number 1 waits on a generation of LSP Number 0.
6. **The refresh has no jitter.** The comment beside `refresh` says
   clause 10.1's jitter "is not applied yet".

The refresh timer is not reset by an event-driven generation
(`schedule_refresh`), as clause 7.3.6 asks. `test/unit/database/
originator_test.rb` holds 1, 2 and the refresh: `test_minimum_interval_
holds_events_back` and `test_refresh`.

## What the standard says

**What could not be checked.** ISO/IEC 10589:2002 is not available
here. Nothing below is checked against it. The clause numbers below are
RFC 1142's, the 1990 republication, and do not convert to the 2002
numbering. RFC 9681 section 3 says that the 2002 update "made no
changes in regards to suggested timer values". That is RFC 9681's
claim; it is not checked here either.

**Read in RFC 1142** (`specs/rfc/rfc1142.txt` in routescope),
2026-11-22:

- 7.3.4, its last paragraph: "The parameters maximumLSPGenerationInterval
  and minimumLSPGenerationInterval shall apply to each LSP individually."
- 7.3.5: the Intermediate system "shall re-generate each LSP at
  intervals of at most maximumLSPGenerationInterval seconds, with jitter
  applied as described in 10.1."
- 7.3.6: "an Intermediate system shall generate an LSP when an event
  occurs which would cause the information content to change." The
  events listed include "an Adjacency or Circuit Up/Down event". "The
  timer maximumLSPGenerationInterval shall not be reset. There is a
  hold-down timer (minimumLSPGenerationInterval) on the generation of
  each individual LSP."
- 7.3.21, the parameters: "minimumLSPGenerationInterval This is the
  minimum time interval between generation of Link State PDUs. A source
  Intermediate system shall wait at least this long before
  re-generating one of its own Link State PDUs. Setting this too large
  causes a delay in reporting new information. Setting this too small
  allows too much overhead. A reasonable setting is 30 seconds."
- The annex: `minimumLSPGenerationInterval-Default INTEGER ::= 30` and
  `MinimumLSPGenerationInterval-Permitted ::= INTEGER(5..300)`, in
  seconds. The type itself is `INTEGER(1..65535)`.
- 10.1: periodic timers whose expiry sends PDUs "shall have jitter
  introduced", up to 25% less than the base value.

So the 1990 text asks for a hold of at least the minimum interval
between two generations of one LSP, 5 s at the least and 30 s by
default. It does not say whether the hold counts from a refresh; "re-
generating one of its own Link State PDUs" reads as any generation. It
has no backoff and no "first change at once".

**Read in RFC 9681** (IS-IS fast flooding), section 3, "Historical
Behavior": "minimumLSPGenerationInterval has been modified to support
millisecond intervals, often with a backoff algorithm applied to prevent
LSP generation storms in the event of rapid successive oscillations."
That describes what implementations do. It defines no algorithm.

**Read in RFC 8405** (SPF back-off delay). It defines a three state
machine, QUIET, SHORT_WAIT and LONG_WAIT, with INITIAL_SPF_DELAY,
SHORT_SPF_DELAY, LONG_SPF_DELAY, TIME_TO_LEARN_INTERVAL and
HOLDDOWN_INTERVAL (sections 3 to 5). Its scope is the routing table
computation, not LSP generation: "IGP event: The reception or
origination of an IGP LSDB change requiring a new routing table
computation." Using its shape for LSP generation would be our choice,
not the RFC's.

No RFC read here defines an LSP generation backoff.

## What FRR does

**Measured** on ospflab, 2026-11-22, FRR 10.7.1
(`quay.io/frrouting/frr:10.7.1`), in a lab of two FRR routers, f1 and
f2, joined by two point-to-point links, Level 2, `frr defaults
traditional`, no `lsp-gen-interval` set, hellos 1 s x 3. A script on
the host printed each new sequence of `f1.00-00` that f2 held, polled
every 0.2 s. Times are f1's debug log (`debug isis update-packets`) and
the script's, UTC. One run each.

| Case | Event on f1 | f1's last LSP before | LSP with the change |
| --- | --- | --- | --- |
| A change 17 s after an LSP | `isis metric 20` on eth1, 02:59:58.144 | 02:59:41.137 | 03:00:11.139, 30.0 s after the last; two more changes at +5 s and +12 s went in the same LSP |
| A change after 89 s of quiet | `isis metric 40` on eth2, 03:01:40.313 | 03:00:11.139 | 03:01:40.408, at once |
| Link loss without BFD, 2 s after an LSP | netem 100% loss on f2's eth1 at 03:01:42.355; f1's hold time expired 03:01:45.162 | 03:01:40.408 | 03:02:10.164: held 25.0 s after the adjacency went down, 30.0 s after the last LSP |
| Link loss with BFD, 2 s after an LSP | netem 100% loss at 03:03:19.707; BFD Down 03:03:20.519 | 03:03:17.770 | 03:03:20.519, the same millisecond as BFD Down, 2.7 s after the last LSP |

The log lines of the last case, from f1:

```
03:03:20.519 ISIS: ISIS-BFD: BFD changed status for adjacency f2 old Up new Down
03:03:20.519 ISIS: ISIS-Adj (LAB): Starting fast-reroute on state change 2->3: bfd session went down
03:03:20.519 ISIS: ISIS-SPF (LAB) L2 SPF scheduled immediately due to BFD 'down' message
03:03:20.519 ISIS: ISIS-Upd (LAB): Refreshed our L2 LSP 0000.0000.0091.00-00, len 99, seq 0x00000008, cksum 0x92b3, lifetime 1190s refresh 857s
```

So FRR at its defaults behaves as isisd does today, with one exception:
a BFD Down skips the hold.

**What the source says**, read to explain the measurement, not in its
place. `isisd/isis_lsp.c` at tag `frr-10.7.1`, `_lsp_regenerate_
schedule`: if the time since `lsp->last_generated` is under
`lsp_gen_interval`, the regeneration is scheduled for the rest of it,
"to match configured lsp_gen_interval", unless `area->
bfd_signalled_down` is set. `isis_bfd.c` sets that flag when a session
goes from Up to Down. Otherwise the regeneration runs after at most
100 ms since the last change event, "the instability timer".
`lsp_regenerate` sets `last_generated` on every generation, refreshes
included. `isis_constants.h`: `DEFAULT_MIN_LSP_GEN_INTERVAL 30`,
`MIN_MIN_LSP_GEN_INTERVAL 1`, `MAX_MIN_LSP_GEN_INTERVAL 120`. FRR has
no LSP generation backoff in this file; its RFC 8405 support is for SPF
(`spf-delay-ietf`), which is not measured here.

The lab's files and full logs are not kept in the repository. The
scripts were `exp1.sh` and `exp2.sh`: a metric change, then 2 s later
`tc qdisc add dev eth1 root netem loss 100%` on f2.

## The options

Each option keeps `changed` the one place that decides, and keeps it a
method a test can replace (CLAUDE.md, "Autonomous operation and testing
controls"). Each keeps the RFC 1142 timing reachable, for tests that
want it.

### Option 0: leave the code, set the labs

Set `minimum_lsp_interval: 1` in bfd-lab, as most labs here do, and
drop its 60 s wait.

- Smallest change. No code.
- isisd at its defaults still holds a failure up to 30 s, which is what
  a user of isisd outside our labs gets.
- bfd-lab would no longer show isisd's default behaviour, and BFD's
  gain would be measured on a setting nobody else uses.

### Option 1: BFD Down skips the hold, as FRR does

An adjacency that goes down because BFD said so generates at once.
Everything else stays.

- Matches FRR 10.7.1, measured above.
- Fixes bfd-lab's case, and only it. A hold time that runs out, a
  carrier loss, or an adjacency that comes up, still wait up to 30 s.
- Needs a reason passed to `changed`, or a second method, so the
  originator knows the event was BFD's.

### Option 2: refreshes and start do not count

`@generated_at` is set only by an event-driven generation. A refresh
and the LSP made at start no longer open a 30 s hold.

- Removes bfd-lab's 27 s after start, and the 30 s after each refresh.
- Still holds a second change within 30 s of a first.
- A reading of 7.3.21 that is not the literal one: a refresh is a
  "re-generating".

### Option 3: a backoff, the first change at once

The shape RFC 9681 section 3 describes. Three settings per level:

| Setting | Meaning | A starting value, for the owner to choose |
| --- | --- | --- |
| `initial` | the wait for the first change after a quiet period | 0 s |
| `secondary` | the wait for the next change after one went out | 1 s |
| `maximum` | the longest wait; also the quiet time that resets it | 30 s |

On a change: if the last event-driven generation was more than
`maximum` ago, wait `initial`. Otherwise wait the current interval from
the last generation, then double the interval, up to `maximum`. A
refresh does not count (Option 2).

- A single failure goes out at once, BFD or not. A flapping link backs
  off to the 30 s of today.
- Two new terms and three settings. The doubling is our choice. No RFC
  read here defines it.
- An `initial` of 0 is below RFC 1142's permitted 5 s. So is the 1 s
  most labs here already set, and FRR's own floor of 1 s.

### Option 4: RFC 8405's state machine, applied to LSP generation

QUIET, SHORT_WAIT and LONG_WAIT, with RFC 8405's five parameters, used
for LSP generation instead of SPF.

- A machine already specified, with its states and timers written out.
- RFC 8405 is for SPF. Its reasons (every router computing at the same
  moment) do not carry over to generation, where only one router
  originates. Option 3 is simpler for the same effect.
- isisd's SPF has its own fixed `delay` (`spf/decision.rb`). If the
  owner later wants RFC 8405 for SPF, that is its own design, and it
  could share this code.

### Also wrong today, whichever option

- **One timestamp for every LSP Number.** RFC 1142 7.3.4 says the hold
  applies "to each LSP individually". Keep `@generated_at` per LSP
  Number. This changes nothing for a router whose LSP fits in LSP
  Number 0, which is every lab here.
- **No jitter on the refresh** (10.1). A separate, small change.

## Recommendation

Option 3, with Option 2 in it, and the defaults chosen so isisd at its
defaults still follows RFC 1142:

- With no setting, isisd keeps today's fixed 30 s hold, counted per LSP
  Number, refreshes included. That is the protocol's default, and
  isis4r's ordinary operation follows the protocol.
- A new `lsp_generation: { initial:, secondary:, maximum: }` turns the
  backoff on. `minimum_lsp_interval` stays, and means the fixed hold.
  Giving both is an error.
- bfd-lab and the other labs set the backoff. bfd-lab drops its 60 s
  wait, and its scenarios get a case that fails twice in a row.

Option 1 is then not needed: with the backoff, a BFD Down after a quiet
period goes out at once, and after a recent change it waits
`secondary`.

## Work, once approved

1. `Originator`: the hold per LSP Number; a `GenerationTimer` object
   that answers the wait for a change, fixed or backoff, which a test
   can replace. Tests on the manual clock: first change at once after
   quiet; the doubling; the reset after `maximum`; a refresh not
   counted with the backoff and counted without it; per LSP Number.
2. Configuration: `lsp_generation` in `isisd.yml` and the simulator's
   `sim.yml`, the router.rb header, `docs/isisd.md`. The daemon API's
   view of the originator shows the current wait.
3. Labs: bfd-lab and the others set it; bfd-lab's loss scenarios lose
   their 60 s wait and are run again through routescope, measured.
4. An interop check against FRR at its defaults, where FRR holds and
   isisd does not.

## Decisions

The owner's answers, 2026-11-22: "option 3 with the defaults you
proposed".

1. Option 3, with option 2 in it: a refresh and the LSP made at start
   do not count toward the backoff.
2. The default stays RFC 1142's fixed hold, 30 s, counted per LSP
   Number. The backoff is a setting.
3. `initial` 0 s, `secondary` 1 s, `maximum` 30 s, when
   `lsp_generation` is given without them.
4. In fixed mode a refresh still counts, as today and as in FRR.
5. The pseudonode LSP follows the same rules, as today: `Pseudonode` is
   an `Originator`. This one was not asked in words; it is the
   document's default.
