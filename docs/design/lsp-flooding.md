# When isisd sends an LSP on a point-to-point circuit

Status: a draft for the owner. No code until it is approved.

## The problem

`docs/design/lsp-generation.md` gave isisd a backoff, so a change to its
own LSP goes out within a second or two. Re-measuring bfd-lab (isis
#116) found a second hold, this one in flooding. In one run, r1
generated its LSP for a link loss at 07:16:46.47, 0.6 s after BFD went
Down. r3 stored it at 49.69, 3.2 s later. r2's LSP for the same loss,
generated at 46.48, reached r3 at 49.50. Each came about 5 s after r3
received the version before it. bfd-lab's `ABOUT.md` keeps the runs.

This document says what isisd does today, what the standard says, what
FRR does, measured, and the options.

## What isisd does today

From `lib/isis/database/update_process.rb` at c2b17fd.

**The flags.** Each LSP entry has an SRM set and an SSN set, holding
circuit names (RFC 1142 7.3.15). `set_srm(entry)` adds the circuit to
SRM and calls `schedule_srm(0)`.

**One timer per circuit.**

```ruby
def schedule_srm(delay)
  @srm_timer ||= @scheduler.after(delay) { send_srm_lsps }
end
```

When it fires, `send_srm_lsps` sends every LSP with SRM set on the
circuit. On a point-to-point circuit SRM stays set until a PSNP or CSNP
clears it, and if anything was sent, the timer is set again for
`@lsp_transmission_interval`: `MINIMUM_LSP_TRANSMISSION_INTERVAL`, 5 s,
in `p2p_circuit.rb`. On a LAN one LSP goes per tick, its SRM cleared,
every `MINIMUM_BROADCAST_LSP_TRANSMISSION_INTERVAL`, 33 ms.

So on a point-to-point circuit:

1. **A new LSP waits for the timer already running.** `||=` keeps the
   timer that was set 5 s after the last send. The new LSP's own
   `schedule_srm(0)` does nothing. It goes when that timer fires: from
   0 to 5 s later.
2. **An acknowledgement does not stop the timer.** A PSNP clears SRM,
   but the timer still runs to its end, finds nothing, and stops. A new
   LSP in that window still waits for it.
3. **It holds every LSP that floods through this system**, not only its
   own. The hold adds up hop by hop.

`lsp_transmission_interval` is a keyword of `P2pCircuit` and
`LanCircuit`. It is not an interface key in `isisd.yml`
(`Router::INTERFACE_KEYS`).

## What the standard says

**What could not be checked.** ISO/IEC 10589:2002 is not available
here. The clause numbers below are RFC 1142's, the 1990
republication. They do not convert to the 2002 numbering.

**Read in RFC 1142** (`specs/rfc/rfc1142.txt` in routescope),
2026-11-22:

- 7.3.15: "On broadcast circuits SRMflag is cleared as soon as the LSP
  has been transmitted, but on non-broadcast circuits SRMflag is only
  cleared on reception of a Link State PDU or Sequence Numbers PDU".
- 7.3.15.5, "Action on expiration of Minimum LSP Transmission
  Interval": "An IS shall perform the following actions every
  minimumLSPTransmissionInterval seconds with jitter applied as
  described in 10.1. a) For all Point to Point circuits C transmit all
  LSPs that have SRMflag set on circuit C, but do not clear the
  SRMflag." Then: "The interval between two consecutive transmissions
  of the same LSP shall be at least minimumLSPTransmissionInterval.
  Clearly, this can only be achieved precisely by keeping a separate
  timer for each LSP. This would be an unwarranted overhead. Any
  technique which ensures the interval will be between
  minimumLSPTransmissionInterval and 2 * minimumLSPTransmissionInterval
  is acceptable."
- 7.3.21: "minimumLSPTransmissionInterval This is the amount of time an
  Intermediate system shall wait before further propagating another
  Link State PDU from the same source system." It adds that a value
  greater than minimumLSPGenerationInterval "makes no sense".
- The annex: `minimumLSPTransmissionInterval-Default INTEGER ::= 5`,
  `MinimumLSPTransmissionInterval-Permitted ::= INTEGER(5..30)`, and the
  attribute's behaviour: "Minimum interval, in seconds, between
  re-transmissions of an LSP". `partialSNPInterval-Default INTEGER ::=
  2`.
- 7.3.17: on point-to-point links each LSP received is acknowledged by
  a PSNP.

Read literally, 7.3.15.5 sends LSPs only on the timer, so a new LSP
could wait up to 5 s. Its own reason, and the annex, speak of
**re-transmissions** of **the same** LSP. 7.3.21's wording, "another
Link State PDU from the same source system", reads as a limit per
source. The two readings differ for a new version of an LSP. The text
here does not settle which one the 2002 edition keeps.

**Read in RFC 9681** (IS-IS fast flooding), 2026-11-22. Section 3 quotes
[ISO10589]'s minimumLSPTransmissionInterval text, "A reasonable value
is 5 s", and says "Convergence targets at the time were on the order of
seconds, and the specified timer values reflect that". Section 5.1
asks receivers to acknowledge sooner: "the receiver SHOULD use a
partialSNPInterval smaller than the one defined in [ISO10589]", with
200 ms as "a reasonable value". Section 5.2: a lost PSNP "results in
needless retransmissions that further delay transmission of other LSPs
that are yet to be transmitted". It defines no rule for when a new
version is first sent.

## What FRR does

**Measured** on ospflab, 2026-11-22, isisd (with the backoff) against
FRR 10.5.1, one point-to-point link, through `test/support/frr_lab.rb`
with `debug isis update-packets` on FRR. FRR's `lsp-gen-interval` was
1 s. Two changes 1.5 s apart each way, one run. From isisd's debug log
and FRR's log, UTC:

| Direction | First LSP sent | Its PSNP back | Second LSP made | Second LSP sent |
| --- | --- | --- | --- | --- |
| isisd to FRR | 17:20:40.665 | 40.886 | 42.195 | 45.667 |
| FRR to isisd | 17:20:54.3, stored by isisd at 54.346 | 54.523 | about 56.0 | stored by isisd at 56.003 |

isisd's lines:

```
17:20:40.612Z info  0000.0000.0001.00-00 sequence 0x00000003 generated: LSP Database Overload bit set (RFC 1142 7.3.19.1)
17:20:40.665Z veth0 > L1 LSP 0000.0000.0001.00-00, sequence 0x00000003, lifetime 1199, checksum 0x539d, IS type 1, OL, 6 TLVs
17:20:40.886Z veth0 < L1 PSNP from 0000.0000.0002.00, 1 TLVs
17:20:42.195Z info  0000.0000.0001.00-00 sequence 0x00000004 generated: LSP Database Overload bit cleared (RFC 1142 7.3.19.1)
17:20:45.667Z veth0 > L1 LSP 0000.0000.0001.00-00, sequence 0x00000004, lifetime 1196, checksum 0x4da6, IS type 1, 6 TLVs
17:20:54.346Z info  veth0 LSP 0000.0000.0002.00-00 sequence 0x00000006 stored: newer than 0x00000005 (RFC 1142 7.3.15.1 e 1)
17:20:56.003Z info  veth0 LSP 0000.0000.0002.00-00 sequence 0x00000007 stored: newer than 0x00000006 (RFC 1142 7.3.15.1 e 1)
```

So isisd held its second LSP 3.5 s, to exactly 5.0 s after the first
send, though FRR had acknowledged the first 0.2 s after it went. FRR
sent its second at once.

**What the source says**, read to explain the measurement.
`isisd/isis_tx_queue.c` at tag `frr-10.5.1`: each circuit has a queue
with one entry per LSP. `_isis_tx_queue_add` cancels that entry's timer
and schedules a send at 0 (`event_add_event(..., 0, &e->retry)`). The
send sets the entry's own retry timer to 5 s. `_isis_tx_queue_del`, on
acknowledgement, cancels it. So FRR keeps a timer per LSP, the
"separate timer for each LSP" 7.3.15.5 calls precise.

## The options

Each keeps the update process's methods ones a test can replace or
drive (CLAUDE.md, "Autonomous operation and testing controls"), and
each keeps `lsp_transmission_interval` as the retransmission interval.
None changes a LAN circuit, where the wait is 33 ms per LSP.

### Option 0: leave it

- No change. A new LSP waits up to 5 s on each point-to-point hop.
- A reading of 7.3.15.5's first sentence supports it.

### Option 1: stop the timer when nothing is flagged

When a PSNP or CSNP clears the last SRM on a circuit, cancel the
timer. A new LSP then finds no timer and goes at once.

- Small. Fixes the measured case, where the ack came 0.2 s after the
  send.
- A new LSP that comes before the ack still waits.

### Option 2: a new LSP goes at once, and each LSP keeps its last send

`set_srm` sends that one LSP at once, and records when it was sent, per
circuit. The circuit timer still ticks every 5 s while anything is
flagged. A tick sends only the flagged LSPs whose last send on that
circuit is 5 s or more ago.

- A new version is never held. Each LSP is retransmitted between 5 and
  10 s after its last send, the window 7.3.15.5 calls acceptable.
- One timer per circuit, as today, plus a time per LSP and circuit.
- Reads "the same LSP" as the same LSP and sequence; a new version is
  not a retransmission. That is the annex's reading. It is not 7.3.21's
  "another Link State PDU from the same source system".

### Option 3: a timer per LSP, as FRR does

Each flagged LSP has its own retransmission timer on each circuit,
started when it is sent and cancelled when it is acknowledged.

- Retransmissions at exactly 5 s. What FRR 10.5.1 does.
- The most timers: one per LSP per circuit while flagged. 7.3.15.5
  calls it "an unwarranted overhead". On the manual clock it is many
  scheduled callbacks for a large database.

### Option 4: a shorter interval

Make `lsp_transmission_interval` an interface key and set it lower.

- No code beyond the key. The hold shrinks but stays.
- Below RFC 1142's permitted 5 s.

### Also worth doing, whichever option

- **Acknowledge sooner.** isisd sent its PSNPs 0.18 and 0.52 s after
  receipt in the run above. RFC 9681 5.1 suggests 200 ms. Not measured
  as a cause here: FRR's acks came in 0.2 s.
- **Jitter** on the retransmission timer, as 7.3.15.5 asks ("with
  jitter applied as described in 10.1"). Not applied today.

## Recommendation

Option 2, with option 1 in it.

- A new LSP, isisd's own or one it floods, goes on each
  point-to-point circuit at once. The hold no longer adds up hop by
  hop.
- Retransmission keeps RFC 1142's interval, and stays within the
  window 7.3.15.5 allows, on one timer per circuit.
- When the last flag clears, the timer stops.

This changes the default, unlike the LSP generation backoff. The
retransmission interval is RFC 1142's, and a new version going at once
is the annex's reading and FRR's behaviour. A test that wants today's
hold replaces `send_srm_lsps` or `set_srm` on one circuit's update
process.

## Work, once approved

1. `UpdateProcess`: the last send per LSP and circuit, `set_srm` sending
   at once on a point-to-point circuit, the tick sending only what is
   due, the timer stopped when nothing is flagged. Tests on the manual
   clock: a new LSP while the timer runs goes at once; an unacknowledged
   LSP is sent again between 5 and 10 s; an acknowledged one is not; the
   timer stops when nothing is flagged; a LAN circuit is unchanged.
2. A scenario test with three routers in a line: a change at one end
   reaches the other end within a second, where today it can take up
   to 10 s.
3. bfd-lab re-run through routescope, `failover_again` measured. The
   interop test of #125 tightened if the numbers allow it.

## Open questions

1. Option 2, or another?
2. Should a new LSP go at once on a LAN too, before the 33 ms tick?
   Today it waits at most one tick per LSP queued ahead of it.
3. Make `lsp_transmission_interval` an interface key in `isisd.yml`?
4. Acknowledge sooner (RFC 9681 5.1), here or in its own design?
