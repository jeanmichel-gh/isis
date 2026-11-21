# Protocol testing

How isis4r checks what it receives, and what a test can make it do with
something wrong. Built to routescope's `docs/design/protocol-conventions.md`,
part 2, as bgp4r, vtep4r and bfd4r are.

## Findings

`lib/isis/validation.rb` holds the receive rules, each a named finding
with the clause it comes from (`CLAUDE.md`, "Validation"). It decides
nothing; the caller acts on a finding under the receive policy. A finding
is on one of three channels: `errors` (the sender broke a clause), `gaps`
(isis4r has no code for it) and `inconclusive` (what arrived cannot
support a verdict).

The first rules are segment routing's (RFC 8667, RFC 8660). They run on
the LSP database after each SPF run, in `Spf::Labels`, since each needs
several sub-TLVs or several systems' LSPs. isisd logs a finding by its
name, and `show.segment_routing` lists them per level.

| Finding | Channel | When |
| --- | --- | --- |
| `srgb_range_zero` | errors | an SRGB descriptor with a range of 0 |
| `srgb_overlap` | errors | two SRGB ranges that overlap |
| `srgb_reserved` | errors | an SRGB range below 16 or past 1048575 |
| `sr_capabilities_twice` | errors | more than one SR-Capabilities from one system |
| `prefix_sid_vl_invalid` | errors | a Prefix-SID with V set and L clear, or L set and V clear |
| `algorithm_not_advertised` | errors | a Prefix-SID for an algorithm its origin does not run |
| `prefix_sid_duplicate` | errors | one index on two prefixes |
| `prefix_sid_label` | gaps | a Prefix-SID that is a label, not an index |

Two outcomes are not findings, since no sender broke a clause: an index
past this system's SRGB, and a neighbor without an SRGB (RFC 8660
section 2.10.1 sends the packet another way). They stay problems, in the
same list.

## Receive policies

`segment_routing: { receive_policy: rfc }` in isisd's file. Each rule
says what each policy does.

| Policy | Does |
| --- | --- |
| `rfc` | the default: what the clause asks. An SRGB that breaks RFC 8660 section 2.3 is "completely ignored", and its node "treated as if it does not have an SRGB"; the first SR-Capabilities is used; an invalid Prefix-SID is not used; two prefixes with one index both go without a label |
| `strict` | refuses on any finding: a node with a finding on its SR-Capabilities has none of its SR data used |
| `lenient` | uses what arrived where it can, to watch what a sender sends: an SRGB that overlaps or has an empty range, and a Prefix-SID whose algorithm its origin did not list. An SRGB with reserved labels is still ignored, since those labels cannot be installed |

The tests: `test/unit/validation_test.rb` for each rule,
`test/unit/spf/sr_findings_test.rb` for each finding on hand-built LSPs
and each policy.
