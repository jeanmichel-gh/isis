# Parse policy

A length field is written by someone else, so it can say anything. These
seven rules decide what isis4r does when one lies. They are written once,
in `ISIS::Tlv.factory`, `ISIS::Tlv::List` and `ISIS::Pdu.factory`, and
every list loop in the library uses those.

The promise behind them: **every object replays exactly the octets it
consumed**, whatever its length fields claimed. A capture of something
broken goes back out broken.

Each rule names the tests that hold it. The suite checks that every test
named here exists, so a renamed or deleted test fails it.

## 1. The boundary passed down always wins

A TLV knows how many octets its PDU has left, and a PDU knows how many its
capture has. A declared length past that boundary is clamped to it and
never followed.

- `TestTlvListParsePolicy#test_tlv_overrunning_its_boundary_is_clamped_and_replayed`
- `TestTlvListParsePolicy#test_boundary_wins_over_the_buffer`
- `TestPduParsePolicy#test_the_boundary_wins`

## 2. A clamp is kept, not absorbed

The object keeps the length as declared and writes it back.

- `TestTlvListParsePolicy#test_tlv_overrunning_its_boundary_is_clamped_and_replayed`
- `TestTlvListParsePolicy#test_clamped_tlv_after_a_good_one`
- `TestPduParsePolicy#test_declared_length_runs_past_the_capture`

## 3. Every read makes progress, or the loop stops

Fewer than two octets cannot be a TLV. A zero length TLV still consumes
its two header octets. The backstop is in the loop, not in each class.

- `TestTlvListParsePolicy#test_zero_length_tlvs_make_progress`
- `TestTlvListParsePolicy#test_one_octet_remainder_is_a_tail`

## 4. Leftover octets are a tail

What cannot be read at the end of a container is kept and written back.

- `TestTlvListParsePolicy#test_one_octet_remainder_is_a_tail`
- `TestTlvListParsePolicy#test_a_single_octet_is_all_tail`
- `TestTlvListParsePolicy#test_tail_survives_the_hash`

## 5. A fixed header cut short builds no layout

Building the layout would invent the octets that never arrived. The PDU is
an `ISIS::Pdu::Truncated` holding what did arrive.

- `TestPduParsePolicy#test_cut_inside_the_common_header`
- `TestPduParsePolicy#test_cut_before_the_type_octet`
- `TestPduParsePolicy#test_cut_inside_the_layout_fixed_header`
- `TestPduParsePolicy#test_a_boundary_inside_the_fixed_header_truncates`

## 6. The declared PDU Length and the capture go wrong four ways

| Case | Result |
|---|---|
| Fixed header incomplete | rule 5, `Truncated` |
| Declared length past the capture | the layout, with what arrived, the declared length kept |
| Declared length short of the capture | the layout, consuming the declared extent |
| Declared length below the fixed header, zero included | `ISIS::Pdu::Malformed`, kept whole, the value never used in arithmetic |

- `TestPduParsePolicy#test_declared_length_runs_past_the_capture`
- `TestPduParsePolicy#test_declared_length_shorter_than_the_capture`
- `TestPduParsePolicy#test_declared_length_below_the_fixed_header`

## 7. A PDU replays its consumed slice, and the capture owns the rest

Octets past a PDU's declared end belong to the level above it. An
`ISIS::Capture` holds one PDU and whatever followed it, and replays all of
it.

- `TestPduParsePolicy#test_declared_length_shorter_than_the_capture`
- `TestCapture#test_padding_after_the_pdu_is_the_capture_tail`
- `TestCapture#test_every_kind_of_pdu_replays_through_a_capture`

## Not a rule, and why

A PDU type with no layout is not parsed at all. `ISIS::Pdu::Unknown` keeps
its octets opaque, because nothing establishes that its body is TLVs or
where they would begin. See `TestPduFactory#test_unimplemented_type_is_opaque_and_replays`.
