# typo_target_name_assign_random

Native target: `crimsonland.exe` at `0x00445380` (522 bytes, 173
instructions).

The recovered MSVC 6.5 `/O2 /GB` source is an honest WIP:

```txt
match=76.88% prefix=17/173 target_insns=173 candidate_insns=173 refs=27/0/0
```

## Recovered source shape

- The score is interpreted as a signed integer. Scores above 120 first take a
  10% high-score-name gate, then an independent 80% four-fragment gate.
- Three-fragment names use an 80% gate above score 80 or a 40% fallback gate
  above score 60. Two-fragment names use the same 80%/40% pattern above scores
  40 and 20. All other attempts use one ordinary fragment.
- Multi-fragment names begin with the prefix-capable word picker. VC6's
  right-to-left argument evaluation calls the ordinary fragment pickers first,
  matching the native random-draw order.
- The high-score branch copies its selected string inline; the fragment
  branches format directly into the selected creature's 64-byte name slot.
- Every candidate is checked against active creature names. A unique name of at
  most 15 bytes returns immediately. Unique overlength names retry 100 times
  and the 101st is accepted; duplicate names do not advance that counter.

The 173-instruction length and all 27 audited references agree. The signed
score cast is material: omitting it changes the native signed `jle` tests into
unsigned comparisons.

## Remaining compiler delta

Native forms each name-slot address through a temporary scaled index and an
`lea`; the calibrated compiler keeps the creature id in the eventual `ebx`
destination register and uses `add`. That allocation choice also changes the
temporary used by the inline string copy and final post-increment comparison.
The other substantial normalized delta is block placement: native shares the
three- and two-fragment formatting bodies through backward branches, while VC6
lays the equivalent clean short-circuit source out linearly.

Equivalent two-dimensional, byte-array, scalar-base, struct-field, and explicit
offset expressions all reproduce the same candidate allocation. High-level
short-circuit expressions, decompiler-shaped nested conditions, shared labels,
and explicit linear gotos likewise do not improve the native block order.
MSVC 6.0 and 6.6 are no better, 6.5pp and 7.0 regress sharply, and `/G6` is
slightly worse. No volatile state, dummy work, or register-forcing construct is
retained.

## Port parity

Python and Zig already preserve the signed score tiers, gate thresholds,
fragment order, uniqueness rule, and 15-byte limit. This recovery exposed a
Python off-by-one in the overlength retry counter: Python accepted the 100th
candidate, while native and Zig accept the 101st. The Python ordering and a
focused regression test were corrected in `fix(typo): preserve native
long-name retries`.

Both ports intentionally cap duplicate retries at 200 to avoid an unbounded
loop when the generalized dictionary cannot produce a unique name; the native
routine has no duplicate-attempt cap.
