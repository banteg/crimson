# typo_target_name_assign_random

Native target: `crimsonland.exe` at `0x00445380` (522 bytes, 173
instructions).

The recovered MSVC 6.5 `/O2 /GB` source matches exactly:

```txt
match=100.00% prefix=173/173 target_insns=173 candidate_insns=173 refs=37/0/0
```

## Recovered source shape

- The score is interpreted as a signed integer. Scores above 120 first take a
  10% high-score-name gate, then an independent 80% four-fragment gate.
- Three-fragment names use independent 80% and 40% gates above scores 80 and
  60. Two-fragment names use the same independent pattern above scores 40 and
  20. VC6 tail-merges each pair of identical formatter bodies through a
  backward branch, matching the native layout. This separate `else if` spelling
  is a strongly evidenced source hypothesis, not proof of the exact original
  text. All other attempts use one ordinary fragment.
- Multi-fragment names begin with the prefix-capable word picker. VC6's
  right-to-left argument evaluation calls the ordinary fragment pickers first,
  matching the native random-draw order.
- The high-score branch copies its selected string inline; the fragment
  branches format directly into the selected creature's 64-byte name slot.
  Each branch and the validation tail spell that slot as the direct table
  expression rather than publishing it through a named pointer.
- Every candidate is checked against active creature names. A unique name of at
  most 15 bytes returns immediately. Unique overlength names retry 100 times
  and the 101st is accepted; duplicate names do not advance that counter.

The 173-instruction body, all 522 bytes, and all 37 audited references agree.
The signed
score cast is material: omitting it changes the native signed `jle` tests into
unsigned comparisons.

## Exact source-spelling completion

The final residual came from publishing the selected slot through a local
`char *name`. With that spelling, VC6 coalesces the creature id into the
eventual `ebx` destination and emits `mov ebx, ebp; shl ebx, 6; add ebx, base`.
The native function instead scales a temporary and forms the persistent `ebx`
slot address with `lea`.

Using `typo_target_name_table[creature_id]` directly at every copy, formatter,
uniqueness, and length site gives VC6 the original common-subexpression shape.
It keeps the slot address in `ebx` across the selected branch and validation,
while constructing it through the native temporary `shl` plus `lea`. This also
recovers the native scratch registers in the inline copy and final
post-increment comparison. No volatile state, dummy work, or register forcing
is involved.

The earlier allocation audit remains useful negative evidence. Its sixteen
byte-neutral variants cover row typedefs, row-struct conversions, typed wrapper
access, byte/shifted offsets, copied indices, and named base/offset forms.
`name-table-type-mutations.json` covers row typedefs, row-struct conversions,
typed wrapper access, and byte/shifted offsets.
`first-name-slot-address-mutations.json` covers copied indices, named
multiply/shift offsets, and both base-first address forms at the first affected
site. Those probes left the named-pointer ownership unchanged, which is why
they were neutral. A separate compiler/flags matrix also confirms MSVC 6.5/6.6
as the best compiler family for this body.

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

## Exactness audit

Live Binary Ninja control flow accounts for every signed score tier, random
gate and draw order, formatter path, active-name scan, length rule, and retry
boundary. Candidate and native each have 173 instructions and 522 bytes with
references `37/0/0`; the normalized instruction streams are identical.
