# bonus_spawn_at_pos WIP

Current best local score:

```txt
match=88.44% prefix=0/99 target_insns=99 candidate_insns=100 refs=14/0/0
```

The recovered source matches the native bounds and Rush-mode guard, slot
allocation, fixed 16-entry spacing scan, sentinel fallback, pickup field
initialization, random type selection, weapon selection, points jackpot roll,
and metadata default amount. All 14 masked references resolve to the intended
globals, constants, and helper calls.

Writing the squared distance as two source operations recovers the native x87
stack schedule through `fsqrt`. This also exposed a Python parity bug: native
PC=24 arithmetic rounds one reachable boundary hypotenuse to exactly 32, while
the old double-precision squared-distance predicate treated it as below 32 and
rejected the spawn. Both ports now use the explicit native PC=24 hypotenuse.

The position input is now a read-only `vec2f_t`, so the recovered guard,
spacing scan, and entry initialization use named `x`/`y` fields instead of raw
float offsets. The saved Binary Ninja prototype and a recovered
`bonus_entry_t *scan` induction cursor expose both the position and bonus-pool
fields in HLIL. This type-only change preserves the score and all 14
references.

The entry initialization also copies through the canonical
`bonus_entry_t::time.position` aggregate. The aggregate assignment compiles
identically to the two scalar component stores, preserving the 88.44% WIP.

The spacing scan now reads that same aggregate on every owning bonus record,
removing its last `time.pos_x`/`time.pos_y` compatibility aliases. The result
remains 100/99 instructions, 88.44%, and 14/0/0 references.

The remaining mismatch is register-save placement. Native saves `EDI` at entry
and shrink-wraps the `ESI` save until after the early guard; the calibrated VC6
compiler saves both registers in the prologue for this clean source. The body
otherwise aligns instruction-for-instruction after accounting for the shifted
save/restore sites. Do not distort the source to manufacture the register
schedule without compiler or neighboring-object evidence.

Inverting the guard into a valid-position body does not induce shrink-wrapping:
VC6 still saves both registers in the prologue and also changes the floating
comparison forms, reducing the score to 80.40% with two fewer aligned
references. The native-facing invalid guard remains the stronger source shape.

## Recovery classification audit

Live Binary Ninja HLIL accounts for all bounds, spacing, allocation, sentinel,
initialization, random-type, weapon, jackpot, and default-amount paths. The
candidate emits 100 instructions against 99 native instructions with `14/0/0`
references. Its localized differences are the documented saved-register
lifetime and dependent allocation/scheduling only, so recovery is
`semantic-complete` with a `compiler` residual.

## Recorded invalid-tail check

Live native disassembly confirms the allocation boundary: only `EDI` is saved
before the complete bounds/Rush guard, and `ESI` is shrink-wrapped at
`0x0041f805` immediately before slot allocation. The candidate saves both in
its prologue.

`invalid-tail-mutations.json` records an explicit `goto` from the unchanged
invalid guard to a physical sentinel-return label at the function tail. The
complete label/goto pairing and the label-only form both compile
byte-identically at 88.44%, 100 instructions, and references `14/0/0`; the
incomplete goto-only form fails compilation. No source variant is retained.
Stock `/G5`, `/G6`, `/Ob1`, and `/Ot` are likewise byte-identical to `/GB`,
while `/Oy-` regresses.

`guard-helper-mutations.json` tests the early bounds/Rush predicate behind
both `__inline` and `__forceinline` helpers, including the complete helper-call
interactions. Unused helper definitions are removed and leave the baseline
byte-identical; calling either helper falls to 75.38% without changing the
100-instruction count or clean `14/0/0` audit. The complete five-variant sweep
is recorded under spec SHA-256
`e882b73953bb6ea1430a1e6b993bd11b91bd7786ae7d88f5efd7652afe38fa72`.
An inlined guard boundary therefore does not reproduce native's shrink-wrapped
`ESI` save.

`entry-scan-declaration-mutations.json` directly tests the native save boundary
at `bonus_alloc_slot()`. Splitting either pointer declaration from assignment,
declaring both pointers before either assignment, and reversing the declaration
order are byte-neutral at 88.44%; initializing the scan before allocation
regresses to 61.69% and loses one resolved reference. All five variants are
recorded under spec SHA-256
`3670bec0873e59fdc94f445a9460db318ae5216700b581ea533caef6c2a6d298`.
The early `ESI` save is not controlled by the entry/scan declaration lifetime.

## Inline valid-body recovery

The surviving 2003 SDK source establishes that small gameplay helpers are
written as ordinary `inline` functions. Applying that source boundary to the
post-guard allocation, spacing scan, and entry initialization recovers the
native shrink-wrapped register lifetime: `bonus_spawn_at_pos` saves only
`EDI` while checking the bounds and Rush-mode guard, then the inlined valid
body introduces the native delayed `push esi` immediately before
`bonus_alloc_slot()`.

This is an exact recovery, not a scheduling tradeoff. The candidate improves
from **88.44%**, 100/99 instructions, prefix zero, and references `14/0/0` to
**100.00%**, 99/99 instructions, prefix 99, and references `15/0/0`. The
helper preserves every previously recovered side effect and return path; its
retained source SHA-256 is
`4045aff58eef0864cc8ca90662c2971582b3d7c05b823c6af3176bdeb97d8e1f`.
