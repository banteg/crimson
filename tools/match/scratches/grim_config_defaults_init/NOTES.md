# `grim_config_defaults_init`

Native target: `grim.dll` at `0x10001710` (734 bytes).

The complete native instruction stream is identical to the executable's
`config_init_defaults` at `0x004028f0` after image relocations are normalized.
Both functions have the same 734-byte extent, 140 instructions, stack layout,
saved-name loop, configuration stores, and final `0x17e` EAX residue.

The two images therefore compile the same recovered implementation against
different instances of the 0x480-byte `crimson_cfg_t` blob. The shared
`crimson_config_defaults_impl.h` body records that provenance without
duplicating or coercing source.

The stock VC6 `/O2 /GB` profile produced 77.74%, 140 native versus 143
candidate normalized instructions, and references `65/0/2`. Live comparison
with the byte-identical executable copy then isolated the same profitable
function-local frame-pointer override: compiling the shared implementation with
`/O2 /GB /Oy- /W3 /GR-` raised the scratch to 86.62%, 144 candidate
instructions, and references `80/0/0`.

The `/Oy-` override is retained because the independently matched executable
copy of this exact function body already carries the same focused profile
evidence, not because of a broad profile search. It removes both apparent
reference conflicts and recovers all 80 referenced destinations. The remaining
mismatch is compiler scheduling and register allocation around the saved-name
loop; it is not missing behavior. No inline assembly, volatile state, dummy
references, forced addresses, or layout-only expressions are used, and the
residual remains compiler-only.

A fresh stock-VC6 matrix confirms the focused override. `/G5`, `/Ob1`, and
explicit `/Ot` are byte-identical when combined with `/Oy-`; removing `/Oy-`
falls to 77.74% with two reference conflicts, and `/G6 /Oy-` falls to 71.83%.
The retained `/O2 /GB /Oy- /W3 /GR-` profile remains the only justified local
configuration and keeps all 80 references exact.

A bounded source-shape sweep then replaced the separate saved-name cursor with
the direct indexed spelling already proven exact in `config_sync_from_grim`.
That natural form raises both byte-identical copies from 636/734 (86.62%) to
641/734 (87.32%), narrows the gap from 98 to 93 bytes, and preserves references
`80/0/0`. Pointer-headed order loops, explicit typed offsets, early index
initialization, and the sibling initializer's alternate memset ordering were
neutral or worse, so none are retained. The remaining residual is still the
one-local native frame versus the compiler's two-local allocation; no register
hints, volatile state, raw offsets, or other coercion is present.

A follow-up cross-profile probe isolated why the native `/Oy` allocation does
not emerge from the current source. Moving the 9-byte name clear to the order
used by exact sibling `config_sync_from_grim` is insufficient on its own. Only
moving that clear and both early one-valued stores across the saved-name loop
frees `EBX`: `/Oy` then emits the native 140 instructions and a 10-instruction
prefix, but reaches only 82.14% with references `65/0/2` because those stores
remain on the wrong side of the loop and the two induction registers are
swapped. The same source falls to 73.94% and `63/0/2` under the retained
`/Oy-` profile.

Register, loop-scoped, post-tested, flattened-index, explicit cursor, typed
offset, and local-reference spellings do not repair that tradeoff; standard
VC6.0, 6.5, and 6.6 backends also emit the same object. The joint ordering
probe is recorded in `experiments.jsonl`, while the canonical shared body and
the stronger 87.32% profile remain unchanged.

A later typed-cursor interaction supersedes that checkpoint. Moving the
9-byte name clear to the order used by exact sibling
`config_sync_from_grim`, traversing `saved_name_order` with an `int *`, and
advancing a typed `char (*)[27]` saved-name cursor in the `strcpy` expression
lets the stock `/O2 /GB /W3 /GR-` profile reach **89.36%**, 142 candidate
versus 140 native instructions, and references `80/0/0`. The same shared body
produces the identical improvement for executable copy
`config_init_defaults`.

Relative to the former retained `/Oy-` result, this recovers 14.96 additional
fuzzy-weighted bytes, reduces the candidate by two instructions, narrows the
gap from 93.04 to 78.09 bytes, preserves complete reference agreement, and
removes the function-local frame-pointer override. The pointer traversal is a
typed presentation of the two contiguous recovered arrays, not a raw-offset
or address-shaped expression.

The remaining residual is still compiler allocation. Native keeps the slot
value in `EBX`, a strength-reduced order offset in `EBP`, and only the
saved-name cursor on the stack. VC6 instead keeps both typed cursors in
callee-saved registers and spills the slot value plus the postincrement's old
name pointer, producing an 8-byte frame. A name cursor alone reached 87.94%
with clean references; the typed order bound supplied the retained gain.
Explicit cursor advances collapse to the older 77.03% allocation, and a
pointer-distance bound grows to 148 instructions and 87.50%. Recovered `bool`
and named-integer field views were byte-neutral, so no speculative type change
is retained.

A recovered field-cursor interaction now supersedes that allocation. Spelling
`ui_info_texts` as the one-byte initialization it is prevents VC6 from sharing
its integer-one value with the later four-byte reserved-field store, leaving
`EBX` available for the saved-name slot index. The order traversal follows the
native byte cursor from `offsetof(crimson_cfg_t, saved_name_order)` up to
`offsetof(crimson_cfg_t, saved_names)` in `sizeof(int)` steps. These are
recovered field boundaries rather than hard-coded offsets, and the shared
implementation passes the matcher fakematch validator.

Stock `/O2 /GB /W3 /GR-` now reaches **99.29%**, the exact native
**140/140** instruction count, and references `83/0/0`. The fuzzy gap falls
from 78.09 to 5.24 bytes, a gain of 72.84 fuzzy-weighted bytes. Executable copy
`config_init_defaults` produces the same result.

Only one scheduler inversion remains: native publishes the saved-name cursor
to its stack slot before loading the `0x88` order offset into `EBP`; available
VC6 backends emit those two independent setup moves in the opposite order.
VC6.0, 6.5, and 6.6 with `/GB`, `/G5`, `/Ob1`, explicit `/Ot`, `/Oa`, and
`/Ow` all tie at the same one-swap result. `/G6`, `/Os`, `/Op`, `/Oy-`, the
processor-pack compiler, and MSVC 7 regress, bounding the residual as compiler
scheduling rather than missing behavior.

`probe_saved_name_schedule.cpp` closes the remaining obvious source-lifetime
escape hatch with a reproducible nine-variant matrix. It moves a raw or typed
saved-name cursor before, between, and after the index and recovered
`saved_name_order` offset initializers, and tests both postincrement and
separate-increment spellings. The raw-pointer forms all fall to **92.53%**,
141 candidate instructions, and references `80/0/0`; the typed array-pointer
forms fall to **90.78%**, 142 instructions, and the same clean references.
None changes the compiler's preferred setup order without perturbing the
otherwise exact body. The canonical direct-index form therefore remains the
honest optimum at 99.29%; all nine negative results are recorded in
`experiments.jsonl`.

The recorded `direct-index-schedule-mutations.json` sweep closes the remaining
fixed-base alternative without changing the canonical source. All **11/11**
variants were evaluated: the direct-index initializer reversal, fixed typed
array bases placed on every side of the index/offset setup, an array reference,
and the equivalent fixed raw bases. Seven variants are byte-identical to the
canonical 99.29% object; the other four keep the same fuzzy score and clean
`83/0/0` references while moving the first mismatch one instruction earlier.

This is a stronger negative result than the advancing-cursor matrix because
the fixed bases preserve the native instruction count and the otherwise exact
loop. VC6 still schedules the independent `0x88` load before the saved-name
base spill. The residual is therefore saturated as a backend scheduling tie,
not a missing source lifetime; larger Grim closure targets should take
priority unless new compiler/TU provenance changes that constraint.

The adjacent-TU hypothesis is now closed as well. `probe_tu_context.cpp`
compiles `grim_config_defaults_init_thunk` immediately after the canonical
initializer under the same VC6 profile. The initializer is byte-identical to
its isolated object: **99.29%**, **140/140** instructions, prefix **21**, and
references **83/0/0**, with the same first mismatch at byte 107. This proves
that merely restoring the observed tail thunk to the translation unit does
not affect the scheduler inversion, so the production TU map should not grow
a no-op cluster for these two functions.

## Exact shared cursor schedule

The executable-side `saved-name-cursor-scheduling-mutations.json` sweep was
repeated after the one-byte `ui_info_texts` correction. A byte cursor
initialized to `saved_names[0]` between the slot-index and order-offset
initializers recovers the native preheader schedule that the older,
pre-correction cursor probes could not produce. Its 27-byte typed advance
preserves every loop instruction and reference.

Because both images include the same recovered body, the retained
`/O2 /GB /W3 /GR-` source now matches this target at **734/734 bytes**,
**140/140 instructions**, and references **83/0/0**. The compiler residual
override has been removed.
