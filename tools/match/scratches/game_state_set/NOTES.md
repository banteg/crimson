# `game_state_set`

Native target: `crimsonland.exe` at `0x004461c0` (1854 bytes).

Live Binary Ninja and the audited UI data map recover the central state-entry
dispatcher. It resets transient UI state, records the previous/current state,
flushes input, configures the active UI elements and callbacks for every menu
state, initializes gameplay mode counters, and seeds the shared transition
timeline.

The main-menu path uses four temporary two-float atlas coordinates per branch
to retarget six menu elements into the item-text texture. That aggregate shape
is supported by the native 0x50-byte frame and its four 0x1c-stride XY copies;
the two config branches deliberately remain separate because the non-wide path
remaps the perk-selection row.

Those 0x1c-stride destinations are now recovered in the canonical
`ui_element_t` as the first four records of an eight-entry `overlay_vertices`
bank. The dispatcher writes each vertex's `u`/`v` pair at offsets `0x138`,
`0x154`, `0x170`, and `0x18c` and assigns the following texture handle at
`0x204`. This removes the former 0x208-byte partial UI mirror while preserving
the result below byte-for-byte. The same shared fields are consumed by
`ui_element_render`, independently confirming the full vertex interpretation
rather than a UV-only padding view.

Current MSVC 6.5 `/O2 /GB` result: **85.35%**, with an exact **166/399**
instruction prefix, 399 native instructions versus 393 candidate instructions,
the exact 0x50-byte frame, and reference audit **162 resolved / 0 unresolved /
0 mismatched**. Keeping the requested state in EBP and a distinct local atlas
row reproduces the native EBP/ESI/EDI allocation and raised the match from the
initial 46.26% switch-shaped reconstruction.

The remaining six-instruction size deficit is localized to the final two
game-mode counter branches. Native VC6 repeats a load/flag/increment/flag/store
sequence for both typo mode and the fallback mode; compiling the equivalent
plausible if/else source tail-folds their common flag stores and uses direct
memory increments. The controls-menu Vec2 assignment also has one independent
store-scheduling difference. No fake dependencies, volatile qualifiers, dead
expressions, or register constraints are used to defeat those optimizations.

The zero written at `0x00487260` on game-over entry is now represented by the
conservative address-derived name `data_487260`. Binary Ninja finds no other
code or data xrefs, so the shared data map records only the proven 32-bit
location and single write, without assigning an unsupported gameplay meaning.
That evidence closes the former unresolved reference while keeping the native
address explicit.

Both main-menu width checks now use the recovered
`grim_config_value_t::operator bool()` instead of manually reinterpreting the
first byte of the returned value object. The source shape matches the already
exact UI layout caller and leaves the `85.35%`, `166/399` prefix, and
`162/0/0` reference audit unchanged.

Binary Ninja now receives an equivalent union-free `ui_element_binja_t`
presentation record for this analysis path. It verifies the full `0x318` size
and exposes the texture store as `overlay_texture_handle` instead of the
misleading `layers[1].texture_handle` union alias. The optimizer still splits
the four UV destinations into transient `void *` SSA register values, so their
remaining `+0x138`, `+0x154`, `+0x170`, and `+0x18c` renderings are decompiler
artifacts, not unrecovered fields. Temporarily wrapping the object in another
aggregate does not preserve those register types. The matching result remains
unchanged.

The global UI graph is now imported as its evidenced
`ui_element_t *[41]` extent instead of 41 unrelated pointer data variables.
This recovers indexed `ui_element_table_end[index]` accesses in the dispatcher
and preserves every interior slot symbol/comment. The remaining transient
atlas destinations still render as `void * + offset` only after Binary Ninja
copies a typed element pointer into short-lived SSA registers; the owning
object and all four destination fields are typed above.

The importer now also persists `ui_element_t *` on the seven distinct MLIL
variables defined by those compiler-generated reloads. Binary Ninja therefore
renders both branches as named `overlay_vertices[0..3].u/v` writes, including
the shared fourth-vertex phi, instead of falling back to
`void * + 0x138..0x190`. This is presentation-only type recovery; it does not
alter the matching scratch or the **85.35%**, `166/399`, `162/0/0` result.

The Play Game and Controls entry arms now address slot 13 through the
canonical `ui_element_t::pos` aggregate for their initial vector copy and
subsequent x/y adjustments. The existing local vector-class cast remains only
at the class-assignment boundary. This source cleanup is byte-neutral at
85.35%, 393/399 instructions, a 166-instruction prefix, and `162/0/0`
references.

## Recorded mode-tail audit

Two complete mutation sweeps record 11 source-equivalent challenges to the
six-instruction final-mode deficit. `mode-tail-sequencing-mutations.json`
covers nested and inverted final arms, a copied mode, counter pointer/reference
aliases, a status pointer, an explicit final condition, and an explicit join.
`mode-counter-scope-mutations.json` adds shared signed/unsigned counters and
guarded mode blocks. Every variant compiles byte-for-byte identically to the
baseline. This bounds ordinary CFG and local-lifetime spelling as explanations
for VC6's native repeated load/flag/increment/flag/store sequence; no artificial
dependency is justified.

`mode-counter-helper-interactions-mutations.json` closes the remaining natural
source-boundary hypothesis. The complete 19-variant sweep crosses three
return-value helper bodies (`__inline`, `__forceinline`, and a named result)
with four call placements: the final two arms, all four counters, Typ-o only,
and the default arm only. All 12 valid two-site interactions are byte-for-byte
identical to the baseline; the four call-only variants fail as expected because
the helper is absent. An ordinary inlined lifecycle helper therefore does not
inhibit VC6's final-arm tail folding, so the six-instruction deficit remains a
bounded compiler residual.

## Mode-dispatch and UI-latch stopping audit

The recovered `Crimson.h` identifies the flattened UI state members behind
this dispatcher as one-byte `bool` fields and the persisted play counters as
signed `int` fields. `ui-latch-type-mutations.json` tests all seven local
latch declarations independently as `bool`; every variant is byte-identical
to the `85.35%`, 393/399-instruction, `162/0/0` baseline. A separate signed
branch-local counter spelling is likewise byte-neutral. The declaration types
therefore do not account for the final mode-tail cross-jump.

`mode-dispatch-source-shape-mutations.json` also tests the previously
unexamined full-switch family. VC6 emits a dense jump table for both complete
switch variants. That shape is contradicted by the native comparison chain,
even though the matcher assigns it 5.35 additional fuzzy-weighted bytes and
six more aligned references. The switch is intentionally not retained:
localized disassembly is stronger source evidence than the incidental
alignment score.

Finally, `controls-position-store-order-mutations.json` tests all four scalar
orders for the Controls panel's `(-180, 139)` position and sign activation.
Every scalar form shortens the candidate to 388 instructions, loses 22.93
fuzzy-weighted bytes, and changes the audit to `156/0/3`. The aggregate
assignment remains the only reference-clean natural form. Together these
complete sweeps leave the six-instruction Typ-o/default cross-jump as an
honest compiler residual rather than an untested source-shape lead.

## Current recovered-type replay (2026-08-12)

The recorded mode-tail experiments predated the latest shared identity and UI
type recovery, so their compiler conclusions were replayed against the current
source. Fresh regions confirm that the only instruction-count difference is
still the six-instruction Typ-o/default counter tail; almost every later region
is a branch-displacement consequence. The Controls aggregate has one separate
store-order mismatch.

Five current sweeps cover 58 compile-valid variants. All eight mode-tail CFG,
copy, pointer, reference, and join forms; all three counter-scope forms; all 28
one- and two-latch `bool` interactions; and all 15 valid inline-helper forms
remain byte-identical at 85.35%, 393/399 instructions, prefix 166, and
`162/0/0` references. The four helper-call controls without a definition fail
as expected. All four Controls scalar store orders still regress to 84.12%,
388/399 instructions, and `156/0/3` references.

The recovered shared types therefore do not reopen the older source-shape
hypotheses. The aggregate Controls assignment remains canonical, and the final
mode arms remain bounded tail-folding debt without an honest source change.

## Exact counter and Controls sequencing recovery (2026-09-05)

Current result: **100%**, 399/399 instructions, full prefix, and references
**169 resolved / 0 unresolved / 0 mismatched**. The compiler-residual conclusions
above are superseded by `direct-counter-controls-mutations.json`.

The four non-quest modes now increment their persisted counters directly before
setting the render and transition latches. The previous reconstruction split
those increments into local loads, increments, and stores interleaved with the
latches. That spelling caused the six-instruction final-branch tail fold; the
ordinary direct increment reproduces the native load/store sequence and raises
matching to 99.75%. Applying it only to the final two modes gives identical
bytes. Moving the increment between latches is a negative reference-audit control.

The Controls arm activates the sign before assigning the panel's position
aggregate. This independently restores the remaining interleaved store order;
combined with the direct counters it matches the complete native function.
No compiler flags, types, branch-layout directives, or artificial dependencies
were changed. All five recorded variants compile and the retained combination
has no reference debt.
