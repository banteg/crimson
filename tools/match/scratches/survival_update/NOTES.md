# survival_update

High-value recovery for the 2,102-byte Survival-mode coordinator at
`0x00407cd0`.

Live Binary Ninja evidence identifies three coherent responsibilities: two
single-player emergency weapon handouts, level-gated scripted formations, and
the elapsed-time-driven random edge-spawn loop. The source keeps those phases
and their native mutable globals explicit while matching is refined.

The recovered candidate now covers the complete function: the console/demo
gate, both reward handouts, all ten scripted stage transitions, the signed
`500 - elapsed / 1800` wave interval, extra-spawn compensation, and both
four-way edge switches. A short-lived right-edge Y scalar is retained on x87
while X is evaluated, matching both native right-edge cases without an
ordering shim.

The recent-death mean is recovered as a short-lived vector of the same type as
the native three-entry global. Its two `operator+=` calls and component scaling
reproduce the complete native x87 window: X remains live while Y is rounded
through the stack after each addition and after the one-third scale. Live
Binary Ninja disassembly confirms those rounding points and the subsequent
distance/health reward test at `0x00407da5..0x00407e2f`. Both ports now express
the arithmetic through the shared PC=24 helpers; a boundary regression records
the native exact-16 result rejected by the strict radius test.

The current honest VC6.5 result is 98.21% with the exact 504-instruction count
and references `139/0/0`. The sole mismatch is the first three scripted spawn
calls. Native reuses the dead centroid slot at `[esp+0x10..0x14]`; this natural
separate-scope source assigns that spawn vector to `[esp+0x18..0x1c]`, then
realigns with native from stage 2 onward. A shared vector recovers the native
slot but forces VC6.5 to materialize centroid X, while returned-vector chains,
independent scalars, and alternate lexical scopes all produce less plausible
or materially worse code. The residual is recorded rather than hidden with a
union, volatile state, alias tricks, dummy expressions, or artificial
dependencies.

The random edge-spawn phase now passes each stack position as a complete
`const vec2f_t *` to the shared `survival_spawn_creature` contract rather than
taking the address of its first float member. Binary Ninja confirms that
prototype at `0x00407510` and identifies the stack locals as vector aggregates.
The change preserves the honest 98.21% score, exact 504-instruction count, and
all 139 references.

The recent-death reward distance now also reads player zero through
`player_state_t::position`. The aggregate field spelling is byte-neutral at
98.21%, 504/504 instructions, a 102-instruction prefix, and 139/0/0
references.

## Recorded centroid/spawn lifetime search

`centroid-spawn-lifetime-mutations.json` exhaustively evaluated 79 single,
pair, and triple lifetime combinations spanning shared versus dedicated outer
vectors, centroid representations, and the first scripted spawn temporary.
No valid variant improved the 98.21% baseline: natural shared/dedicated and
renamed forms are byte-neutral, while scalar/plain forms regress or fail to
compile when combined incompatibly (spec
`90ba4a354d983edcc00f75723e265e90a7744a3f08bc9ad34a93ac99e1616eac`).
The full result, including compile-invalid interactions, is recorded in
`experiments.jsonl`.

`function-scope-spawn-vector-mutations.json` separately tests two canonical
function-scope declarations and their interaction with the first scripted
stage. Declarations alone are byte-neutral; actually routing the spawn through
either long-lived vector regresses to 83.33%. The native stack-slot reuse is
therefore not evidence for extending the vector's semantic lifetime.

## Recovery classification audit

The focused diff has the exact native 504-instruction count and confines every
remaining mismatch to the first three scripted spawn calls. Live Binary Ninja
identifies the same `vec2f_t` call arguments and shows native reusing the dead
centroid slot; the natural separate-scope source uses a later stack slot, then
realigns for all remaining stages and both random edge-spawn loops. No
condition, formation, RNG call, coordinate, or reference is absent.

Classification is `RECOVERY=semantic-complete`, `RESIDUAL=compiler`. Before
and after classification remain 98.21%, prefix 102/504, 504/504
instructions, and references 139/0/0.

`scripted-spawn-inline-helper-mutations.json` tests three inline/force-inline
coordinate helpers and their interaction with the first three scripted
spawns. Helper definitions alone are neutral, but every complete helper use
falls to 83.33% and moves the first mismatch into the prologue while retaining
the 504-instruction count and all 139 references. Inlining a helper local does
not reproduce native reuse of the dead centroid slot, so no source change is
retained.

## Original vector type replay (2026-08-14)

The authenticated MOD SDK `vec2_t` adds an empty default constructor, a scalar
constructor, and union-backed component/array storage to the same two-float
value used by the game. `original-vector-type-mutations.json` replays the four
default/scalar and plain/union combinations against the current stack-coloring
residual. Every form is byte-identical at 98.21%, 504/504 instructions, prefix
102, and `139/0/0` references. The native reuse of the dead centroid slot is
therefore not controlled by those original type declarations. No source change
is retained. The spec SHA-256 is
`95f8382be19a7b54ec4338b0927e914e458bbc3926aff6bdcc3b7eac994e60d5`.

## Batch 04 focused value boundaries (2026-09-05)

`batch-04-focused-value-boundaries-mutations.json` records 3 complete, compiling
controls against the 98.214286% baseline. The source forms are
`first-wave-pod-identity`, `first-wave-local-class`, `centroid-aggregate-copy`.

No control improves the retained baseline without a metric tradeoff. Canonical source
and configuration are unchanged. These results bound the recorded hypothesis, not the
function's matchability.

## UI storage follow-up (2026-09-05)

Crossed first-stage/call-local coordinates with centroid sum, scale, and distance value
forms. Shorter stage owners rotate the surrounding stack layout; the original compound
scale is neutral. No form preserves the exact prefix while recovering the first three
native spawn slots.

ui-storage-followup-controls-mutations.json records 16 complete, compiling controls.
These results bound the tested source forms and inputs; they do not establish that
matching is impossible.
