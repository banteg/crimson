# `player_fire_weapon`

Native target: `crimsonland.exe` at `0x00444980` (1,518 bytes).

Despite the legacy name, stack accesses prove this is the bespoke Typ-o Shooter
player frame/firing routine with three arguments: a typed two-float aim-point
pointer, a fire-request byte, and a reload-request byte. Binary Ninja previously
modeled only the two bytes and discarded the leading pointer; the sole native
callsite pushes all three, and the corrected prototype now exposes
`&typo_target_world` in the caller. The routine tops up the equipped shotgun
every frame, copies the submitted creature position into the player's aim
point, emits the muzzle sprites and twelve jittered shotgun projectiles when
firing, applies perk-dependent spread/cooldown rules, wraps the movement phase,
and clamps the player to the terrain bounds.

The signature and source are grounded in the live Binary Ninja disassembly.
The authoritative name map now persists the leading argument as
`const vec2f_t *`, preventing map replay from degrading the recovered
two-float aim aggregate back to `float *`.
The ports mirror the Typ-o frame reset and command-to-aim/fire/reload policy in
`src/crimson/typo/player.py`, `src/crimson/typo/runtime.py`, and
`crimson-zig/src/typo/player.zig`. Both now retain the native Shotgun weapon id
3; Sawed-off Shotgun id 4 has distinct ordinary-runtime recipes and is not the
mode loadout.

MSVC 6.5 currently produces 378 instructions against the native 378 at a
99.21% match, with a 245-instruction exact prefix, a 12.05-byte fuzzy gap, and
all 142 masked references resolved. Declaring the perk-assisted readiness flag
after aim computation but before the normal-readiness test reproduces the
native zero-store schedule and first raised the score from 86.77% to 95.24%
without changing behavior or instruction count.

The native reuses the same four stack floats with opposite position/velocity
roles between its two sprite calls. Expressing that reuse directly recovers the
native argument slots. The forced-inline `typo_fire_vec_add` helper computes
both component sums before storing the canonical `vec2f_t`, reproducing the
native x87 staging while retaining adjacent-vector semantics. Together these
natural source boundaries raise the result from 95.24% to 99.21%.

The remaining delta is three stack-slot operands in the pellet-position loop:
the native writes the same two component sums at `[esp+0x20]` and
`[esp+0x24]`, while VC6 assigns the candidate `[esp+0x18]` and `[esp+0x1c]`,
then passes that equivalent vector to the same projectile call. A separately
scoped projectile vector regresses the frame and score, so the scratch retains
the better semantic source rather than using a layout-only array, union,
volatile state, or another artificial allocation constraint.

The two muzzle-sprite calls expose their position and velocity arguments as
read-only vector aggregates at the shared `fx_spawn_sprite` boundary.

Those two stack values use canonical `vec2f_t` storage directly, and the
repeated player-position cursor points at `player_state_t::position`.

The shotgun pellet update now names the flat projectile
`fields.speed_scale` member instead of traversing the matching-only
`pos.tail.vy` cursor overlay.

The player-state accesses now also use the recovered `movement`, `aim`, and
`position` vector members, and the muzzle sprites use their recovered color
aggregate. The readiness values remain semantically appropriate `bool` locals;
only the declaration boundary needed correction to reproduce native
scheduling.

The final terrain clamp now addresses the selected player's canonical
`position.x/y` fields directly. This removes the last scalar position aliases
from the function.

## Recorded shotgun-local sweep

`shotgun-vector-slot-mutations.json` evaluated five declaration and heading
orders around the shotgun vector. Swapping the declarations was byte-neutral
and the heading reorders regressed, so none supplied evidence for changing the
recovered source. The stack-coloring residual remains explicit.

`pellet-vector-reuse-mutations.json` also tested reusing the existing
effect-position aggregate for each pellet. It regresses 99.21% to 96.03%, so
the dedicated semantic projectile vector is retained.

`pellet-position-lifetime-mutations.json` records three further dedicated
pellet-position lifetimes. Outer- and loop-scoped canonical vectors both
regress to 90.21%, and explicit component stores regress to 89.42%, while
retaining the 378-instruction count and 142 resolved references. The existing
adjacent-vector expression remains the strongest source evidence despite its
two stack-slot operand differences.

## Pellet-slot ownership interaction audit

Fresh native stack data flow proves the two sprite calls use
`effect_velocity` at the lower vector slot and `effect_position` at the upper
slot, then the pellet loop writes and passes the upper slot. The current
99.21% candidate instead colors the pellet result into the lower slot. That
made the previously tested direct `effect_position` reuse worth crossing with
the declaration lifetime rather than treating the three operand differences
as arbitrary stack offsets.

`pellet-position-owner-interaction-mutations.json` evaluates all 23 single and
paired combinations of five declaration schedules and direct, reference, and
pointer ownership of the upper slot. Every declaration schedule is
byte-neutral alone. Every upper-slot owner, alone or paired, produces the same
96.03% object and moves the first mismatch 71 instructions earlier.

`pellet-position-scope-coloring-mutations.json` then tests a disjoint lexical
scope for the two sprite vectors followed by an outer or loop-local pellet
vector. The corrected complete variants also give the pellet loop its own
player-position alias, so no out-of-scope variable is being relied on. The
best complete forms reach only 96.83%; the outer pellet forms fall to 90.21%.
Thus neither extending the native upper-slot owner nor asking VC6 to color a
new disjoint-lifetime aggregate preserves the otherwise exact allocation.
The canonical two-vector source remains the honest optimum, and both complete
interaction matrices are recorded in `experiments.jsonl`.

## Current-baseline pellet allocation probes (2026-08-11)

`predeclared-pellet-vector-mutations.json` tests the missing third-local
interaction: a dedicated pellet vector declared before, between, or after the
two sprite vectors. All three forms fall to 90.21%, so declaration order does
not color a disjoint pellet value into the native upper slot.

`vector-helper-parameter-ownership-mutations.json` tests pointer and reference
ownership for every parameter of the forced-inline vector helper. All four
forms are byte-identical to the retained 99.21% object. The residual is not
hidden in the helper's source-level parameter ownership.

## Vector result-ownership bound (2026-08-12)

The remaining untested helper boundary was return-value ownership.
`vector-helper-result-ownership-mutations.json` adds two ordinary forced-inline
helpers that return a named `vec2f_t`, preserving the native Y-then-X
calculation order, and tests their use at the first sprite, second sprite, and
pellet call sites in every one- through four-site combination.

Both unused return helpers optimize away and leave the 99.21% baseline
byte-identical. Every actual return-value assignment is a decisive regression:
pellet-only forms fall to 87.11%--87.89%, other partial uses fall as low as
81.94%, and using the returned vector at all three sites falls to
79.69%--81.25% with two reference mismatches in the worst forms. All move the
first mismatch from instruction 245 to the prologue. Across 16 compile-valid
variants, no returned aggregate preserves the native frame or existing exact
prefix. The destination-writing helper remains the strongest natural source,
and the three pellet stack operands remain a compiler coloring residual.

## Original vector type replay (2026-08-14)

The exact MOD SDK union storage and assignment-body scalar constructor were
replayed independently and together in
`original-vector-type-mutations.json`. All three variants are byte-identical at
99.21%, 378/378 instructions, prefix 245, and `142/0/0` references. Neither
authenticated type spelling changes the pellet result's stack color, so no
source edit is retained. The spec SHA-256 is
`164c7a7dc645c3dcd7a8516cad1b74b7c76a375fa19f3130e0bc5b9cde29be24`.

## Original shotgun vector identity replay (2026-08-14)

The recovered shotgun helper result and its local vector objects were replayed
with their original class identity while preserving the flattened C ABI at
the three external call boundaries. The valid complete transfer is
byte-identical at 99.21%, 378/378 instructions, prefix 245, and `142/0/0`
references, so class identity does not alter the remaining pellet stack color.

An earlier invalid plan attempted to redeclare the existing C-linkage sprite
function with class-pointer parameters and produced C2733. That failed record
is explicitly paired with a `mutation-error-audit`; the corrected spec casts
only at the recovered flattened-header boundary. No source edit is retained.
Spec SHA-256 is
`e11e5c09656ca8befe7f1bd1be143d33ff4ae1ca40c31871e9fa8f1058398815`.

## Batch 04 focused value boundaries (2026-09-05)

`batch-04-focused-value-boundaries-mutations.json` records 3 complete, compiling
controls against the 99.206349% baseline. The source forms are `effect-motion-pair`,
`effect-motion-position-first`, `pellet-coordinate-scalar-publication`.

No control improves the retained baseline without a metric tradeoff. Canonical source
and configuration are unchanged. These results bound the recorded hypothesis, not the
function's matchability.
