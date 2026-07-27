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
