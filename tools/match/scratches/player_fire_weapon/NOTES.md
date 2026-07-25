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
95.24% match, with a 174-instruction exact prefix and all 141 masked references
resolved. Declaring the perk-assisted readiness flag after aim computation but
before the normal-readiness test reproduces the native zero-store schedule and
raises the score from 86.77% without changing behavior or instruction count.
The remaining delta is localized to one honest code-generation difference:
the native reuses the same four stack floats with opposite position/velocity
roles between its two sprite calls, while the straightforward two-vector C++
keeps each vector in one stable slot. Separate scoped vectors grow the frame,
while scalar locals lose the required adjacent-vector semantics, so this
scratch intentionally does not use a layout-only array or other artificial
constraint to improve the score.

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
