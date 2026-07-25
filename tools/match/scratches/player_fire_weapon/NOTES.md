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

MSVC 6.5 currently produces 378 instructions against the native 378 at an
86.77% match, with all 141 masked references resolved and no mismatches. The
remaining broad delta is localized to two honest code-generation differences:
the native reuses the same four stack floats with opposite position/velocity
roles between its two sprite calls, while the straightforward two-vector C++
keeps each vector in one stable slot; and VC6 schedules the second fire-ready
flag's zero initialization later than the native. Separate scoped vectors grow
the frame, while scalar locals lose the required adjacent-vector semantics, so
this scratch intentionally does not use a layout-only array or other artificial
constraint to improve the score.

The two muzzle-sprite calls now expose their position and velocity arguments as
read-only vector aggregates at the shared `fx_spawn_sprite` boundary. This
keeps the same honest 86.7725% score, exact 378-instruction count, and all 141
references.

Those two stack values now use canonical `vec2f_t` storage directly, and the
repeated player-position cursor points at `player_state_t::position`. This
removes five layout casts without changing the honest WIP result.

The shotgun pellet update now names the flat projectile
`fields.speed_scale` member instead of traversing the matching-only
`pos.tail.vy` cursor overlay. This source cleanup is byte-neutral: the
candidate remains 378/378 instructions at 86.77% with all 141 references.

The player-state accesses now also use the recovered `movement`, `aim`, and
`position` vector members, and the muzzle sprites use their recovered color
aggregate. These are source-shape improvements rather than score claims: VC6
emits the same 378 instructions at 86.7725%, with all 141 references still
resolved. An explicit byte-local experiment did not move the second readiness
initialization to the native location, so the semantically appropriate `bool`
locals remain.

The final terrain clamp now addresses the selected player's canonical
`position.x/y` fields directly. This removes the last scalar position aliases
from the function without changing its 86.77%, 378/378-instruction, 141/0/0
result.
