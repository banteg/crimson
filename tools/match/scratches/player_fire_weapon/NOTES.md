# `player_fire_weapon`

Native target: `crimsonland.exe` at `0x00444980` (1,518 bytes).

Despite the legacy name and decompiler prototype, stack accesses prove this is
the bespoke Typ-o Shooter player frame/firing routine with three arguments:
an aim-point pointer, a fire-request byte, and a reload-request byte. It tops up
the equipped shotgun every frame, copies the submitted creature position into
the player's aim point, emits the muzzle sprites and twelve jittered shotgun
projectiles when firing, applies perk-dependent spread/cooldown rules, wraps the
movement phase, and clamps the player to the terrain bounds.

The signature and source are grounded in the live Binary Ninja disassembly.
The port already mirrors the Typ-o frame reset and command-to-aim/fire/reload
policy in `src/crimson/typo/player.py` and `src/crimson/typo/runtime.py`.

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
