# `gameplay_update_and_render`

Native target: `crimsonland.exe` at `0x0040aab0` (2,840 bytes).

This is the core per-frame gameplay coordinator. It applies Reflex Boost time
scaling, freezes simulation for pause/shareware limits, advances perks,
effects, creatures, projectiles, players, mode logic, bonuses, camera, world,
tutorial, HUD, and UI, and drives death, level-up, perk-prompt, trial-overlay,
pause-help, and cursor transitions.

Binary Ninja control flow established two easy-to-miss native behaviors:

- attract/demo playback bypasses the pause/shareware frame freeze;
- the shareware quest limit combines sequence time, elapsed minutes, and quest
  progress, while non-quest modes lock as soon as elapsed trial time is
  positive.

The native level threshold uses the promoted `1.8f` exponent and a float
`-1000.0f` multiplier. An array-element C++ reference preserves VC6's in-place
weapon-time update, and direct compound assignments preserve its pause-help
fade arithmetic. These are natural source shapes, not volatile, dead-code,
register, or assembly constraints.

The deterministic Python and Zig coordinators retain the adjacent core state
mutation directly: after player and mode updates, player 0's current weapon
receives `frame_dt_ms` in the native 64-slot `unsigned int` time table. This
happens before `gameplay_render_world` and ordinary bonus pickup, so a newly
collected weapon begins accumulating on the next frame. High-score finalization
uses this table instead of the former per-weapon shot-count heuristic.

MSVC 6.5 matches all 713 instructions and all 291 references exactly.
