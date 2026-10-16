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

The same boundary now stages `highscore_active_record.score_xp` immediately
after mode logic and before world rendering or bonus pickup. Results consume
that staged player-0 value rather than reconstructing the active record from
the later live player state.

MSVC 6.5 matches all 713 instructions and all 291 references exactly.

The perk-prompt hit test now represents its relative mouse position as a
`vec2f_t` local. Named component assignments and bounds checks replace the raw
two-float array while preserving that complete exact match.

## 1.9.8 (C2 9044)

Exact in both builds. Shared spellings: the run-state globals go through the
original `gameplay_run_state` aggregate (`CRIMSONLAND_USE_ORIGINAL_GAME_OWNER`),
which keeps the weapon-time update an in-place `add [mem], reg` in 1.9.8; the
pulse update is an `if`/`else` of two compound assignments, which hoists the
pulse load above the hover test; and the trial check is `!(x > 5.0f)`, the
`and eax, 0x4100` lowering. All three are byte-identical in 1.9.93.

Behaviour guards: 1.9.8 has no `play_time_get` 40-minute check and instead
ends the trial after 60 minutes of `play_time_ms` (as in
`demo_trial_overlay_render`), and it raises the level to 1.8 in double
precision (`(double)level`, the 1.8f constant widened).
