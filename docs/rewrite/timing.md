---
tags:
  - rewrite
  - parity
---

# Timing domains and mode scheduling

Crimsonland Classic 1.9.93 uses a variable frame delta, several accumulated
clocks, and mode-specific scheduling rules. Movement usually consumes float
seconds; spawning, scoring, and scripted transitions often consume truncated
integer milliseconds. A periodic spawn interval is not a fixed simulation step.

The Python port preserves many of these consumers inside a shared deterministic
session, but live play supplies fixed 60 Hz ticks. Native behavior and current
Python behavior are distinguished below; sharing a helper does not establish
native parity for every mode.

This reference comes from the recovered C/C++ and Python source. Every native
function it describes is an exact match, as is all of the game and engine code;
see `tools/match/STATUS.md` for evidence status. This page does not claim a new
native runtime comparison.

For conversion and precision rules, see [delta-time parity](parity/delta-time.md)
and [float policy](float-parity-policy.md). For execution ownership, see the
[deterministic session](deterministic-step-pipeline.md).

## Native clocks and deltas

| Domain | Producer and behavior | Consumers |
| --- | --- | --- |
| Engine elapsed milliseconds | `grim_timing_update` samples `timeGetTime()`, waiting until more than 1 ms has elapsed. It advances `grim_time_ms` only when engine timing is not frozen. | Engine elapsed-time API. |
| Engine frame seconds | `grim_frame_dt = elapsed_ms * 0.001f`; engine freeze makes it zero. The getter caps the game-facing delta at `0.1f`. | Game frame input; engine key-repeat timers use the internal, uncapped delta. |
| Outer game delta | `game_frame_update` reads the capped delta, then applies `0.9f` for the Reflex Boosted perk during active ordinary gameplay. | `game_time_s`, screen fades, the saved `frame_dt_copy`, and the initial integer cadence. |
| World simulation delta | `gameplay_update_and_render` applies the Reflex Boost bonus scale and gameplay zero gates. | Creatures, projectiles, effects, mode scheduling, and many bonus timers. |
| Player movement delta | Part of `player_update` temporarily applies `0.6f / time_scale_factor`, then restores the world delta through another arithmetic sequence. | Movement/turning within that window; earlier player timers and later weapon/reload work use the world-domain delta. |
| Restored outer delta | The gameplay coordinator restores its entry delta before the perk prompt, HUD, and UI updates. | UI transitions and pause-help fades can advance while gameplay is paused. |
| Saved audio/console delta | `frame_dt_copy` is saved before the console zero gate and gameplay bonus scaling. | SFX cooldowns and console open/close animation. It still includes the outer Reflex Boosted perk scale. |

Native sources:

- `decomp/1.9/grim/timing/init.cpp`,
  `decomp/1.9/grim/timing/update.cpp`, and
  `decomp/1.9/grim/timing/get_frame_dt.cpp`.
- `decomp/1.9/grim/app/run_loop.cpp` for input timing and frame dispatch.
- `decomp/1.9/crimsonland/game/game_frame_update.cpp`,
  `decomp/1.9/crimsonland/game/gameplay_update_and_render.cpp`, and
  `decomp/1.9/crimsonland/gameplay/player_update_heading.cpp` for delta mutation order.
- `decomp/1.9/crimsonland/audio/audio_update.cpp` and
  `decomp/1.9/crimsonland/console/console_update.cpp` for saved-delta consumers.

### Slow motion is layered

The Reflex Boosted **perk** and Reflex Boost **bonus** are separate transforms:

1. The outer loop applies the perk's `0.9f` multiplier.
2. At gameplay entry, an already-active bonus latch applies a factor of `0.3f`.
   If the bonus timer is below one second, the factor is
   `(1 - timer) * 0.7f + 0.3f` instead.
3. Player movement temporarily cancels that factor and substitutes `0.6f`.
   At full slowdown, movement therefore gets approximately twice the world's
   delta. The outer perk multiplier still applies to both.
4. After movement, native restores the delta with
   `time_scale_factor * movement_dt * 1.6666666f`. This arithmetic round trip
   can differ from restoring a saved float bit-for-bit.
5. The bonus latch is updated later in the frame. Entry state, timer decrement,
   and pickups must retain their order; recomputing the latch eagerly changes
   which frame first sees the slowdown.

The final bonus timer-second itself counts down in simulation time, so its
easing window is not necessarily one wall-clock second.

### Seconds and milliseconds can disagree

`frame_dt_ms` is derived by truncating `frame_dt * 1000`, with native float
precision. It is not an independent high-resolution clock and there is no
fractional-millisecond carry between these conversions. A supplied `1/60`
second tick produces 16 ms; 60 such additions produce 960 ms even though the
seconds-domain deltas total approximately one second. Native engine sampling
starts with integer milliseconds, so this example describes a supplied 60 Hz
delta, not a claim that every native frame measures exactly `1/60` second.

The globals are also mutated at different points. Opening the console zeros
`frame_dt` after `frame_dt_ms` and `frame_dt_copy` have been saved. Individual
consumers add their own console guards. `game_time_ms` is advanced before the
current frame's integer delta is derived, whereas `game_time_s` advances later
from the current outer float delta. They are not interchangeable representations
of one canonical timestamp.

Engine freeze, gameplay pause, the console, and leaving the gameplay state are
therefore distinct controls. In ordinary non-demo gameplay, pause zeros both
simulation deltas; the outer delta is subsequently restored for UI. These
details are visible in the two frame coordinators above.

## Mode scheduling in the original

Survival, Rush, Quest, and Tutorial all run inside
`gameplay_update_and_render`. Survival/Rush/Quest mode updates execute after
players and before the shared elapsed-time accounting; Tutorial's script runs
after world rendering but before the outer delta is restored. Typo has its own
coordinator.

| Mode | Scheduling policy | Clock and gates |
| --- | --- | --- |
| Survival | Decrement spawn cooldown by `frame_dt_ms * player_count`; catch up with `while (cooldown < 0)`. The base interval is `500 - run_elapsed_ms / 1800`; the late-game negative-interval path emits additional spawns, and the eventual interval is clamped to at least 1 ms. Separate milestone waves depend on player level. | Simulation milliseconds; returns immediately when the console is open. Spawn difficulty reads elapsed time before this frame's shared elapsed increment. |
| Rush | Same cooldown subtraction and catch-up condition, adding 250 ms per wave. Each wave creates two creatures. More players consume the cooldown faster. | Simulation milliseconds from the shared coordinator; console guard. The fixed 250 ms spawn interval does not make Rush fixed-step. |
| Quest | Advance an authored spawn timeline while creatures or queued spawns remain. Dispatch when `trigger_time_ms < timeline`; the no-creatures stall path can release a pending wave after more than 3000 ms, provided the timeline exceeds 1700 ms. Completion has a separate timer and sound/transition thresholds. | Simulation milliseconds. Timeline/banner advancement has console and render-pass guards, but the dispatcher and completion path are called outside that guard. Do not assume every quest timer has the same pause/console policy. |
| Tutorial | Accumulate stage and transition timers, while movement, firing, pickups, and perk actions also gate progression. Prompt and hint fades consume integer milliseconds. | Simulation milliseconds; console guard. Tutorial instructional overlays can slow with the world, unlike the later ordinary HUD/UI pass. |
| Typo Shooter | Subtract `frame_dt_ms * player_count`; on a spawn, add `3500 - run_elapsed_ms / 800`, then clamp the remaining cooldown to at least 100 ms. That makes at most one two-creature wave per update, even with an overdue cooldown. | Its own coordinator's integer cadence, without perk/bonus slowdown in normal play. Console blocks cooldown subtraction and elapsed accounting. It calls weapon firing directly rather than ordinary `player_update`. |

Native mode sources are under `decomp/1.9/crimsonland/`:

- `game/survival_update.cpp` and `game/rush_mode_update.cpp`.
- `game/quest_mode_update.cpp` and `quests/quest_spawn_timeline_update.cpp`.
- `game/tutorial_timeline_update.cpp`.
- `typo/typo_gameplay_update_and_render.cpp`.

### Typo's residual slow-motion branch is not a gameplay feature

Normal Typo play has no perk progression or collectible bonuses. A fresh Typo
run enters through `game_state_set` and calls `gameplay_reset_state`, which
clears pending perks, the Reflex Boost timer, and the time-scale latch. The Typo
coordinator has no ordinary level-up/perk-selection or bonus-pickup update; it
clears the Reflex Boost timer/latch when the console is closed and removes all
bonus-pool entries every frame. The outer `0.9f` perk transform also requires
`GAME_STATE_GAMEPLAY`, excluding `GAME_STATE_TYPO_GAMEPLAY`.

There is still a conditional `0.3f` branch and a call to `perks_update_effects`
before it in the recovered Typo coordinator. These are residual shared-state
code, not evidence of obtainable slow motion in this mode. The branch has no
final-second easing, but that difference matters only if an active latch is
introduced outside the normal mode flow. The practical timing distinction in
Typo is its spawn/debt policy, not an alternative slow-motion mechanic.

Entry/reset evidence: `decomp/1.9/crimsonland/ui_elements/game_state_set.cpp` and
`decomp/1.9/crimsonland/gameplay/gameplay_reset_state.cpp`.

### Run time, playtime, and score

The normal coordinator accumulates survival elapsed milliseconds and weapon-use
milliseconds from the simulation cadence, guarded by console/pause state.
Quest's spawn timeline is separately gated by remaining encounter work.

Outer-frame `play_time_ms` and demo-trial accounting run before the `0.9f` perk
transform. `time_played_ms` runs after that transform but before gameplay bonus
scaling, and excludes Tutorial. Their eligibility guards also differ. They
should not be used as substitutes for survival time or the quest timeline.

Quest results further transform the timeline into a score by subtracting life
and unpicked-perk bonuses. That final time is a scoring value, not another clock.
See `decomp/1.9/crimsonland/end_screens/quest_results_screen_update.cpp` and the Python
counterpart `src/crimson/quests/results.py` (`compute_quest_final_time`).

## Python port counterparts

### Scheduling and explicit timing values

`src/crimson/modes/base_gameplay_mode.py` supplies live ticks through
`FixedStepClock` in `src/crimson/sim/clock.py`. The default tick rate is 60 Hz;
the clock caps an incoming render-frame duration at 100 ms, accumulates the
remainder, and can request multiple simulation ticks per render frame. This
differs from native's single variable-delta callback and capped game-facing
delta. Each granted tick is built by `LiveTickSource` in
`src/crimson/replay/ticks.py`, recorded, then stepped. Once the run ends (or Esc
asks for the pause menu) the world keeps ticking while the gameplay timeline runs
down by each tick's simulated milliseconds; the frame stops when that run-down is
over and the mode leaves gameplay, or when a mode callback ends the batch.

Replay execution reaches the same session through
`src/crimson/replay/driver/playback_driver.py`; playback pacing is separate from
the delta supplied to each session tick. See [deterministic session](deterministic-step-pipeline.md)
for the input/presentation boundary.

`src/crimson/sim/timing.py` makes the domains explicit:

| Python value/helper | Meaning |
| --- | --- |
| `FrameTiming.dt` / `dt_ms_i32` | Input tick delta and its truncated milliseconds, before optional outer perk transformation. “Raw” here means session input, not Windows wall time. |
| `FrameTiming.dt_sim` / `dt_sim_ms_i32` | World delta after optional perk transformation, bonus scaling, and zero gate. |
| `FrameTiming.dt_audio` | World delta before bonus scaling/zero gate; the counterpart of native's saved audio delta. |
| `ftol_ms_i32` | Float32 scaling plus truncation for integer cadence. |
| `reflex_boost_time_scale_factor` | Native-style bonus easing with PC24 operation boundaries. |

`_session_timing` in `src/crimson/sim/sessions.py` computes these once per tick.
`WorldState.world_dt_after_perk_steps` in `src/crimson/sim/world_state.py` applies
the outer Reflex Boosted transform.
`src/crimson/gameplay.py` implements the movement remap and arithmetic restore
in `_player_reflex_movement_dt` and `_player_reflex_restored_dt`. The world
passes the returned player delta on to the next player, preserving the
shared-global round-trip effect.

### Mode mapping and current differences

| Native subsystem | Python counterpart | Current timing choice |
| --- | --- | --- |
| Survival spawning | `survival_update` in `src/crimson/sim/mode_updates.py` | Simulation milliseconds for cooldown; previous elapsed value for difficulty. |
| Rush spawning and elapsed time | `rush_mode_update` in `src/crimson/sim/mode_updates.py` | Simulation milliseconds, as native. Rush has no perks or bonus drops, so they equal the input milliseconds. |
| Quest timeline and completion | `quest_mode_update` in `src/crimson/sim/mode_updates.py`; `src/crimson/quests/timeline.py` | Simulation milliseconds for timeline, stall, and completion; `run_elapsed_ms` exposes the quest timeline rather than general session elapsed time. |
| Tutorial stages and fades | `tutorial_timeline_update` in `src/crimson/tutorial/timeline.py`, called by `WorldState.step` after the corpse cull and Telekinetic pickups | Simulation milliseconds passed to the stage machine and overlay state. |
| Typo spawn cadence | `typo_spawn_update` in `src/crimson/typo/runtime.py`, called by `typo_gameplay_update` | Simulation milliseconds and the same remaining-cooldown clamp. |
| Audio cooldowns | `src/crimson/sim/sessions.py` builds the presentation plan; `src/crimson/sim/batch_apply.py` applies it | `sfx_dt=timing.dt_audio`; music streaming is serviced separately from simulation ticks. |

The Rush distinction matters when a time transform is active; with no transform,
raw and simulation cadence coincide. This is a source-level difference, not a
claim that normal Rush play can acquire every slow-motion state.

Python's `initialize_run` sets `perk_progression_enabled=False` for Typ-o.
Typ-o sessions step `typo_gameplay_update` instead of `WorldState.step`, in the
native order of `typo_gameplay_update_and_render`: perks see the unscaled
delta, the rest of the frame the delta after Reflex Boost's flat
`TYPO_TIME_SCALE_FACTOR` of 0.3, and the frame clears the Weapon Power Up and
Reflex Boost timers.

`FrameTiming.compute` never zeroes `dt_sim`: native pause and console gates
belong to the outer mode/UI pump, not to session timing.

## Other engine timing

Grim's FPS estimate samples accumulated frames after more than 500 ms, then
subtracts 500 ms from the sample accumulator. It is a reporting cadence.
`decomp/1.9/grim/app/app_tick.cpp` contains a separate 30 ms
accumulator with a modulo remainder; its callback in
`decomp/1.9/grim/app/app_on_tick.cpp` is empty. Neither establishes
a fixed gameplay timestep in the original.

## Existing regression references

- `tests/sim/test_timing_ftol_ms_i32.py`: conversion and timing-domain behavior.
- `tests/sim/test_render_partition_parity.py`: port tick behavior across render rates.
- `tests/modes/test_survival_spawn.py`, `tests/modes/test_rush_mode_spawn.py`,
  and `tests/modes/test_typo_spawns.py`: mode scheduler behavior.
- `tests/modes/test_quest_spawn_timeline.py` and
  `tests/modes/test_quest_final_time.py`: quest scheduling and score conversion.
- `tests/modes/test_tutorial_timeline_update.py`: tutorial stage timing.
- `tests/screens/test_replay_viewer.py`: the replay viewer's pause, step and speed.

These tests describe port contracts. Passing them is not independent evidence
that every original mode, console state, and time transform matches.
