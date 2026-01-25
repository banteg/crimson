---
tags:
  - status-analysis
---

# Creature runtime contract (creature_update_all)

This page defines the **minimum runtime contract** we need from `creature_update_all`
(`crimsonland.exe` `FUN_00426220`) to unblock **Survival** in the rewrite.

**Source of truth:** the decompiles (Ghidra/IDA/Binary Ninja). Code under `src/` is our
reimplementation and may be wrong; use it as a porting aid, not an authority.

The rewrite already contains several **pure** (unit-testable) building blocks:

- AI target selection: `docs/creatures/ai.md` + `src/crimson/creatures/ai.py`
- Animation phase + frame selection: `docs/creatures/animations.md` + `src/crimson/creatures/anim.py`
- Spawning (templates + spawn slots): `docs/creatures/spawning.md` + `src/crimson/creatures/spawn.py`
  - Spawn-slot tick behavior is tested in `tests/test_spawn_slots.py`.

What is *missing* is the “glue”: the per-tick order, state mutation, and event emission that
ties these pieces into a realtime loop.

## Data model (what the loop owns)

The source-of-truth layout is the native `creature_t` pool; see
[`docs/creatures/struct.md`](struct.md).

For Survival parity, the runtime update loop must at least track:

- Per-creature motion state: `pos_xy`, `vel_xy`, `heading`, `target_heading`
- Per-creature targeting state: `target_x/target_y`, `target_player`, `force_target`, `ai_mode`,
  plus link/orbit fields (`link_index`, `target_offset_x/y`, `orbit_angle/radius`)
- Per-creature timers: `attack_cooldown`, `collision_timer`, hit flash timer
- Per-creature “alive” state: `active` + `health` (and a one-shot “death handled” latch)
- Per-creature presentation state: `anim_phase` + `tint_rgba`
- Spawn-slot state (global arrays / pool), indexed via `link_index` for slot-owning creatures

## Referenced tables (renderer + SFX)

`creature_update_all` (and helpers) consult the creature **type table**
(`docs/creatures/animations.md`):

- Animation rate (advances `anim_phase`)
- Atlas base frame and corpse frame (render/death)
- Per-type SFX “banks” (damage/death/contact variants)

## Per-tick order (Survival subset)

This is the “contract” part: **the order matters** because it defines which state is visible to
subsystems in the same tick (e.g. collision uses post-move position; death should run after all
damage sources have been applied).

Observed high-level structure inside `creature_update_all` (mirrors `docs/crimsonland-exe/frame-loop.md`):

1) **AI target selection**
   - AI7 link-index timer behavior (flag `0x80`) is ticked early and can force `ai_mode = 7`.
   - Target selection computes:
     - `target_x/target_y`, `target_heading`, `force_target`
     - `move_scale` (local speed reduction in some modes)
     - optional self-damage when a required link is dead (modes `4/5` apply `creature_apply_damage(..., 1000.0, ...)`)
   - Reference port: `src/crimson/creatures/ai.py` (derived from decompilation).

2) **Heading integration**
   - Move `heading` toward `target_heading` with a per-frame turn rate clamp (native eases rather
     than snapping).

3) **Velocity integration**
   - Compute velocity from `heading` and `move_speed` (scaled by `move_scale` from AI).
   - Integrate position: `pos += vel * dt`.

4) **Bounds clamp**
   - Clamp `pos_xy` to terrain bounds.
   - The native clamp is size-aware; for Survival we can start with a simple `[0, w] x [0, h]`
     clamp and refine when we port the exact margin rule.

5) **Collision + contact damage**
   - Contact damage to players is driven by per-creature `collision_flag` +
     `collision_timer` (see `docs/creatures/struct.md`).
   - Contract:
     - When in contact range, set/keep `collision_flag` and decrement `collision_timer` by `dt`.
     - When the timer crosses below zero, apply `player_take_damage(contact_damage)` and reset the
       timer to its period (native adds `0.5` seconds).
     - When not in contact range, clear the flag and reset/relax the timer (native behavior TBD).

6) **Ranged attacks**
   - If the creature is a ranged variant (`creature_flags` indicates ranged mode), decrement
     `attack_cooldown` and, when it elapses, spawn a projectile and reset the cooldown.
   - Observed ranged-variant gates:
     - `0x10`: spawns projectile type `9` and adds `1.0` to `attack_cooldown` (plays `sfx_shock_fire`).
     - `0x100`: spawns a projectile whose type id is stored in `orbit_radius` (also plays a fire SFX).
   - Note: animation strip selection also uses `0x10` as a render-strip offset; see
     `docs/creatures/animations.md`.

7) **Spawn-slot ticking**
   - Some spawner templates allocate a **spawn slot** and store the slot index in
     `creature_link_index` (these creatures also use flag `0x4`, which doubles as the short-strip
     animation flag; see the `HAS_SPAWN_SLOT` alias in `src/crimson/creatures/spawn.py`).
   - Contract:
     - For each active spawn slot, call `tick_spawn_slot(slot, dt_seconds)`.
     - If it returns a `child_template_id`, call `creature_spawn_template(child_template_id, ...)`
       (or the rewrite equivalent: `build_spawn_plan(...)` then materialize it).
   - The tested semantics (`tests/test_spawn_slots.py`):
     - Timer always decrements: `timer -= dt`
     - When `timer < 0`, it is incremented by `interval` **exactly once** (no loop).
     - `count` increments and a spawn triggers only if `count < limit`.
     - Even when at limit, the timer still resets by `interval`.

## “Death contract” (what happens when HP crosses `<= 0`)

When a creature transitions from alive to dead (`health <= 0`), the runtime must perform a
one-shot death handler.

In the native code this is handled by `creature_handle_death` (`0x0041e910`) and is invoked from
inside `creature_update_all`.

Minimum side effects needed by Survival:

1) **Deactivate** the creature (`active = 0`) and update creature counters:
   - `creature_kill_count` (HUD and scoring)
   - `creature_active_count` (recomputed each update pass in native)

2) **Award XP** to the primary player:
   - `creature_handle_death` adds `int(creature_reward_value)` to `player_experience`
     (`player_health + 0x88`).
   - If the “Bloody Mess / Quick Learner” perk is active (`perk_id_bloody_mess_quick_learner`),
     it adds `int(reward_value * 1.3)` instead.
   - If `bonus_double_xp_timer > 0`, it adds the same amount **again** (effectively doubling XP).

3) **Attempt bonus drop**
   - Native uses a per-kill gate (`bonus_try_spawn_on_kill`, `0x41f8d0`), then selects a type using
     `bonus_pick_random_type` (`docs/bonus-drop-rates.md`).
   - Forced bonus-on-death uses flag `0x400` (`BONUS_ON_DEATH`) and calls `bonus_spawn_at(pos, id, duration)`
     using `link_index` low/high 16-bit fields.

4) **Queue FX + SFX**
   - FX: blood, corpse decals, sprite bursts (see `docs/structs/effects.md` and terrain baking notes).
   - SFX: per-type death sounds use the type table SFX banks (`docs/creatures/animations.md`).

5) **Survival bookkeeping**
   - Survival tracks recent death positions and a handout gate via globals listed in
     `docs/creatures/struct.md` (used by `survival_update`).
   - The rewrite should carry equivalent state (even if the reward logic is initially stubbed).

Notes:

- Some flags add death behavior:
  - `SPLIT_ON_DEATH` spawns smaller child creatures (max_health scaling is documented in
    `docs/creatures/struct.md`).
  - `BONUS_ON_DEATH` (`0x400`) forces a specific bonus id/duration (encoded via `link_index` in native).
