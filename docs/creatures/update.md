---
tags:
  - status-analysis
---

# Creature update and death lifecycle

Native behavior is anchored to `creature_update_all` (`0x00426220`),
`creature_apply_damage` (`0x004207c0`) and `creature_handle_death` (`0x0041e910`).
Their recovered bodies are in `tools/match/scratches/creature_update_all/scratch.cpp`,
`tools/match/scratches/creature_apply_damage/scratch.cpp` and
`tools/match/scratches/creature_handle_death/scratch.c`. Consult address-keyed
binary analysis when changing behavior; the Python implementation is a port.

## Update ownership and order

The native loop visits 384 pool slots in index order. For each active slot it
counts the entry and reduces hit flash. Freeze gates the subsequent ordinary
update. That update handles self-damage and link timers, targeting, living AI,
movement/animation/spawner work, then proximity effects and attacks. Death and
corpse phases use the same pool, rather than a separate collection.

The living branch is selected by `lifecycle_stage == 16.0`. Health and `active`
are separate gates used by different consumers. In particular, an active entry
can already be dying, collidable, fading, or awaiting corpse baking. Do not
replace those tests with one generic `alive` predicate. See [struct](struct.md),
[AI](ai.md), [animation](animations.md) and [spawning](spawning.md) for details.

## Infection and attack timers

The historical symbols `collision_flag` and `collision_timer` do not describe the
player attack cooldown:

- Plaguebearer sets the flag on eligible nearby creatures. In the living branch,
  the flagged timer loses `frame_dt`; a negative timer gains `0.5` once and the
  creature loses 15 health. A lethal infection calls death handling inline.
- Radioactive also uses `collision_timer`: within 100 units it loses
  `frame_dt * 1.5`; when negative with positive health it resets to `0.5` and
  applies `(100 - distance) * 0.3` health loss, with its own lethal branch.
- `attack_cooldown` loses `frame_dt` when positive, otherwise it is set to zero.
  Melee requires creature size greater than 16, distance below 30, a living
  target and no Energizer. At cooldown `<= 0`, the native loop plays attack SFX,
  applies Mr. Melee retaliation and poison effects, calls `player_take_damage`,
  queues impact FX, then adds `1.0` to the cooldown.
- At distance greater than 64, flag `0x10` fires projectile type 9 and adds
  `1.0`; flag `0x100` fires the type stored in the orbit-radius union and adds
  `(rand() & 3) * 0.1 + orbit_angle`. Both share `attack_cooldown`.

Spawn-slot timers run in the owning creature's update: subtract `dt`, add the
interval once if negative, and spawn/increment only while below the count limit.
The timer still advances at the limit. See `tests/creatures/test_spawn_slots.py`.

## Synchronous death handling

A lethal damage path calls `creature_handle_death` immediately. Moving death to
an end-of-tick queue changes which bonus state, child slots and RNG draws later
operations see. Direct health writes, such as Radioactive's branch, have their
own side effects and do not automatically inherit every death-handler action.

The handler's order is:

1. Emit a forced bonus for flag `0x400`, then update the recent-death positions
   and Survival reward gates. These occur before the inactive-entry return.
2. For an active creature, release its spawn-slot ownership and create splitter
   children when required. Children copy the native creature record and then
   overwrite their phase, heading, health, size, speed, damage and reward fields.
3. With `keep_corpse`, decrement lifecycle by `frame_dt` and retain `active`.
   Otherwise clear `active` immediately.
4. Award player 0 XP. Quick Learner adds `int(reward * 1.3f)`; the ordinary branch
   converts the floating sum of existing XP plus reward back to an integer.
   Double XP repeats the corresponding operation.
5. Attempt an ordinary bonus drop unless the bonus-spawn guard is set.
6. Read the current Freeze timer. If positive, emit freeze shards/shatter,
   increment kills, deactivate the slot and queue a terrain mark. A bonus created
   earlier in this same handler can affect this decision.

The first three death positions are stored; the counter saturates at six. On
reaching three, the fire and handout gates are cleared. See
[Survival handouts](../re/static/secrets/survival-weapon-handouts.md).

## Corpse completion

For a dying entry with positive lifecycle, the update subtracts `dt * 28`.
Crossing zero queues the corpse decal unless violence is disabled. If the queue
is full, lifecycle becomes `0.001` so baking can retry. Successful completion
increments the kill counter; body-fade configuration determines immediate
release versus a fading entry. The negative-lifecycle path subtracts `dt * 20`;
render/post-render cleanup completes the remaining lifecycle.

The Python owners are `src/crimson/creatures/runtime.py`,
`src/crimson/creatures/damage.py`, `src/crimson/creatures/damage_runtime.py` and
`src/crimson/creatures/lifecycle.py`. Session post-render finalization preserves
the native boundary for headless replay; see the
[session contract](../rewrite/deterministic-step-pipeline.md).
