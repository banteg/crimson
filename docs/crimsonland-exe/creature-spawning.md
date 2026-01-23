---
tags:
  - status-analysis
---

# Creature spawning (creature_spawn_template / FUN_00430af0)

`creature_spawn_template(template_id, pos_xy, heading)` is the primary translation layer from
"spawn ids" (quests/survival/demo scripts) to initialized `creature_t` entries.

It is not a static struct/table: it always performs base creature initialization, runs a large
template switch, may allocate additional creatures and/or spawn-slot entries, and then applies
shared tail modifiers (difficulty/hardcore, demo gating, etc).

## Inputs

- `template_id` (aka `param_1`): spawn id used by quest tables and other spawners.
- `pos_xy` (aka `param_2`): spawn position (two floats).
- `heading` (aka `param_3`): radians; sentinel `-100.0` means "randomize heading".
- Globals consulted:
  - RNG stream: `crt_rand()` (MSVCRT `rand()`).
  - `demo_mode_active`: skips the spawn burst effect when nonzero.
  - `terrain_texture_width/terrain_texture_height`: bounds check for the burst effect.
  - `config_blob.hardcore` and `DAT_00487194` (difficulty level): final stat modifiers.

## Outputs and side effects

- Returns a pointer into `creature_pool` (`creature_t *`). Some templates return the last creature
  allocated (for formations), not necessarily the base creature.
- May allocate additional `creature_pool` entries (formation spawns, escorts).
- May allocate and configure spawn-slot entries (deferred child spawns driven by `creature_update_all`).
- May spawn a burst effect at the spawn position (skipped in demo mode or when out of bounds).

## Algorithm sketch (high level)

### 1) Base init (always)

- Allocates a creature slot (`creature_alloc_slot()`), then writes base fields:
  - `ai_mode = 0`, `pos_xy`, `vel_xy = 0`
  - `active = 1`, `state_flag = 1`
  - collision defaults (`collision_flag = 0`, `collision_timer = 0`)
  - `hitbox_size = 16`, `attack_cooldown = 0`
- Seeds a transient random heading early: `crt_rand() % 0x13a * 0.01`.
- If `heading == -100.0`, randomizes the final heading: `crt_rand() % 0x274 * 0.01`.
- `creature_alloc_slot()` itself consumes RNG to seed per-creature defaults (notably `phase_seed`).

### 2) Template switch (template-specific)

Large switch/if-chain on `template_id` assigns template-specific constants and behavior:

- Stats: `type_id`, `flags`, `health`, `move_speed`, `reward_value`, `size`, `tint_rgba`,
  `ai_mode`, and various AI/link fields.
- Formation spawners: allocate N linked children and arrange them using circular offsets
  (`cos/sin`) and AI link modes (e.g. `ai_mode = 3` with `link_index = parent`).
- Spawn-slot spawners: allocate a slot (`FUN_00430ad0()`), store the slot index in `link_index`,
  and configure `creature_spawn_slot_*` arrays (timer/count/limit/interval/template/owner).

### 3) Tail modifiers (shared end-of-function)

Applied after the template switch to the returned creature:

- If not in demo mode and inside terrain bounds: `effect_spawn_burst(pos, 8)`.
- `max_health = health`.
- Spider SP1 special case: when `type_id == 3` and flags do not include `0x10` or `0x80`,
  sets `0x80`, clears `link_index`, and applies a `move_speed *= 1.2` buff.
- Template `0x38` special case: in hardcore, applies `move_speed *= 0.7`.
- Overwrites `heading` with the final (possibly randomized) heading argument.
- Difficulty / hardcore scaling:
  - Non-hardcore:
    - For flag `0x4` spawners: `spawn_slot_interval += 0.2`.
    - If `DAT_00487194 > 0`, scales reward/speed/contact/health, and for flag `0x4` spawners
      adds `min(3.0, difficulty * 0.35)` to `spawn_slot_interval`.
  - Hardcore:
    - Clears difficulty (`DAT_00487194 = 0`).
    - Buffs speed/contact/health.
    - For flag `0x4` spawners: `spawn_slot_interval -= 0.2` clamped to `>= 0.1`.

## Repo references

- Decompile extracts (used for reconciliation):
  - `artifacts/creature_spawn_template/ghidra.c`
  - `artifacts/creature_spawn_template/ida.c`
  - `artifacts/creature_spawn_template/binja-hlil.txt`
- Spawn-slot field summary: `docs/structs/creature.md`
- Rewrite model (pure plan builder): `src/crimson/spawn_plan.py`
- MSVCRT-compatible RNG for deterministic replays: `src/crimson/crand.py`

