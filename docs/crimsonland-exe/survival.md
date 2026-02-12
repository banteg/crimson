---
tags:
  - status-analysis
---

# Survival mode contract (survival_update)

This page documents the core Survival-mode responsibilities of the classic game
(`crimsonland.exe` v1.9.93) independent of rendering.

**Source of truth:** decompiles (Ghidra/IDA/Binary Ninja). Code under `src/` is our
reimplementation and can drift; treat it as a porting aid, not an authority.

Key functions:

- `survival_update` (`0x00407cd0`): mode-local update (spawns + one-off rewards).
- `survival_spawn_creature` (`0x00407510`): picks a creature type and stats from Survival XP.
- `creature_handle_death` (`0x0041e910`): awards Survival XP on kills and updates reward gates.

## State (minimum set)

Survival-specific state referenced by `survival_update` / death handling:

- `survival_elapsed_ms` (ms): used to scale wave spawn cadence. In Binja it is accessed as
  `highscore_active_record + 0x20` and in other docs as `DAT_00487060`.

- `survival_spawn_cooldown` (ms): countdown accumulator for wave spawns (decremented by `player_count * frame_dt_ms`).
- `survival_spawn_stage` (0..10): scripted stage index that gates milestone spawns by `player_level`.
- Reward gates:
  - `survival_reward_handout_enabled`
  - `survival_reward_fire_seen`
  - `survival_reward_damage_seen`
  - `survival_recent_death_pos` + `survival_recent_death_count` (tracked in `creature_handle_death`)
- Player progression (stored in the per-player struct; see `docs/structs/player.md`):
  - `player_experience` (`player_health + 0x88`)
  - `player_level` (`player_health + 0x90`)

## Update responsibilities

### 1) One-off Survival weapon handouts (reward gates)

`survival_update` contains special-case “help the player” weapon grants gated by
the reward globals listed above.

Observed behavior (high level):

- If the run has not seen **player fire** or **player damage** and a time gate has passed,
  Survival may grant a weapon and then permanently disables the handout logic by setting
  both `survival_reward_fire_seen` and `survival_reward_damage_seen`.

- A second handout check triggers when **exactly 3 recent death positions** have been recorded
  (in `creature_handle_death`), the player is close to their centroid, and player HP is low.

Weapons granted (weapon ids):

- `0x18` — Shrinkifier 5k
- `0x19` — Blade Gun

See also:

- Reward gate globals are listed in `docs/creatures/struct.md`.
- `docs/weapon-id-map.md` for the id-to-name mapping.
- `docs/secrets/survival-weapon-handouts.md` for detailed secret-lead analysis of these two grants.

### 2) Scripted stage spawns (milestones)

These are fixed spawns tied to `player_level` that run in addition to wave spawns.

The stage index advances monotonically and can “cascade” if `player_level` jumps across
multiple thresholds.

Milestones (as implemented by `survival_update` and mirrored in tests):

- Stage `0` → `1` when `player_level >= 5`: spawn `FORMATION_RING_ALIEN_8_12` (`0x12`, ring of 8 aliens) at `(-164, 512)` and `(1188, 512)` (heading π).
- Stage `1` → `2` when `player_level >= 9`: spawn `ALIEN_CONST_RED_BOSS_2C` (`0x2c`, red boss alien) at `(1088, 512)` (heading π).
- Stage `2` → `3` when `player_level >= 11`: spawn 12× `SPIDER_SP2_RANDOM_35` (`0x35`, spider sp2) at `(1088, 256 + i*(128/3))` (heading π).
- Stage `3` → `4` when `player_level >= 13`: spawn 4× `ALIEN_CONST_RED_FAST_2B` (`0x2b`, fast red alien) at `(1088, 384 + i*64)` (heading π).
- Stage `4` → `5` when `player_level >= 15`: spawn 4× `SPIDER_SP1_AI7_TIMER_38` (`0x38`, timed spider sp1) at right edge and 4× at left edge:
  - `(1088, 384 + i*64)` and `(-64, 384 + i*64)` (heading π).
- Stage `5` → `6` when `player_level >= 17`: spawn `SPIDER_SP1_CONST_SHOCK_BOSS_3A` (`0x3a`, shock boss spider) at `(1088, 512)` (heading π).
- Stage `6` → `7` when `player_level >= 19`: spawn `SPIDER_SP2_SPLITTER_01` (`0x01`, splitter spider) at `(640, 512)` (heading π).
- Stage `7` → `8` when `player_level >= 21`: spawn `SPIDER_SP2_SPLITTER_01` (`0x01`, splitter spider) at `(384, 256)` and `(640, 768)` (heading π).
- Stage `8` → `9` when `player_level >= 26`: spawn 4× `SPIDER_SP1_CONST_RANGED_VARIANT_3C` (`0x3c`, ranged spider sp1) at `(1088, 384 + i*64)` and 4× at `(-64, 384 + i*64)` (heading π).
- Stage `9` → `10` when `player_level >= 32`: spawn the final wave:
  - `SPIDER_SP1_CONST_SHOCK_BOSS_3A` (`0x3a`, shock boss spider) at `(1088, 512)` and `(-64, 512)` (heading π)
  - `SPIDER_SP1_CONST_RANGED_VARIANT_3C` (`0x3c`, ranged spider sp1) at top edge `((384 + i*64), -64)` and bottom edge `((384 + i*64), 1088)` (heading π)

Rewrite ports (derived from decompile + validated by tests):

- `src/crimson/creatures/spawn.py:advance_survival_spawn_stage`
- `tests/test_survival_milestones.py`

### 3) Continuous wave spawns (cadence)

Wave spawns are driven by `survival_spawn_cooldown` (milliseconds):

1) Decrement:

- `survival_spawn_cooldown -= player_count * frame_dt_ms`

2) When the cooldown goes negative, schedule spawns:

- `interval_ms = 500 - (survival_elapsed_ms // 1800)`
- If `interval_ms < 0`:
  - `extra = (1 - interval_ms) >> 1`
  - `interval_ms += extra * 2`
  - spawn `extra` creatures immediately (each with a fresh random edge position)
- Clamp: `interval_ms = max(1, interval_ms)`
- `survival_spawn_cooldown += interval_ms`
- Spawn 1 creature at a random edge position.

The native code loops while `survival_spawn_cooldown < 0` (so very large `frame_dt_ms` could
produce multiple “interval” spawns in one tick), but with the normal bounded frame time this
rarely iterates more than once.

Spawn position (per creature):

- A random edge is selected (`rand() & 3`), and the spawn position is placed just outside the
  playable rectangle by `40.0` units.

Each spawn calls `survival_spawn_creature(pos)` to choose a type and stats from `player_experience`.

Rewrite ports (derived from decompile + validated by tests):

- `src/crimson/creatures/spawn.py:tick_survival_wave_spawns`
- `tests/test_survival_wave.py`
- `src/crimson/creatures/spawn.py:build_survival_spawn_creature`
- `tests/test_survival_spawn.py`

## Progression (XP, levels, perks)

### XP awarding on kills

In Survival, XP is awarded on creature death by `creature_handle_death`:

- Adds `int(creature_reward_value)` to `player_experience`.
- If “Bloody Mess / Quick Learner” is active, awards `int(reward_value * 1.3)` instead.
- If Double XP is active (`bonus_double_xp_timer > 0`), the same amount is added again.

See: `docs/creatures/update.md` for the death contract details.

### Level thresholds

HUD and progression use a pow-based threshold (via `crt_ci_pow`, exponent ≈ `1.8`):

- `level_threshold(level) = 1000 + int(pow(level, 1.8) * 1000)`

The Survival progress bar uses:

- previous threshold for `level-1` (with a special-case: at `level == 1`, previous threshold is `0`)
- next threshold for `level`
- ratio = `(player_experience - prev) / (next - prev)`

Rewrite model: `src/crimson/gameplay.py:survival_level_threshold` (validate against decompile if it drifts).

### Perk flow (native vs rewrite)

Native behavior (high level):

- Level-ups increment a “pending perks” counter.
- The main gameplay loop renders a level-up prompt (`perk_prompt_update_and_render`) and
  transitions to the perk selection screen when the prompt is accepted.

- Perk choices are generated by `perks_generate_choices` and applied by `perk_apply`.

Rewrite behavior today:

- `survival_progression_update` advances levels and can auto-pick pending perks instead of
  opening a selection UI. This is an approximation until the full perk prompt/selection flow is implemented.

See also: `docs/crimsonland-exe/frame-loop.md` and `docs/crimsonland-exe/gameplay.md`.
