---
tags:
  - status-analysis
---

# Creature spawning (creature_spawn_template / 0x00430af0)

`creature_spawn_template(template_id, pos_xy, heading)` is the primary translation layer from
"spawn ids" (quests, tutorial timelines, and other scripted spawners) to initialized `creature_t`
entries.

It is not a static struct/table: it always performs base creature initialization, runs a large
template switch, may allocate additional creatures and/or spawn-slot entries, and then applies
shared tail modifiers (difficulty/hardcore, demo gating, etc).

For the pure, unit-testable model we use while porting templates, see: [`spawn_plan.md`](spawn_plan.md).

## Spawn id name provenance

The canonical spawn-id names combine the Windows `template_id` values with developer-facing creature
names recovered from the PS4 1.00 remake's `data/creatures/creature-variants.xml`.

The remake's `legacy_variant_index` is not the Windows spawn id. We cross-mapped fixed creatures by
type and the exact health, speed, reward, damage, and size fingerprint (`remake scale * 64`), then
retained the native Windows value as each identifier's hexadecimal suffix:

| Windows id | Canonical name | Remake variant |
| --- | --- | --- |
| `0x0f` | `ALIEN_GHOST_0F` | `AlienGhost` |
| `0x21` | `ALIEN_HIDDEN_1_21` | `AlienHidden1` |
| `0x22` | `ALIEN_HIDDEN_2_22` | `AlienHidden2` |
| `0x23` | `ALIEN_HIDDEN_3_23` | `AlienHidden3` |
| `0x25` | `ALIEN_SMALL_GREEN_MAN_25` | `AlienSmallGreenMan` |
| `0x26` | `ALIEN_SMALL_GRAY_26` | `AlienSmallGray` |
| `0x27` | `ALIEN_BONUS_CARRIER_27` | `AlienBonusCarrier` |
| `0x29` | `ALIEN_BIG_GRAY_29` | `AlienBigGray` |
| `0x2b` | `ALIEN_DEADLY_FAST_2B` | `AlienDeadlyFast` |
| `0x3a` | `SPIDER_BOSS_3A` | `SpiderBoss` |
| `0x3c` | `SPIDER_PLASMA_SHOOTER_3C` | `SpiderPlasmaShooter` |
| `0x40` | `SPIDER_SMALL_BLUE_40` | `SpiderSmallBlue` |
| `0x42` | `ZOMBIE_SMALL_WHITE_42` | `ZombieSmallWhite` |

Spawner names are cross-mapped by their den family, child variant, spawn interval, and surviving stat
fingerprints. Some balance fields changed in the remake, so these are semantic names rather than a
claim that the records are byte-for-byte identical:

| Windows id | Canonical name | Remake variant |
| --- | --- | --- |
| `0x07` | `DEN_ALIEN_BASIC_07` | `DenAlienBasic` |
| `0x08` | `DEN_ALIEN_BASIC_SLOWER_08` | `DenAlienBasicSlower` |
| `0x09` | `DEN_ALIEN_WEAK_SMALL_09` | `DenAlienWeakSmall` |
| `0x0a` | `DEN_SPIDER_BASIC_0A` | `DenSpiderBasic` |
| `0x0b` | `DEN_SPIDER_PLASMA_SHOOTERS_0B` | `DenSpiderPlasmaShooters` |
| `0x0c` | `DEN_LIZARD_WEAK_0C` | `DenLizardWeak` |
| `0x0d` | `DEN_LIZARD_WEAK_SLOWER_0D` | `DenLizardWeakSlower` |
| `0x10` | `DEN_SPIDER_WEAK_10` | `DenSpiderWeak` |

## Inputs

- `template_id` (aka `param_1`): spawn id used by quest tables and other spawners.
- `pos_xy` (aka `param_2`): spawn position (two floats).
- `heading` (aka `param_3`): radians; sentinel `-100.0` means "randomize heading".
- Globals consulted:
  - RNG stream: `crt_rand()` (MSVCRT `rand()`).
  - `demo_mode_active`: skips the spawn burst effect when nonzero.
  - `terrain_texture_width/terrain_texture_height`: bounds check for the burst effect.
  - `config_blob.hardcore` and `quest_fail_retry_count` (difficulty level): final stat modifiers.

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
  - `lifecycle_stage = 16`, `attack_cooldown = 0`
- Seeds a transient random heading early: `crt_rand() % 0x13a * 0.01`.
- If `heading == -100.0`, randomizes the final heading: `crt_rand() % 0x274 * 0.01`.
- `creature_alloc_slot()` itself consumes RNG to seed per-creature defaults (notably `phase_seed`).

### 2) Template switch (template-specific)

Large switch/if-chain on `template_id` assigns template-specific constants and behavior:

- Stats: `type_id`, `flags`, `health`, `move_speed`, `reward_value`, `size`, `tint_rgba`,
  `ai_mode`, and various AI/link fields.

- Formation spawners: allocate N linked children and arrange them using circular offsets
  (`cos/sin`) and AI link modes (e.g. `ai_mode = 3` with `link_index = parent`).

- Spawn-slot spawners: allocate a slot (`creature_spawn_slot_alloc()`), store the slot index in `link_index`,
  and configure `creature_spawn_slot_*` arrays (timer/count/limit/interval/template/owner).

### 3) Tail modifiers (shared end-of-function)

Applied after the template switch to the returned creature:

- If not in demo mode and inside terrain bounds: `effect_spawn_burst(pos, 8)`.
- `max_health = health`.
- Note: difficulty/hardcore scaling applies to `health` after this assignment, so `max_health` retains the
  pre-scaled value.

- Spider SP1 special case: when `type_id == 3` and flags do not include `0x10` or `0x80`,
  sets `0x80`, clears `link_index`, and applies a `move_speed *= 1.2` buff.

- Template `0x38` special case: in hardcore, applies `move_speed *= 0.7`.
- Overwrites `heading` with the final (possibly randomized) heading argument.
- Difficulty / hardcore scaling:
  - Non-hardcore:
    - For flag `0x4` spawners: `spawn_slot_interval += 0.2`.
    - If `quest_fail_retry_count > 0`, scales reward/speed/contact/health, and for flag `0x4` spawners
      adds `min(3.0, difficulty * 0.35)` to `spawn_slot_interval`.

  - Hardcore:
    - Clears difficulty (`quest_fail_retry_count = 0`).
    - Buffs speed/contact/health.
    - For flag `0x4` spawners: `spawn_slot_interval -= 0.2` clamped to `>= 0.1`.

## Spawn id porting checklist (rewrite)

This tracks our `creature_spawn_template` rewrite coverage.

- Ported: implemented in `build_spawn_plan` (pure plan builder).
- Verified: covered by unit tests in `tests/creatures/test_spawn_plan.py`.
- Legend: ✅ complete · 🚧 in progress · ⬜ not started
- Note: spawn id `0x02` does not appear in the decompile extracts and is omitted.

<!-- spawn-status:start -->
Generated by `uv run scripts/gen_spawn_templates.py`.

| Spawn id | Creature | Ported | Verified |
| --- | --- | --- | --- |
| `0x0` | `zombie` | ✅ | ✅ |
| `0x1` | `spider_sp2` | ✅ | ✅ |
| `0x3` | `spider_sp1` | ✅ | ✅ |
| `0x4` | `lizard` | ✅ | ✅ |
| `0x5` | `spider_sp2` | ✅ | ✅ |
| `0x6` | `alien` | ✅ | ✅ |
| `0x7` | `alien` | ✅ | ✅ |
| `0x8` | `alien` | ✅ | ✅ |
| `0x9` | `alien` | ✅ | ✅ |
| `0xa` | `alien` | ✅ | ✅ |
| `0xb` | `alien` | ✅ | ✅ |
| `0xc` | `alien` | ✅ | ✅ |
| `0xd` | `alien` | ✅ | ✅ |
| `0xe` | `alien` | ✅ | ✅ |
| `0xf` | `alien` | ✅ | ✅ |
| `0x10` | `alien` | ✅ | ✅ |
| `0x11` | `lizard` | ✅ | ✅ |
| `0x12` | `alien` | ✅ | ✅ |
| `0x13` | `alien` | ✅ | ✅ |
| `0x14` | `alien` | ✅ | ✅ |
| `0x15` | `alien` | ✅ | ✅ |
| `0x16` | `lizard` | ✅ | ✅ |
| `0x17` | `spider_sp1` | ✅ | ✅ |
| `0x18` | `alien` | ✅ | ✅ |
| `0x19` | `alien` | ✅ | ✅ |
| `0x1a` | `alien` | ✅ | ✅ |
| `0x1b` | `spider_sp1` | ✅ | ✅ |
| `0x1c` | `lizard` | ✅ | ✅ |
| `0x1d` | `alien` | ✅ | ✅ |
| `0x1e` | `alien` | ✅ | ✅ |
| `0x1f` | `alien` | ✅ | ✅ |
| `0x20` | `alien` | ✅ | ✅ |
| `0x21` | `alien` | ✅ | ✅ |
| `0x22` | `alien` | ✅ | ✅ |
| `0x23` | `alien` | ✅ | ✅ |
| `0x24` | `alien` | ✅ | ✅ |
| `0x25` | `alien` | ✅ | ✅ |
| `0x26` | `alien` | ✅ | ✅ |
| `0x27` | `alien` | ✅ | ✅ |
| `0x28` | `alien` | ✅ | ✅ |
| `0x29` | `alien` | ✅ | ✅ |
| `0x2a` | `alien` | ✅ | ✅ |
| `0x2b` | `alien` | ✅ | ✅ |
| `0x2c` | `alien` | ✅ | ✅ |
| `0x2d` | `alien` | ✅ | ✅ |
| `0x2e` | `lizard` | ✅ | ✅ |
| `0x2f` | `lizard` | ✅ | ✅ |
| `0x30` | `lizard` | ✅ | ✅ |
| `0x31` | `lizard` | ✅ | ✅ |
| `0x32` | `spider_sp1` | ✅ | ✅ |
| `0x33` | `spider_sp1` | ✅ | ✅ |
| `0x34` | `spider_sp1` | ✅ | ✅ |
| `0x35` | `spider_sp2` | ✅ | ✅ |
| `0x36` | `alien` | ✅ | ✅ |
| `0x37` | `spider_sp2` | ✅ | ✅ |
| `0x38` | `spider_sp1` | ✅ | ✅ |
| `0x39` | `spider_sp1` | ✅ | ✅ |
| `0x3a` | `spider_sp1` | ✅ | ✅ |
| `0x3b` | `spider_sp1` | ✅ | ✅ |
| `0x3c` | `spider_sp1` | ✅ | ✅ |
| `0x3d` | `spider_sp1` | ✅ | ✅ |
| `0x3e` | `spider_sp1` | ✅ | ✅ |
| `0x3f` | `spider_sp1` | ✅ | ✅ |
| `0x40` | `spider_sp1` | ✅ | ✅ |
| `0x41` | `zombie` | ✅ | ✅ |
| `0x42` | `zombie` | ✅ | ✅ |
| `0x43` | `zombie` | ✅ | ✅ |
<!-- spawn-status:end -->

## Spawn template ids (direct type/flags map)

The large template switch inside `creature_spawn_template` assigns `type_id` and sometimes
`flags`. The table below lists only these direct assignments (useful for labeling).

It does not capture randomized parameters, formation spawns, spawn slots, or tail modifiers.

<!-- spawn-templates:start -->
Generated by `uv run scripts/gen_spawn_templates.py`.

| Spawn id (template_id) | Type id | Creature | Flags (creature_flags) | Anim note |
| --- | --- | --- | --- | --- |
| `0x0` | `0` | `zombie` | `0x44` | long strip (0x40 overrides 0x4) |
| `0x1` | `4` | `spider_sp2` | `0x8` |  |
| `0x3` | `3` | `spider_sp1` | `` |  |
| `0x4` | `1` | `lizard` | `` |  |
| `0x5` | `4` | `spider_sp2` | `` |  |
| `0x6` | `2` | `alien` | `` |  |
| `0x7` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0x8` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0x9` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xa` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xb` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xc` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xd` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xe` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xf` | `2` | `alien` | `` |  |
| `0x10` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0x11` | `1` | `lizard` | `` |  |
| `0x12` | `2` | `alien` | `` |  |
| `0x13` | `2` | `alien` | `` |  |
| `0x14` | `2` | `alien` | `` |  |
| `0x15` | `2` | `alien` | `` |  |
| `0x16` | `1` | `lizard` | `` |  |
| `0x17` | `3` | `spider_sp1` | `` |  |
| `0x18` | `2` | `alien` | `` |  |
| `0x19` | `2` | `alien` | `` |  |
| `0x1a` | `2` | `alien` | `` |  |
| `0x1b` | `3` | `spider_sp1` | `` |  |
| `0x1c` | `1` | `lizard` | `` |  |
| `0x1d` | `2` | `alien` | `` |  |
| `0x1e` | `2` | `alien` | `` |  |
| `0x1f` | `2` | `alien` | `` |  |
| `0x20` | `2` | `alien` | `` |  |
| `0x21` | `2` | `alien` | `` |  |
| `0x22` | `2` | `alien` | `` |  |
| `0x23` | `2` | `alien` | `` |  |
| `0x24` | `2` | `alien` | `` |  |
| `0x25` | `2` | `alien` | `` |  |
| `0x26` | `2` | `alien` | `` |  |
| `0x27` | `2` | `alien` | `0x400` | bonus_id=WEAPON (3), duration_override=5 (packed in link_index) |
| `0x28` | `2` | `alien` | `` |  |
| `0x29` | `2` | `alien` | `` |  |
| `0x2a` | `2` | `alien` | `` |  |
| `0x2b` | `2` | `alien` | `` |  |
| `0x2c` | `2` | `alien` | `` |  |
| `0x2d` | `2` | `alien` | `` |  |
| `0x2e` | `1` | `lizard` | `` |  |
| `0x2f` | `1` | `lizard` | `` |  |
| `0x30` | `1` | `lizard` | `` |  |
| `0x31` | `1` | `lizard` | `` |  |
| `0x32` | `3` | `spider_sp1` | `` |  |
| `0x33` | `3` | `spider_sp1` | `` |  |
| `0x34` | `3` | `spider_sp1` | `` |  |
| `0x35` | `4` | `spider_sp2` | `` |  |
| `0x36` | `2` | `alien` | `` |  |
| `0x37` | `4` | `spider_sp2` | `0x100` |  |
| `0x38` | `3` | `spider_sp1` | `0x80` |  |
| `0x39` | `3` | `spider_sp1` | `0x80` |  |
| `0x3a` | `3` | `spider_sp1` | `0x10` | projectile_type=9 |
| `0x3b` | `3` | `spider_sp1` | `` |  |
| `0x3c` | `3` | `spider_sp1` | `0x100` | projectile_type=26 (packed in orbit_radius) |
| `0x3d` | `3` | `spider_sp1` | `` |  |
| `0x3e` | `3` | `spider_sp1` | `` |  |
| `0x3f` | `3` | `spider_sp1` | `` |  |
| `0x40` | `3` | `spider_sp1` | `` |  |
| `0x41` | `0` | `zombie` | `` |  |
| `0x42` | `0` | `zombie` | `` |  |
| `0x43` | `0` | `zombie` | `` |  |
<!-- spawn-templates:end -->

Notes:

- `src/crimson/creatures/spawn.py` contains both the spawn-id labeling index (direct type/flags) and the
  pure plan builder (formations/spawn slots/tail modifiers).

## Spawn id sources (call sites)

`template_id` is supplied by a mix of scripted spawners and data tables:

- `demo_setup_variant_0` (`0x00402ed0`), `demo_setup_variant_2` (`0x00402fe0`),
  `demo_setup_variant_1` (`0x004030f0`), `demo_setup_variant_3` (`0x00403250`):
  mode setup helpers called from `demo_mode_start` (`0x00403390`) (hard‑coded spawn ids like `0x34`, `0x35`,
  `0x38`, `0x41`, `0x24`, `0x25`).

- `survival_update` (`0x00407cd0`): milestone spawns using `0x12`, `0x2b`,
  `0x2c`, `0x35`, `0x38`, `0x3a`, `0x3c`, and `1`. Regular enemy waves are spawned via
  `survival_spawn_creature` (`0x00407510`), which selects type/stats based on
  `player_experience` (not a spawn id). Python models: `advance_survival_spawn_stage`,
  `tick_survival_wave_spawns`, `build_survival_spawn_creature`.

- Rush mode (`rush_mode_update`, `0x004072b0`): spawns edge waves via `creature_spawn`
  (type ids `2`/`3`), not `creature_spawn_template`. Python models: `tick_rush_mode_spawns`,
  `build_rush_mode_spawn_creature`.

- Tutorial timeline (`tutorial_timeline_update`, `0x00408990`): scripted spawns using `0x24`, `0x26`,
  `0x27`, `0x28`, `0x40`. Python models: `build_tutorial_stage3_fire_spawns`,
  `build_tutorial_stage4_clear_spawns`, `build_tutorial_stage5_repeat_spawns`,
  `build_tutorial_stage6_perks_done_spawns`.

- Quest/timeline spawner (`quest_spawn_timeline_update`, `0x00434250`): pulls spawn ids from the
  table at `quest_spawn_table` (`pfVar4[3]`) with counts in `pfVar4[5]`. Python model:
  `crimson.quests.timeline.tick_quest_spawn_timeline` (see also `tick_quest_mode_spawns` for the
  `quest_mode_update` gating).

- AI subspawns (`creature_update_all`): periodic spawns using `&creature_spawn_slot_template + iVar6 * 0x18`,
  which is seeded for some template ids inside `creature_spawn_template` (`0x00430af0`).

## Quest spawn table (quest_spawn_table)

Quests populate a fixed table at `quest_spawn_table` (entry size `0x18`, count in
`quest_spawn_count`). `quest_spawn_timeline_update` (`0x00434250`) walks the table and
spawns entries whose trigger time has elapsed.

Entry layout (dwords):

| Offset | Field | Notes |
| --- | --- | --- |
| 0x00 | x | base spawn X; if offscreen, the group spreads along Y instead of X. |
| 0x04 | y | base spawn Y. |
| 0x08 | heading | passed as `heading` to `creature_spawn_template`. |
| 0x0c | spawn id | cast to int and passed as `template_id` to `creature_spawn_template`. |
| 0x10 | trigger time | compared against `quest_spawn_timeline` (quest clock). |
| 0x14 | count | number of spawns in the group; decremented to 0 after firing. |

Notes:

- `quest_start_selected` (`0x0043a790`) chooses a quest builder from the table at
  `quest_selected_meta`. The function pointer lives at `&quest_selected_builder`; when null, it
  falls back to `quest_build_fallback` (`0x004343e0`) (two entries with spawn id
  `0x40`, counts 10/0x14, trigger times
  500/5000).

- `quest_build_zombie_time` (`0x00437d70`), `quest_build_lizard_raze` (`0x00438840`), and
  `quest_build_surrounded_by_reptiles` (`0x00438940`) are examples of quest builders that write
  multiple `quest_spawn_table` entries with varying spawn ids and timings.

## Repo references

- Decompile extracts (used for reconciliation):
  - `artifacts/creature_spawn_template/ghidra.c`
  - `artifacts/creature_spawn_template/ida.c`
  - `artifacts/creature_spawn_template/binja-hlil.txt`
- Creature pool + spawn-slot fields: `docs/creatures/struct.md`
- Rewrite model (pure plan builder): `src/crimson/creatures/spawn.py`
- Survival mode (pure models): `src/crimson/creatures/spawn.py`
  - `advance_survival_spawn_stage`, `tick_survival_wave_spawns`, `build_survival_spawn_creature`
  - Tests: `tests/modes/test_survival_milestones.py`, `tests/modes/test_survival_wave.py`, `tests/modes/test_survival_spawn.py`
- Rush mode (pure models): `src/crimson/creatures/spawn.py`
  - `tick_rush_mode_spawns`, `build_rush_mode_spawn_creature`
  - Tests: `tests/modes/test_rush_mode_spawn.py`
- Tutorial timeline (pure models): `src/crimson/creatures/spawn.py`
  - `build_tutorial_stage3_fire_spawns`, `build_tutorial_stage4_clear_spawns`,
    `build_tutorial_stage5_repeat_spawns`, `build_tutorial_stage6_perks_done_spawns`

  - Tests: `tests/modes/test_tutorial_timeline_spawns.py`
- Quest timeline (pure model): `src/crimson/quests/timeline.py`
  - `tick_quest_spawn_timeline`, `tick_quest_mode_spawns`, `quest_spawn_table_empty`
  - Tests: `tests/modes/test_quest_spawn_timeline.py`, `tests/modes/test_quest_mode_spawns.py`
- MSVCRT-compatible RNG for deterministic replays: `src/grim/rand.py` (`Crand`)
