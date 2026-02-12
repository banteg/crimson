---
tags:
  - status-analysis
---

# Survival one-off weapon handouts

This page expands the `survival_update` (`0x00407cd0`) handout logic that grants
two non-quest weapons in Survival and is therefore a concrete lead for secret
weapon behavior.

## Why this matters for secrets

- The handout code directly assigns:
  - weapon id `24` (`0x18`) — Shrinkifier 5k
  - weapon id `25` (`0x19`) — Blade Gun
- Both weapons are absent from `quest_unlock_weapon_id` in `quest_database_init`;
  see [weapon candidates](weapon-candidates.md).
- The startup secret-hint block says there are "few secret weapons hidden inside
  the game"; these handouts are two verified runtime paths that fit that hint.

## Handout A: time-based Shrinkifier 5k

`survival_update` grants id `24` if all of these are true:

- single-player (`config_player_count == 1`)
- `survival_reward_damage_seen == 0`
- `survival_reward_fire_seen == 0`
- `survival_elapsed_ms > 64000`
- `survival_reward_handout_enabled != 0`
- current weapon is Pistol (`player_weapon_id == 1`)

Side effects:

- `weapon_assign_player(0, 24)`
- `survival_reward_weapon_guard_id = 24`
- `survival_reward_handout_enabled = 0`
- `survival_reward_damage_seen = 1`
- `survival_reward_fire_seen = 1`

## Handout B: low-health centroid Blade Gun

`survival_update` grants id `25` if all of these are true:

- single-player (`config_player_count == 1`)
- `survival_recent_death_count == 3`
- `survival_reward_fire_seen == 0`
- player distance to centroid of first 3 recorded death positions is `< 16.0`
- `player_health < 15.0`
- this check does **not** require `survival_reward_handout_enabled != 0`
  and does **not** test `survival_reward_damage_seen`

Centroid formula in decompile:

- `cx = (p0.x + p1.x + p2.x) * 0.33333334`
- `cy = (p0.y + p1.y + p2.y) * 0.33333334`

Side effects:

- `weapon_assign_player(0, 25)`
- `survival_reward_weapon_guard_id = 25`
- `survival_reward_fire_seen = 1`
- `survival_reward_handout_enabled = 0`

## Decoded Blade-hint mapping (inference)

From the decoded secret line in [Easter eggs](easter-eggs.md#secret-line-decode-5-bit-indices):

> Dead Center Inside The Triangle Of The First Blood Sacrifice Yourself For Firepower

The Blade Gun handout gate matches this text closely:

- **"Dead Center Inside The Triangle"** -> player must stand near the centroid of
  three recorded death positions (`distance < 16.0`).
- **"Of The First Blood"** -> the check uses the first three stored death samples
  (`survival_recent_death_count == 3`, positions at indices 0..2).
- **"Sacrifice Yourself"** -> player health must be low (`player_health < 15.0`).
- **"For Firepower"** -> reward is weapon id `25` (Blade Gun).

This mapping is an evidence-backed inference, not a direct static code xref from
the secret string to `survival_update`.

## Gate writers and lifecycle

Related writes outside `survival_update`:

- `player_update` sets `survival_reward_fire_seen = 1` when fire input is used.
- `player_take_damage` sets `survival_reward_damage_seen = 1` on damage attempts
  (including shielded hits).
- `creature_handle_death` records up to 3 death positions and increments
  `survival_recent_death_count` up to 6.
- When `survival_recent_death_count` reaches `3`, `creature_handle_death` sets:
  - `survival_reward_fire_seen = 0`
  - `survival_reward_handout_enabled = 0`
  This is the key transition that enables the second handout check.

Run reset state (`gameplay_reset_state`) initializes:

- `survival_reward_weapon_guard_id = 1`
- `survival_recent_death_count = 0`
- `survival_reward_damage_seen = 0`
- `survival_reward_fire_seen = 0`
- `survival_reward_handout_enabled = 1`

## Temporary weapon guard behavior

`gameplay_render_world` enforces that ids `24` and `25` are only valid when the
guard id matches:

- if `player_weapon_id == 25` and `survival_reward_weapon_guard_id != 25`, force
  Pistol (`weapon_assign_player(..., 1)`)
- if `player_weapon_id == 24` and `survival_reward_weapon_guard_id != 24`, force
  Pistol (`weapon_assign_player(..., 1)`)

This makes the handouts effectively temporary, guard-bound rewards instead of
normal unlocks.

## Evidence pointers

- `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
  - `survival_update` handout checks around `0x00407cd0`
  - `gameplay_render_world` guard checks around `0x00405960`
  - `player_update` fire flag write around `0x004136b0`
  - `player_take_damage` damage flag write around `0x00425e50`
  - `creature_handle_death` recent-death tracking around `0x0041e910`
  - reset init around `0x00412d70`
- `docs/weapon-id-map.md`
- `docs/re/static/secrets/weapon-candidates.md`
- `docs/crimsonland-exe/survival.md`
