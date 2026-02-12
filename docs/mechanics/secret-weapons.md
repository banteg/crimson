---
tags:
  - mechanics
  - systems
  - secrets
---

# Secret weapons

This page tracks weapon paths that are not part of normal quest weapon unlocks.
Current verified paths are:

- two one-off Survival handouts (`24` Shrinkifier 5k, `25` Blade Gun)
- one persistent progression unlock (`29` Splitter Gun)

## Survival one-off handouts

In single-player Survival, `survival_update` can assign hidden weapons under
strict runtime gates. These are runtime grants, not permanent unlocks.
For decompile-level gate writes and evidence pointers, see
[Survival weapon handouts (RE/static)](../re/static/secrets/survival-weapon-handouts.md).

### Shrinkifier 5k (`weapon_id = 24`)

The time-based check runs when all of these are true:

- single-player Survival
- `survival_reward_damage_seen == 0`
- `survival_reward_fire_seen == 0`
- `survival_elapsed_ms > 64000`
- `survival_reward_handout_enabled != 0`

To actually receive the weapon, the current weapon must still be Pistol
(`weapon_id == 1`).

Important edge case: if the timer gate passes while holding a non-pistol weapon,
the gate is still consumed (flags are set), but no Shrinkifier is granted.

Known table stats: clip `8`, shot cooldown `0.21s`, reload `1.22s`.

### Blade Gun (`weapon_id = 25`)

The centroid check runs when all of these are true:

- single-player Survival
- `survival_recent_death_count == 3`
- `survival_reward_fire_seen == 0`
- player distance to centroid of the first three recorded death positions is `< 16.0`
- player health is `< 15.0`

Centroid formula:

- `cx = (p0.x + p1.x + p2.x) * 0.33333334`
- `cy = (p0.y + p1.y + p2.y) * 0.33333334`

Important edge case: this check does not require
`survival_reward_handout_enabled != 0` and does not require
`survival_reward_damage_seen == 0`.

`creature_handle_death` sets `survival_reward_fire_seen = 0` and
`survival_reward_handout_enabled = 0` exactly when the recent-death counter
reaches `3`; that transition is what opens the Blade Gun path.

Known table stats: clip `6`, shot cooldown `0.35s`, reload `3.50s`, damage scale `11.0x`.

## Handout guard behavior

`survival_reward_weapon_guard_id` guards temporary handout ownership.
Each world step:

- if current weapon is Blade Gun (`25`) and guard is not `25`, force Pistol
- if current weapon is Shrinkifier 5k (`24`) and guard is not `24`, force Pistol

This guard is written by the handout grants and initialized at run reset.
It is not generally cleared just because you switched weapons.

## Splitter Gun

Splitter Gun (`weapon_id = 29`) is a persistent unlock, not a one-off handout.
It becomes available once hardcore quest progression reaches
`quest_unlock_index_full >= 40` (and demo mode is off).

## Other non-quest weapon candidates

Multiple named weapons exist in the weapon table but are not present in
`quest_unlock_weapon_id` progression. For these, no verified unlock path is
currently documented. See [weapon candidates](../re/static/secrets/weapon-candidates.md) for the current
candidate list and evidence notes.
