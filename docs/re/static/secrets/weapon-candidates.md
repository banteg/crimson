---
tags:
  - status-analysis
---

# Secret weapon candidates

This document lists weapons that are not unlocked through the standard quest
progression, making them candidates for "Secret Weapons" or unfinished content.

## Methodology

1. **Full Weapon List**: Derived from [weapon-id-map](../../../re/static/reference/weapon-id-map.md) (1-based ids 1-53;
   id 0 is the dummy/none entry).

2. **Quest Unlocks**: Analyzed `quest_database_init` (`FUN_00439230`) in
   `crimsonland.exe`.

   - Each quest entry is initialized via `FUN_00430a20`.
   - `quest_unlock_weapon_id` is at offset `0x24` (set by
     `*(undefined4 *)(quest_meta_cursor + 0x24) = ...`).

   - `FUN_00430a20` sets the tier, index, and name; it does not set unlock IDs.
   - The unlock IDs are set after the `FUN_00430a20` call in
     `quest_database_init`.

   - Many quests store `0` in the unlock slot; with the 1-based ID scheme,
     `0` maps to the dummy entry (no weapon).

## Unlock Array Analysis (from `quest_database_init` tail)

The decompilation shows a series of assignments starting around line 27063.
Structure: `quest_unlock_weapon_id` is at `0x00484754`. The stride is `0x2c`.
So `quest_unlock_weapon_id` for quest `i` is at `0x00484754 + i * 0x2c`.

The "flat" assignments at the end of the function target addresses that line up
with this stride:

- `quest_unlock_weapon_id` = `0x00484754` (quest 0 unlock slot)
- `DAT_00484780` = `0x00484754 + 0x2c` = `0x00484780`
- `_DAT_004847ac` = `0x00484780 + 0x2c` = `0x004847ac`

### Quest Unlock List (weapon_id values are 1-based)

| Quest Idx | Address | Value (Dec) | Value (Hex) | Weapon Name |
| :--- | :--- | :--- | :--- | :--- |
| 0 | `quest_unlock_weapon_id` | 2 | `0x02` | Assault Rifle |
| 1 | `DAT_00484780` | 3 | `0x03` | Shotgun |
| 2 | `_DAT_004847ac` | 0 | `0x00` | None (dummy entry) |
| 3 | `_DAT_004847d8` | 8 | `0x08` | Flamethrower |
| 4 | `_DAT_00484804` | 0 | `0x00` | None (dummy entry) |
| 5 | `_DAT_00484830` | 5 | `0x05` | Submachine Gun |
| 6 | `_DAT_0048485c` | 0 | `0x00` | None (dummy entry) |
| 7 | `_DAT_00484888` | 6 | `0x06` | Gauss Gun |
| 8 | `_DAT_004848b4` | 0 | `0x00` | None (dummy entry) |
| 9 | `_DAT_004848e0` | 12 | `0x0c` | Rocket Launcher |
| 10 | `_DAT_0048490c` | 0 | `0x00` | None (dummy entry) |
| 11 | `_DAT_00484938` | 9 | `0x09` | Plasma Rifle |
| 12 | `_DAT_00484964` | 0 | `0x00` | None (dummy entry) |
| 13 | `_DAT_00484990` | 21 | `0x15` | Ion Rifle |
| 14 | `_DAT_004849bc` | 0 | `0x00` | None (dummy entry) |
| 15 | `_DAT_004849e8` | 7 | `0x07` | Mean Minigun |
| 16 | `_DAT_00484a14` | 0 | `0x00` | None (dummy entry) |
| 17 | `_DAT_00484a40` | 4 | `0x04` | Sawed-off Shotgun |
| 18 | `_DAT_00484a6c` | 0 | `0x00` | None (dummy entry) |
| 19 | `_DAT_00484a98` | 11 | `0x0b` | Plasma Minigun |
| 20 | `_DAT_00484ac4` | 0 | `0x00` | None (dummy entry) |
| 21 | `_DAT_00484af0` | 10 | `0x0a` | Multi-Plasma |
| 22 | `_DAT_00484b1c` | 0 | `0x00` | None (dummy entry) |
| 23 | `_DAT_00484b48` | 13 | `0x0d` | Seeker Rockets |
| 24 | `_DAT_00484b74` | 0 | `0x00` | None (dummy entry) |
| 25 | `_DAT_00484ba0` | 15 | `0x0f` | Blow Torch |
| 26 | `_DAT_00484bcc` | 0 | `0x00` | None (dummy entry) |
| 27 | `_DAT_00484bf8` | 18 | `0x12` | Rocket Minigun |
| 28 | `_DAT_00484c24` | 0 | `0x00` | None (dummy entry) |
| 29 | `_DAT_00484c50` | 20 | `0x14` | Jackhammer |
| 30 | `_DAT_00484c7c` | 0 | `0x00` | None (dummy entry) |
| 31 | `_DAT_00484ca8` | 19 | `0x13` | Pulse Gun |
| 32 | `_DAT_00484cd4` | 0 | `0x00` | None (dummy entry) |
| 33 | `_DAT_00484d00` | 14 | `0x0e` | Plasma Shotgun |
| 34 | `_DAT_00484d2c` | 0 | `0x00` | None (dummy entry) |
| 35 | `_DAT_00484d58` | 17 | `0x11` | Mini-Rocket Swarmers |
| 36 | `_DAT_00484d84` | 0 | `0x00` | None (dummy entry) |
| 37 | `_DAT_00484db0` | 22 | `0x16` | Ion Minigun |
| 38 | `_DAT_00484ddc` | 0 | `0x00` | None (dummy entry) |
| 39 | `_DAT_00484e08` | 23 | `0x17` | Ion Cannon |
| 40 | `_DAT_00484e34` | 31 | `0x1f` | Ion Shotgun |
| 41 | `_DAT_00484e60` | 0 | `0x00` | None (dummy entry) |
| 42 | `_DAT_00484e8c` | 0 | `0x00` | None (dummy entry) |
| 43 | `_DAT_00484eb8` | 30 | `0x1e` | Gauss Shotgun |
| 44 | `_DAT_00484ee4` | 0 | `0x00` | None (dummy entry) |
| 45 | `_DAT_00484f10` | 0 | `0x00` | None (dummy entry) |
| 46 | `_DAT_00484f3c` | 0 | `0x00` | None (dummy entry) |
| 47 | `_DAT_00484f68` | 0 | `0x00` | None (dummy entry) |
| 48 | `_DAT_00484f94` | 0 | `0x00` | None (dummy entry) |
| 49 | `_DAT_00484fc0` | 28 | `0x1c` | Plasma Cannon |

### Unlocked List (Summary)

2, 3, 8, 5, 6, 12, 9, 21, 7, 4, 11, 10, 13, 15, 18, 20, 19, 14, 17, 22, 23, 31, 30, 28.

### Always Available? (Checking `weapon_refresh_available`)

`weapon_refresh_available` clears the availability flags and then sets entry 1
available before it processes the unlock list:

- Entry 0 is the dummy/none weapon.
- Entry 1 is Pistol, so Pistol is always available.
- In `_config_game_mode == 1`, it also sets entry 2 (Assault Rifle), entry 3
  (Shotgun), and entry 5 (Submachine Gun) available.

This means `quest_unlock_weapon_id = 0` is effectively "no weapon unlock", and
some basic weapons can be available even if they never appear in the unlock
array.

### Missing Named Weapons (not in `quest_unlock_weapon_id`)

Named weapon IDs that do not appear in the quest unlock list:

- 1 (Pistol) - default available (see above)
- 16 (HR Flamer)
- 24 (Shrinkifier 5k)
- 25 (Blade Gun)
- 26 (Spider Plasma)
- 27 (Evil Scythe)
- 29 (Splitter Gun)
- 32 (Flameburst)
- 33 (RayGun)
- 41 (Plague Sphreader Gun)
- 42 (Bubblegun)
- 43 (Rainbow Gun)
- 44 (Grim Weapon)
- 45 (Fire bullets)
- 50 (Transmutator)
- 51 (Blaster R-300)
- 52 (Lighting Rifle)
- 53 (Nuke Launcher)

Unknown/unlabelled ranges (no names in `weapon_table_init`): 34-40 and 46-49.

### Candidate List (Detailed Stats)

The following named weapons are absent from the standard quest unlock sequence
(excluding default Pistol). Stats derived from `weapon_table` analysis:

| ID | Name | Clip | Fire Rate | Reload | Notes |
| -- | -- | -- | -- | -- | -- |
| 16 | HR Flamer | 30 | 0.01s | 1.80s | Flag 0x8. |
| 24 | Shrinkifier 5k | 8 | 0.21s | 1.22s | Damage 0.0x. Flag 0x8. |
| 25 | Blade Gun | 6 | 0.35s | 3.50s | Damage 11.0x. Projectile 20. Flag 0x8. |
| 26 | Spider Plasma | 5 | 0.20s | 1.20s | Damage 0.5x. Projectile 10. Flag 0x8. |
| 27 | Evil Scythe | 3 | 1.00s | 3.00s | Wide spread (0.68). |
| 29 | Splitter Gun | 6 | 0.70s | 2.20s | Damage 6.0x. Projectile 30. |
| 32 | Flameburst | 60 | 0.02s | 3.00s | - |
| 33 | RayGun | 12 | 0.70s | 2.00s | - |
| 41 | Plague Sphreader Gun | 5 | 0.20s | 1.20s | Damage 0.0x. Projectile 15. Flag 0x8. |
| 42 | Bubblegun | 15 | 0.16s | 1.20s | Flag 0x8. |
| 43 | Rainbow Gun | 10 | 0.20s | 1.20s | Projectile 10. Flag 0x8. |
| 44 | Grim Weapon | 3 | 0.50s | 1.20s | - |
| 45 | Fire bullets | 112 | 0.14s | 1.20s | Damage 0.25x. Projectile 60. Flag 0x1. |
| 50 | Transmutator | 50 | 0.04s | 5.00s | Flag 0x9. |
| 51 | Blaster R-300 | 20 | 0.08s | 2.00s | Flag 0x9. |
| 52 | Lighting Rifle | 500 | 4.00s | 8.00s | Flag 0x8. |
| 53 | Nuke Launcher | 1 | 4.00s | 8.00s | Flag 0x8. |

**Observations:**

- Weapons 41-53 often have missing or reused SFX ids (`_DAT_...`) and odd stats.
- "Plague Sphreader" does 0 damage and likely relies on the Plague mechanic
  (see Plaguebearer perk).

- "Fire bullets" is a named weapon entry with projectile type 60 and low damage
  scale; likely a bonus/test entry.

## Start Weapon Analysis

Check `quest_start_weapon_id` (offset 0x28) assignments in `quest_database_init`.

- `s_Land_Hostile`: `*(undefined4 *)(quest_meta_cursor + 0x28) = 1;` -> **Pistol (1)**.
- `s_Minor_Alien_Breach`: `... = 1;`
- ... many `1`s.
- `s_Survival_Of_The_Fastest`: `... = 5;` (Submachine Gun)
- Other distinct values: `6` (Gauss Gun), `0xb` (Plasma Minigun),
  `0x12` (Rocket Minigun).

This suggests **Pistol (1)** is the default start weapon, with a few quests
forcing specific weapons.

## Conclusion for Candidates

Weapons not present in the quest unlock table (excluding default Pistol) are:

- HR Flamer (16)
- Shrinkifier 5k (24)
- Blade Gun (25)
- Spider Plasma (26)
- Evil Scythe (27)
- Splitter Gun (29)
- Flameburst (32)
- RayGun (33)
- Plague Sphreader Gun (41)
- Bubblegun (42)
- Rainbow Gun (43)
- Grim Weapon (44)
- Fire bullets (45)
- Transmutator (50)
- Blaster R-300 (51)
- Lighting Rifle (52)
- Nuke Launcher (53)

Two of these candidates now have verified runtime acquisition logic in Survival:
Shrinkifier 5k (24) and Blade Gun (25). See
`docs/re/static/secrets/survival-weapon-handouts.md`.

The late-ID block (RayGun and 41+, plus 50+) still looks like the strongest
"secret/debug weapon" cluster. The midrange misses (HR Flamer, Shrinkifier,
Splitter, Flameburst, Fire bullets) may be normal weapons unlocked via other
mechanisms and need confirmation.
