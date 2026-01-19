# Secret Weapon Candidates

This document lists weapons that are **not** unlocked through the standard quest progression, making them candidates for "Secret Weapons" or unfinished content.

## Methodology

1.  **Full Weapon List**: Derived from `docs/weapon-id-map.md` (ids 0-52).
2.  **Quest Unlocks**: Analyzed `quest_database_init` (`FUN_00439230`) in `crimsonland.exe`.
    - Each quest entry is initialized via `FUN_00430a20`.
    - `quest_unlock_weapon_id` is at offset `0x24` (set by `*(undefined4 *)(quest_meta_cursor + 0x24) = ...`).
    - Note: The decompiler output for `quest_database_init` sets offsets like `0x28` (start weapon) and `0x8` (time limit), but explicit `0x24` assignments are less frequent or done via the `FUN_00430a20` calls if the stride is consistent.
    - **Wait**: `FUN_00430a20` signature is `void FUN_00430a20(int *param_1, int param_2, uint param_3, uint *param_4)`. It sets the tier, index, and name. It *does not* set the unlock IDs.
    - **Correction**: The unlock IDs are set *after* the `FUN_00430a20` call in `quest_database_init`.
    - Looking at the decompiled code, we see assignments like `*(undefined4 *)(quest_meta_cursor + 0x28) = 1;` (Start Weapon).
    - We *don't* see explicit `0x24` assignments in the provided snippet for *every* quest.
    - **Hypothesis**: Many quests don't unlock a weapon (value 0/none?).
    - However, there is a block at the *end* of `quest_database_init` (lines 27063+) that initializes a large block of globals:
      - `quest_unlock_weapon_id = 2;` (Global var? No, likely the array start)
      - `DAT_00484780 = 3;` ...
      - This looks like a manual array initialization or a "flat" assignment to the unlock array `DAT_00484754`.

## Unlock Array Analysis (from `quest_database_init` tail)

The decompilation shows a series of assignments starting around line 27063.
Structure: `quest_unlock_weapon_id` is at `0x00484754`. The stride is `0x2c`.
So `quest_unlock_weapon_id` for quest `i` is at `0x00484754 + i * 0x2c`.

Let's trace the "flat" assignments at the end of the function.
They seem to be writing to globals that might be aliased to the array if the decompiler got confused, OR they are initializing a separate lookup table.
Actually, look at the addresses:
- `quest_unlock_weapon_id` = `0x00484754` (Quest 0 unlock?)
- `DAT_00484780` = `0x00484754 + 0x2c` = `0x00484780`. **Confirmed**.
- `_DAT_004847ac` = `0x00484780 + 0x2c` = `0x004847ac`. **Confirmed**.

This confirms the tail of `quest_database_init` manually fills the unlock slots!

### Quest Unlock List

| Quest Idx | Address | Value (Dec) | Value (Hex) | Weapon Name (from ID map) |
| :--- | :--- | :--- | :--- | :--- |
| 0 | `quest_unlock_weapon_id` | 2 | `0x02` | Shotgun |
| 1 | `DAT_00484780` | 3 | `0x03` | Sawed-off Shotgun |
| 2 | `_DAT_004847ac` | 0 | `0x00` | (None/Pistol?) - Likely 0 means "None" here if 0 is Pistol? Or is 0 Pistol? ID map says 0 is Pistol. Quest logic likely ignores 0 or 0 is default available. |
| 3 | `_DAT_004847d8` | 8 | `0x08` | Plasma Rifle |
| 4 | `_DAT_00484804` | 0 | `0x00` | |
| 5 | `_DAT_00484830` | 5 | `0x05` | Gauss Gun |
| 6 | `_DAT_0048485c` | 0 | `0x00` | |
| 7 | `_DAT_00484888` | 6 | `0x06` | Mean Minigun |
| 8 | `_DAT_004848b4` | 0 | `0x00` | |
| 9 | `_DAT_004848e0` | 12 | `0x0c` | Seeker Rockets |
| 10 | `_DAT_0048490c` | 0 | `0x00` | |
| 11 | `_DAT_00484938` | 9 | `0x09` | Multi-Plasma |
| 12 | `_DAT_00484964` | 0 | `0x00` | |
| 13 | `_DAT_00484990` | 21 | `0x15` | Ion Minigun |
| 14 | `_DAT_004849bc` | 0 | `0x00` | |
| 15 | `_DAT_004849e8` | 7 | `0x07` | Flamethrower |
| 16 | `_DAT_00484a14` | 0 | `0x00` | |
| 17 | `_DAT_00484a40` | 4 | `0x04` | Submachine Gun |
| 18 | `_DAT_00484a6c` | 0 | `0x00` | |
| 19 | `_DAT_00484a98` | 11 | `0x0b` | Rocket Launcher |
| 20 | `_DAT_00484ac4` | 0 | `0x00` | |
| 21 | `_DAT_00484af0` | 10 | `0x0a` | Plasma Minigun |
| 22 | `_DAT_00484b1c` | 0 | `0x00` | |
| 23 | `_DAT_00484b48` | 13 | `0x0d` | Plasma Shotgun |
| 24 | `_DAT_00484b74` | 0 | `0x00` | |
| 25 | `_DAT_00484ba0` | 15 | `0x0f` | HR Flamer |
| 26 | `_DAT_00484bcc` | 0 | `0x00` | |
| 27 | `_DAT_00484bf8` | 18 | `0x12` | Pulse Gun |
| 28 | `_DAT_00484c24` | 0 | `0x00` | |
| 29 | `_DAT_00484c50` | 20 | `0x14` | Ion Rifle |
| 30 | `_DAT_00484c7c` | 0 | `0x00` | |
| 31 | `_DAT_00484ca8` | 19 | `0x13` | Jackhammer |
| 32 | `_DAT_00484cd4` | 0 | `0x00` | |
| 33 | `_DAT_00484d00` | 14 | `0x0e` | Blow Torch |
| 34 | `_DAT_00484d2c` | 0 | `0x00` | |
| 35 | `_DAT_00484d58` | 17 | `0x11` | Rocket Minigun |
| 36 | `_DAT_00484d84` | 0 | `0x00` | |
| 37 | `_DAT_00484db0` | 22 | `0x16` | Ion Cannon |
| 38 | `_DAT_00484ddc` | 0 | `0x00` | |
| 39 | `_DAT_00484e08` | 23 | `0x17` | Shrinkifier 5k |
| 40 | `_DAT_00484e34` | 31 | `0x1f` | Flameburst |
| 41 | `_DAT_00484e60` | 0 | `0x00` | |
| 42 | `_DAT_00484e8c` | 0 | `0x00` | |
| 43 | `_DAT_00484eb8` | 30 | `0x1e` | Ion Shotgun |
| 44 | `_DAT_00484ee4` | 0 | `0x00` | |
| 45 | `_DAT_00484f10` | 0 | `0x00` | |
| 46 | `_DAT_00484f3c` | 0 | `0x00` | |
| 47 | `_DAT_00484f68` | 0 | `0x00` | |
| 48 | `_DAT_00484f94` | 0 | `0x00` | |
| 49 | `_DAT_00484fc0` | 28 | `0x1c` | Splitter Gun |

### Unlocked List (Summary)
2, 3, 8, 5, 6, 12, 9, 21, 7, 4, 11, 10, 13, 15, 18, 20, 19, 14, 17, 22, 23, 31, 30, 28.

### Always Available? (Checking `weapon_refresh_available`)
`weapon_refresh_available` sets flags based on the unlock list.
Usually, starting weapons (Pistol) are available by default.
`weapon_table` entry 0 is "Pistol".
Is Pistol (ID 0) ever unlocked?
The list above has 0s. Does 0 mean "No Unlock" or "Unlock Pistol"?
Given "Pistol" is usually default, 0 probably means "No *new* unlock".
Wait, `weapon_refresh_available` logic:
`if 0 < quest_unlock_index ... loop ... (&DAT_004d7a6c)[id * 0x7c] = 1;`
If `id` is 0, it unlocks Pistol.
If `id` is used as "None", how does it distinguish?
Usually games use -1 for None.
If 0 is stored in the array, it re-unlocks Pistol (harmless).
BUT, if a quest is meant to give *nothing*, storing 0 would trigger a "You got a new weapon: Pistol!" message if the message logic isn't careful.
However, `weapon_refresh_available` just sets the *available* flag.
Start weapons (Pistol) might be hardcoded as available or unlocked by default elsewhere.
Actually, `weapon_refresh_available` might *clear* everything first?
Yes: `do { *puVar2 = 0; ... }` clears availability.
Then it iterates the quest list up to `quest_unlock_index`.
So if `quest_unlock_weapon_id` is 0, it enables Weapon 0 (Pistol).
This implies Pistol is "unlocked" by many quests? That seems redundant.
Or maybe `quest_unlock_index` determines *how many* quests are considered.
Ah, `quest_unlock_index` is the *count* of completed quests (or max index).
It iterates `iVar5 = 0` to `quest_unlock_index`.
So if you beat quest 2, you get the unlocks from quest 0, 1, and 2.
If quest 2 has unlock ID 0, you get Pistol.
This confirms Pistol (0) is technically an "unlockable" but since you start with it, it's trivial.
**Except:** Is Pistol actually ID 0? Yes.
Is Assault Rifle (ID 1) in the list? No.
Wait, `Assault Rifle` (ID 1) is NOT in the quest unlock list above?
Let's check.
IDs found: 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 28, 30, 31.
Missing from range 0-32 (Named weapons):
- 0 (Pistol) - Default?
- 1 (Assault Rifle) - **Missing!**
- 16 (Mini-Rocket Swarmers) - **Missing!**
- 24 (Blade Gun) - **Missing!**
- 25 (Spider Plasma) - **Missing!**
- 26 (Evil Scythe) - **Missing!**
- 27 (Plasma Cannon) - **Missing!**
- 29 (Gauss Shotgun) - **Missing!**
- 32 (RayGun) - **Missing!**

Also 33-52 are "Unknown/Unlabelled" or special.
- 40 (Plague Sphreader)
- 41 (Bubblegun)
- 42 (Rainbow Gun)
- 43 (Grim Weapon)
- 44 (Fire bullets)
- 49 (Transmutator)
- 50 (Blaster R-300)
- 51 (Lighting Rifle)
- 52 (Nuke Launcher)

### Candidate List (Detailed Stats)

The following named weapons appear to be **absent** from the standard quest unlock sequence. Stats derived from `weapon_table` analysis:

| ID | Name | Clip | Fire Rate | Reload | Notes |
| -- | -- | -- | -- | -- | -- |
| 16 | Mini-Rocket Swarmers | 5 | 1.80s | 1.80s | Fast fire but limited clip? |
| 24 | Blade Gun | 6 | 0.35s | 3.50s | High damage (11.0x), Projectile Type 20. |
| 25 | Spider Plasma | 5 | 0.20s | 1.20s | Low damage (0.5x), likely spawns spiders? |
| 26 | Evil Scythe | 3 | 1.00s | 3.00s | Wide spread (0.68), no damage mult? |
| 27 | Plasma Cannon | 3 | 0.90s | 2.70s | Massive damage (28.0x), high spread. |
| 29 | Gauss Shotgun | 4 | 1.05s | 2.10s | Similar to Shotgun but Gauss. |
| 32 | RayGun | 12 | 0.70s | 2.00s | Standard raygun. |
| 40 | Plague Sphreader Gun | 5 | 0.20s | 1.20s | Damage 0.0x. Flag 8. Projectile 15. Likely status effect. |
| 41 | Bubblegun | 15 | 0.16s | 1.20s | Very low spread (0.05). Flag 8. |
| 42 | Rainbow Gun | 10 | 0.20s | 1.20s | Projectile 10. Flag 8. |
| 43 | Grim Weapon | 3 | 0.50s | 1.20s | "Grim" branding. Flag 0 (None). |
| 49 | Transmutator | 50 | 0.04s | 5.00s | Very fast fire, long reload. Flag 9. |
| 50 | Blaster R-300 | 20 | 0.08s | 2.00s | Fast blaster. Flag 9. |
| 51 | Lighting Rifle | 500 | 4.00s | 8.00s | Huge clip, very slow. Debug weapon? |
| 52 | Nuke Launcher | 1 | 4.00s | 8.00s | 1 shot nuke. Flag 8. |

**Observations:**
- Weapons 40-52 often have missing sounds (`_DAT_...`) or reuse generic ones.
- "Grim Weapon" (43) shares its name with the `grim.dll` engine, possibly a developer tool.
- "Plague Sphreader" doing 0 damage suggests it relies on the "Plague" mechanic (see "Plaguebearer" perk).

## Start Weapon Analysis

Check `quest_start_weapon_id` (offset 0x28) assignments in `quest_database_init`.
- `s_Land_Hostile`: `*(undefined4 *)(quest_meta_cursor + 0x28) = 1;` -> **Assault Rifle (1)**.
- `s_Minor_Alien_Breach`: `... = 1;`
- ... many `1`s.
- `s_Evil_Zombies_At_Large`: `... = 1;`
- `s_Survival_Of_The_Fastest`: `... = 5;` (Gauss Gun)
- `s_Spideroids`: `... = 1;`
- `s_The_Unblitzkrieg`: `... = 1;`
- `s_The_Spanking_Of_The_Dead`: `... = 1;`
- `s_Knee_deep_in_the_Dead`: `... = 1;`
- `s_Cross_Fire`: `... = 1;`
- `s_Army_of_Three`: `... = 1;`
- `s_Monster_Blues`: `... = 1;`
- `s_Nagolipoli`: `... = 1;`
- `s_The_Gathering`: `... = 1;`

This confirms **Assault Rifle (1)** is the default starting weapon for almost all quests, explaining why it doesn't need an "unlock" entry (it's provided by the mode/quest config).

## Conclusion for Candidates

The *true* secret/missing weapons are likely:
- **Mini-Rocket Swarmers (16)**
- **Blade Gun (24)**
- **Spider Plasma (25)**
- **Evil Scythe (26)**
- **Plasma Cannon (27)**
- **Gauss Shotgun (29)**
- **RayGun (32)**
- **Plague Sphreader (40)**
- **Bubblegun (41)**
- **Rainbow Gun (42)**
- **Grim Weapon (43)**
- **Transmutator (49)**
- **Blaster R-300 (50)**
- **Lighting Rifle (51)**
- **Nuke Launcher (52)**

This list matches the "Secret Weapons" rumors (e.g. Splitter Gun is 28 and IS in the list, wait. 28 is Splitter Gun. Is 28 in the unlock list?
`_DAT_00484fc0 = 28;` (Entry 49, last one). Yes, Splitter Gun is unlocked by the final quest ("The Gathering" or similar).
So Splitter Gun is NOT a secret weapon (just late game).

I will write this analysis to `docs/secret-weapon-candidates.md`.
