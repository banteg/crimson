---
tags:
  - status-analysis
---

# Bonus drop rates

These rates come from `bonus_pick_random_type` (0x412470) and describe the
bonus type distribution once a bonus is about to spawn. They do not include
the per-kill spawn gate in `bonus_try_spawn_on_kill` (0x41f8d0).

## Picker logic (summary)

- `r = rand() % 0xA2` (0..161).
- Points (id 1) if `r <= 12` (13/162).
- Energizer (id 2) if `r == 13` AND `(rand() & 0x3f) == 0` (1/10368).
- Otherwise, fall through to the bucketed ids 3..14 using `esi = r - 0x0d` and
  a 10-step loop. The loop repeats until an id is assigned; this produces the
  weights in the table below.

## Distribution (per bonus pick, all bonuses enabled)

| ID | Bonus | Weight (out of 10368) | Chance | Percent |
| --- | --- | --- | --- | --- |
| 1 | Points | 832 | 13/162 | 8.0247% |
| 2 | Energizer | 1 | 1/10368 | 0.0096% |
| 3 | Weapon | 1343 | 1343/10368 | 12.9533% |
| 4 | Weapon Power Up | 1280 | 10/81 | 12.3457% |
| 5 | Nuke | 1152 | 1/9 | 11.1111% |
| 6 | Double Experience | 640 | 5/81 | 6.1728% |
| 7 | Shock Chain | 640 | 5/81 | 6.1728% |
| 8 | Fireblast | 640 | 5/81 | 6.1728% |
| 9 | Reflex Boost | 640 | 5/81 | 6.1728% |
| 10 | Shield | 640 | 5/81 | 6.1728% |
| 11 | Freeze | 640 | 5/81 | 6.1728% |
| 12 | MediKit | 640 | 5/81 | 6.1728% |
| 13 | Speed | 640 | 5/81 | 6.1728% |
| 14 | Fire Bullets | 640 | 5/81 | 6.1728% |

## Reroll gates

`bonus_pick_random_type` rerolls until it finds an allowed type (up to 0x64
attempts, then falls back to id 1 / Points). The distribution above is
renormalized when these gates are active:

- `bonus_meta_enabled` disables id 0; all other ids are enabled in init.
- Shock Chain (7) is rerolled if `shock_chain_links_left > 0`.
- Freeze (11) is rerolled if `bonus_freeze_timer > 0`.
- Shield (10) is rerolled if either player shield timer is active.
- Weapon (3) is rerolled if `perk_id_my_favourite_weapon` is owned.
- MediKit (12) is rerolled if `perk_id_death_clock` is owned.
- Weapon (3) is also rerolled when `bonus_state` contains a type `0x0e` entry
  with state 0 (see the scan at the top of `bonus_pick_random_type`).

- In quest mode (`config_blob[0x18] == 3`), additional quest stage checks can
  suppress Nuke (5) and Freeze (11).
