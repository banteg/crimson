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

`bonus_pick_random_type` (`decomp/1.9/crimsonland/gameplay/bonus_pick_random_type.cpp`)
rerolls until it finds an allowed type (giving up after 100 rerolls and
returning id 1 / Points). The distribution above is renormalized when these
gates are active:

- `bonus_meta_table[].enabled`: `bonus_reset_availability` enables every id
  except 0.
- Shock Chain (7) is rerolled if `shock_chain_links_left > 0`.
- Freeze (11) is rerolled if `bonus_freeze_timer > 0`.
- Shield (10) is rerolled if either player shield timer is active.
- Weapon (3) is rerolled if `perk_id_my_favourite_weapon` is owned.
- MediKit (12) is rerolled if `perk_id_death_clock` is owned.
- Weapon (3) is also rerolled while a Fire Bullets (14) drop with state 0 is in
  `bonus_pool` (`has_fire_bullets_drop`, from the scan at the top of the
  function).

- In quest mode (`config_blob.game_mode == GAME_MODE_QUEST`):
  - Nuke (5) is rerolled in 2.10, 4.10, and 5.10, and also in 3.10 on hardcore.
  - Freeze (11) is rerolled in 4.10, and also in 2.10 on hardcore.
