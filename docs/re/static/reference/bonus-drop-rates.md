---
tags:
  - status-analysis
---

# Bonus drop rates

These rates come from `bonus_pick_random_type` (0x412470) and describe the
bonus type distribution once a bonus is about to spawn. They do not include
the per-kill spawn gate in `bonus_try_spawn_on_kill` (0x41f8d0).

## Picker logic (summary)

Source: `decomp/1.9/crimsonland/gameplay/bonus_pick_random_type.cpp:16-45`.

- `bucket = rand() % 0xA2 + 1` (1..162).
- Points (id 1) if `bucket <= 13` (13/162).
- `bucket == 14` draws `rand() & 0x3f`: Energizer (id 2) on 0 (1/10368),
  otherwise Weapon (id 3).
- `bucket` 15..134 map to ids 3..14 in steps of 10.
- `bucket` 135..162 (28/162) leave the id at 0. Entry 0 is disabled
  (`bonus_reset_availability`), so the pick is rerolled like any other
  blocked type. The loop does not wrap around to id 3.

## Distribution (per bonus pick, all bonuses enabled)

Out of 162 × 64 = 10368 raw outcomes, 1792 reroll and 8576 assign a type.
The chances below are per assigned pick.

| ID | Bonus | Weight (out of 8576) | Chance | Percent |
| --- | --- | --- | --- | --- |
| 1 | Points | 832 | 13/134 | 9.7015% |
| 2 | Energizer | 1 | 1/8576 | 0.0117% |
| 3 | Weapon | 703 | 703/8576 | 8.1973% |
| 4 | Weapon Power Up | 640 | 5/67 | 7.4627% |
| 5 | Nuke | 640 | 5/67 | 7.4627% |
| 6 | Double Experience | 640 | 5/67 | 7.4627% |
| 7 | Shock Chain | 640 | 5/67 | 7.4627% |
| 8 | Fireblast | 640 | 5/67 | 7.4627% |
| 9 | Reflex Boost | 640 | 5/67 | 7.4627% |
| 10 | Shield | 640 | 5/67 | 7.4627% |
| 11 | Freeze | 640 | 5/67 | 7.4627% |
| 12 | MediKit | 640 | 5/67 | 7.4627% |
| 13 | Speed | 640 | 5/67 | 7.4627% |
| 14 | Fire Bullets | 640 | 5/67 | 7.4627% |

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
