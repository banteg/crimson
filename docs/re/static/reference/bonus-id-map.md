---
tags:
  - status-analysis
---

# Bonus ID map

This map is derived from `bonus_metadata_init`, which builds the bonus metadata table at `bonus_meta_label`.
See also: [Bonus drop rates](bonus-drop-rates.md).
The entry index is the bonus type id used by `bonus_apply` and `bonus_spawn_at`.

Table fields:

- `icon_id` comes from `bonus_meta_icon_id + id * 0x14`, used by `bonus_render` to select the icon sprite.
- `icon_frame` maps `icon_id` to `bonuses.png` grid=4 frames in
  `artifacts/atlas/frames/game/bonuses/grid4/frame_{icon_id:03d}.png` (when `icon_id >= 0`).
  Bonus id `3` uses `icon_id = -1` and renders the weapon icon from `ui_weapon_icons_texture`.

- `description` comes from `bonus_meta_description + id * 0x14`, used for the bonus info strings.
- `default_amount` comes from `bonus_meta_default_amount + id * 0x14`, used when `bonus_spawn_at` is called with
  `duration_override == -1`.

- `enabled` comes from `bonus_meta_enabled + id * 0x14`; id `0` is cleared during init.

| ID | Name | Description | icon_id | icon_frame | default_amount | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | (unused) | — | — | — | — | `DAT_004853dc` is set to `0`, disabling this entry. |
| 1 | Points | You gain some experience points. | 12 | `frame_012.png` | 500 | `bonus_apply` adds `default_amount` to score. |
| 2 | Energizer | Suddenly monsters run away from you and you can eat them. | 10 | `frame_010.png` | 8 | `bonus_apply` updates `bonus_energizer_timer`. |
| 3 | Weapon | You get a new weapon. | -1 | weapon icon | 3 | `bonus_apply` treats `default_amount` as weapon id; often overridden. |
| 4 | Weapon Power Up | Your firerate and load time increase for a short period. | 7 | `frame_007.png` | 10 | `bonus_apply` updates `bonus_weapon_power_up_timer`. |
| 5 | Nuke | An amazing explosion of ATOMIC power. | 1 | `frame_001.png` | 0 | `bonus_apply` performs the large explosion + shake sequence. |
| 6 | Double Experience | Every experience point you get is doubled when this bonus is active. | 4 | `frame_004.png` | 0 | `bonus_apply` updates `bonus_double_xp_timer`. |
| 7 | Shock Chain | Chain of shocks shock the crowd. | 3 | `frame_003.png` | 0 | `bonus_apply`: plays `sfx_shock_hit_01`, sets `shock_chain_links_left = 0x20`, spawns the initial chain projectile (`type_id = 0x15`), and stores it in `shock_chain_projectile_id`.<br>`projectile_update`: when the active chain projectile hits, it spawns the next link immediately and targets `creature_find_nearest(projectile_pos, hit_creature_id, 100.0)` (**min** distance; candidates require `d > 100`, and there is no health gate). |
| 8 | Fireblast | Fireballs all over the place. | 2 | `frame_002.png` | 0 | `bonus_apply` spawns a radial projectile burst (type `9`). |
| 9 | Reflex Boost | You get more time to react as the game slows down. | 5 | `frame_005.png` | 3 | `bonus_apply` updates `bonus_reflex_boost_timer`. |
| 10 | Shield | Force field protects you for a while. | 6 | `frame_006.png` | 7 | `bonus_apply` updates `player_shield_timer` (`DAT_00490bc8`). |
| 11 | Freeze | Monsters are frozen. | 8 | `frame_008.png` | 5 | `bonus_apply` updates `bonus_freeze_timer`. |
| 12 | MediKit | You regain some of your health. | 14 | `frame_014.png` | 10 | `bonus_apply` restores health in 10-point increments. |
| 13 | Speed | Your movement speed increases for a while. | 9 | `frame_009.png` | 8 | `bonus_apply` updates `player_speed_bonus_timer` (`DAT_00490bc4`). |
| 14 | Fire Bullets | For few seconds -- make them count. | 11 | `frame_011.png` | 4 | `bonus_apply` updates `player_fire_bullets_timer` (`DAT_00490bcc`). While active, `projectile_spawn` overrides player-owned projectiles to type `0x2d` (pellet count from `weapon_projectile_pellet_count[weapon_id]`). |
