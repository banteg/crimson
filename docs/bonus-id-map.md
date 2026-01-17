# Bonus ID map

This map is derived from `FUN_00412660`, which builds the bonus metadata table at `bonus_meta_label`.
The entry index is the bonus type id used by `bonus_apply` and `bonus_spawn_at`.

Table fields:

- `icon_id` comes from `bonus_meta_icon_id + id * 0x14`, used by `bonus_render` to select the icon sprite.
- `default_amount` comes from `bonus_meta_default_amount + id * 0x14`, used when `bonus_spawn_at` is called with
  `duration_override == -1`.

| ID | Name | Description | icon_id | default_amount | Notes |
| --- | --- | --- | --- | --- | --- |
| 0 | (unused) | — | — | — | `DAT_004853dc` is set to `0`, disabling this entry. |
| 1 | Points | You gain some experience points. | 12 | 500 | `bonus_apply` adds `default_amount` to score. |
| 2 | Energizer | Suddenly monsters run away from you and you can eat them. | 10 | 8 | `bonus_apply` updates `bonus_energizer_timer`. |
| 3 | Weapon | You get a new weapon. | -1 | 3 | `bonus_apply` treats `default_amount` as weapon id; often overridden. |
| 4 | Weapon Power Up | Your firerate and load time increase for a short period. | 7 | 10 | `bonus_apply` updates `bonus_weapon_power_up_timer`. |
| 5 | Nuke | An amazing explosion of ATOMIC power. | 1 | 0 | `bonus_apply` performs the large explosion + shake sequence. |
| 6 | Double Experience | Every experience point you get is doubled when this bonus is active. | 4 | 0 | `bonus_apply` updates `bonus_double_xp_timer`. |
| 7 | Shock Chain | Chain of shocks shock the crowd. | 3 | 0 | `bonus_apply` spawns chained lightning via `projectile_spawn` type `0x15`; `shock_chain_links_left` / `shock_chain_projectile_id` track the active chain. |
| 8 | Fireblast | Fireballs all over the place. | 2 | 0 | `bonus_apply` spawns a radial projectile burst (type `9`). |
| 9 | Reflex Boost | You get more time to react as the game slows down. | 5 | 3 | `bonus_apply` updates `bonus_reflex_boost_timer`. |
| 10 | Shield | Force field protects you for a while. | 6 | 7 | `bonus_apply` updates `DAT_00490bc8`. |
| 11 | Freeze | Monsters are frozen. | 8 | 5 | `bonus_apply` updates `bonus_freeze_timer`. |
| 12 | MediKit | You regain some of your health. | 14 | 10 | `bonus_apply` restores health in 10-point increments. |
| 13 | Speed | Your movement speed increases for a while. | 9 | 8 | `bonus_apply` updates `DAT_00490bc4`. |
| 14 | Fire Bullets | For few seconds -- make them count. | 11 | 4 | `bonus_apply` updates `DAT_00490bcc`. While active, `projectile_spawn` overrides player-owned projectiles to type `0x2d` (pellet count from `weapon_projectile_pellet_count[weapon_id]`). |
