# Projectile struct

This map documents the projectile pool at `DAT_004926b8`.

Notes:

- Entry size: `0x40` bytes.
- Pool size: `0x60` entries (loop in `projectile_update`).
- Primary writers: `projectile_spawn` (`FUN_00420440`) and `projectile_update` (`FUN_00420b90`).

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | active (byte) | Set to `1` on spawn; cleared when lifetime expires in `projectile_update`. |
| 0x04 | angle | Set from spawn angle; used for `cos/sin` movement vectors. |
| 0x08 | pos_x | Set from `pos[0]` on spawn; updated per tick. |
| 0x0c | pos_y | Set from `pos[1]` on spawn; updated per tick. |
| 0x10 | origin_x | Initialized to spawn position; used to compute distance traveled. |
| 0x14 | origin_y | Initialized to spawn position; used to compute distance traveled. |
| 0x18 | vel_x | Set to `cos(angle) * 1.5` on spawn. |
| 0x1c | vel_y | Set to `sin(angle) * 1.5` on spawn. |
| 0x20 | type_id | Spawn parameter; drives branching in `projectile_update`. |
| 0x24 | life_timer | Starts at `0.4`, decremented each frame; when <= 0, the entry clears. |
| 0x28 | unused / reserved | Zeroed on spawn; no reads observed yet. |
| 0x2c | speed_scale | Multiplier applied to movement step in `projectile_update`. |
| 0x30 | damage pool / pierce budget | Seeded to `1.0` for most types; special cases get large budgets (300/240/50). Decremented on hit and used as the damage parameter for multi-hit projectiles. |
| 0x34 | hit_radius | Passed into `creature_find_in_radius` and `creatures_apply_radius_damage`. |
| 0x38 | base_damage / weapon meta | Copied from `DAT_004d7a98[type_id]`; no direct reads observed yet. |
| 0x3c | owner_id | Stored on spawn; used to skip the shooter in hit tests. |

Related tables:

- `DAT_004d7a28` is consulted during `projectile_update` to gate one of the hit
  effect paths (value `4` skips it).
- `DAT_004d7a9c` is used as the damage scale for each `type_id`.
- `DAT_004d7a98` is copied into the projectile entry on spawn and shares the
  same stride as the weapon table.
- `DAT_004926e8` (offset `0x30`) acts like a shared damage pool for piercing
  projectiles: it is decremented on hit and, if still positive, passed into
  `FUN_004207c0` as the damage value before subtracting the target's health.

## Rendering notes

`projectile_render` uses `type_id` to select atlas frames in
`assets/crimson/game/projs.png`. See [Sprite atlas cutting](atlas.md) for the
current frame mapping table.

Some beam/chain effects override UVs with `grim_set_uv_point` to draw a thin
strip from inside `projs.png` (see the atlas notes for the grid2 sub-cut).
