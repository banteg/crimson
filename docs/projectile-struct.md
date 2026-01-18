# Projectile struct

This map documents `projectile_pool` (`DAT_004926b8`).

Notes:

- Entry size: `0x40` bytes.
- Pool size: `0x60` entries (loop in `projectile_update`).
- Primary writers: `projectile_spawn` (`FUN_00420440`) and `projectile_update` (`FUN_00420b90`).
- Field arrays are labeled in the data map (e.g. `projectile_pos_x`, `projectile_type_id`,
  `projectile_life_timer`, `projectile_owner_id`) at `projectile_pool` + offsets.

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
| 0x30 | damage pool / pierce budget | Seeded to `1.0` for most types; special cases set `300` (type `6`), `240` (type `0x2d`), or `50` (type `0x19`). Decremented on hit and used as the damage parameter for multi-hit projectiles. |
| 0x34 | hit_radius | Passed into `creature_find_in_radius` and `creatures_apply_radius_damage`. Set to `3.0` for type `0x16`, `5.0` for type `0x15`, and `10.0` for type `0x17/0x1c` (default `1.0`). |
| 0x38 | base_damage / weapon meta | Copied from `weapon_projectile_meta[type_id]`; no direct reads observed yet. |
| 0x3c | owner_id | Stored on spawn; used to skip the shooter in hit tests. |

Related tables:

- `DAT_004d7a28` is consulted during `projectile_update` to gate one of the hit
  effect paths (value `4` skips it).
- `weapon_projectile_damage_scale` is used as the damage scale for each `type_id`.
- `weapon_projectile_meta` is copied into the projectile entry on spawn and shares the
  same stride as the weapon table.
- `projectile_pool + 0x30` (`DAT_004926e8`) acts like a shared damage pool for
  piercing projectiles: it is decremented on hit and, if still positive, passed
  into `FUN_004207c0` as the damage value before subtracting the target's health.

Spawn notes:

- When Fire Bullets is active (`player_fire_bullets_timer` / `DAT_00490bcc > 0`
  or `player2_fire_bullets_timer` / `DAT_00490f2c > 0`) and the owner is a player (`owner_id == -100 / -1 / -2 / -3`), `projectile_spawn`
  forces `type_id` to `0x2d` regardless of the requested type.

Known type_id sources (partial):

| type_id | Sources | Notes |
| --- | --- | --- |
| `0x1` | Assault Rifle (id `0x1`); Flamethrower (id `0x7`) | Direct weapon spawn. |
| `0x2` | Weapon id `0x2` (unnamed in table) | Direct weapon spawn. |
| `0x3` | Sawed-off Shotgun (id `0x3`); Submachine Gun (id `0x4`); Ion Rifle (id `0x14`) | Pellet-style multi-spawn. |
| `0x5` | Gauss Gun (id `0x5`) | Direct weapon spawn. |
| `0x6` | Mean Minigun (id `0x6`); Ion Shotgun (id `0x1e`) | Direct spawn + spread variant. |
| `0x9` | Multi-Plasma (id `0x9`); Plasma Minigun (id `0x0a`); Fireblast bonus (id `8`) | Radial burst in `bonus_apply`. |
| `0x0b` | Rocket Launcher (id `0x0b`); Blow Torch (id `0x0e`); Plasma Minigun spread (id `0x0a`); Angry Reloader perk (id `50`) | Fired as single shots or radial bursts. |
| `0x13` | Jackhammer (id `0x13`) | Direct weapon spawn. |
| `0x15` | Ion Minigun weapon (id `0x15`); Man Bomb perk (id `53`); Shock Chain bonus (id `7`) | Beam/chain segment types. |
| `0x16` | Ion Cannon weapon (id `0x16`); Flameburst weapon (id `0x1f`); Man Bomb perk (id `53`) | Beam/chain segment type. |
| `0x17` | Shrinkifier 5k (id `0x17`) | Beam segment type. |
| `0x18` | Blade Gun (id `0x18`) | Direct weapon spawn. |
| `0x19` | Spider Plasma (id `0x19`) | Direct weapon spawn. |
| `0x1c` | Splitter Gun weapon (id `0x1c`) | Direct weapon spawn. |
| `0x1d` | Gauss Shotgun (id `0x1d`) | Direct weapon spawn. |
| `0x2d` | Fire Bullets bonus (id `14`); Fire Cough perk (id `54`) | Forced on player shots when Fire Bullets is active. |
| `0x29` | Bubblegun weapon (id `0x29`) | Direct weapon spawn. |
| `0x2b` | Grim Weapon (id `0x2b`) | Direct weapon spawn. |

Non-projectile weapon paths (player_update):

| Weapon id | Name | Path | Notes |
| --- | --- | --- | --- |
| `0x8` | Plasma Rifle | `fx_spawn_particle` | Emits particle shots; no `projectile_spawn`. |
| `0xf` | HR Flamer | `fx_spawn_particle` | Sets particle flag `1` in `DAT_00493ee8`. |
| `0x10` | Mini-Rocket Swarmers | `fx_spawn_particle` | Sets particle flag `2` in `DAT_00493ee8`. |
| `0x0c` | Seeker Rockets | `fx_spawn_secondary_projectile` type `1` | Uses `secondary_projectile_pool` (`DAT_00495ad8`). |
| `0x0d` | Plasma Shotgun | `fx_spawn_secondary_projectile` type `2` | Uses the secondary projectile pool. |
| `0x11` | Rocket Minigun | `fx_spawn_secondary_projectile` type `2` | Spawns multiple secondaries per shot. |
| `0x12` | Pulse Gun | `fx_spawn_secondary_projectile` type `4` | Uses the secondary projectile pool. |
| `0x2a` | Rainbow Gun | `fx_spawn_particle_slow` | Particle-only path. |

See [Effects pools](effects-struct.md) for secondary projectile type behaviors and particle style ids.

## Rendering notes

`projectile_render` uses `type_id` to select atlas frames in
`artifacts/assets/crimson/game/projs.png`. See [Sprite atlas cutting](atlas.md) for the
current frame mapping table.

Some beam/chain effects override UVs with `grim_set_uv_point` to draw a thin
strip from inside `projs.png` (see the atlas notes for the grid2 sub-cut).
The overlays in [Sprite atlas cutting](atlas.md) show the exact UV slice.
