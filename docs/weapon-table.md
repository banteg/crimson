# Weapon table (weapon_table_init)

**Status:** In progress

Weapon stats are initialized in `weapon_table_init` (`FUN_004519b0`) and stored
in a fixed‑stride table. The accessor `weapon_table_entry` (`FUN_0041fc60`)
returns a pointer to the name buffer at the start of each entry:

```
weapon_table (`DAT_004d7a2c`) + weapon_id * 0x1f
```

`0x1f` is a count of `u32` slots, so the stride is **0x7c bytes** per entry.
Entry `0` is a dummy (none); weapon id `1` (Pistol) starts at entry `1`.

Note: the returned pointer is **not** the first field of the entry.
There is a 4‑byte field at offset `-0x04` (`weapon_ammo_class` / `DAT_004d7a28`)
that is indexed with the same stride.

## Offsets (relative to entry base)

All offsets below are in **bytes**, relative to the pointer returned by
`FUN_0041fc60`.

| Offset | Type  | Meaning | Evidence |
| ------ | ----- | ------- | -------- |
| `-0x04` | int | Ammo class / HUD indicator | Used to choose `ui_ui_ind*` icons in the HUD: `0=bullet`, `1=fire`, `2=rocket`, else electric. |
| `0x00` | char[0x40] | Weapon name | String is copied inline during `weapon_table_init` and rendered in the HUD weapon list via `FUN_0041c4b0`. |
| `0x40` | byte | Unlocked/available flag | `FUN_00452e40` clears the table then marks unlocked weapons; `FUN_00452cd0` skips entries with `0`. |
| `0x44` | int | Clip size | Copied into `player_clip_size` (`DAT_00490b74`) on weapon swap and used to reset `player_ammo` (`DAT_00490b7c`). |
| `0x48` | float | Shot cooldown | Copied into `player_shot_cooldown` (`DAT_00490b84`) after firing in `player_fire_weapon`. |
| `0x4c` | float | Reload time | Loaded into `player_reload_timer` (`DAT_00490b80`) in `player_start_reload` (scaled by perks). |
| `0x50` | float | Spread / heat increment | Added to `player_spread_heat` (`DAT_00490b68`) after each shot (scaled by perks). |
| `0x58` | int | Shot SFX base id | Used with `0x5c` to pick a random fire SFX. |
| `0x5c` | int | Shot SFX variant count | `rand % count + base` in `player_fire_weapon`. |
| `0x60` | int | Reload / equip SFX id | Played when a reload starts and when swapping to the weapon. |
| `0x64` | int | HUD icon id | Passed into the HUD sprite selection (shifted by `<< 1`). |
| `0x68` | byte | Flags | Bit `0x1` triggers a muzzle flash / effect burst; bits `0x4/0x8` affect crosshair rendering. |
| `0x6c` | float | Projectile meta value | Copied into projectile entries on spawn (`weapon_projectile_meta`). |
| `0x70` | float | Damage scale | Used in projectile hit damage computation (`weapon_projectile_damage_scale`). |
| `0x74` | int | Pellet count | Number of pellets spawned in the spread fire path (`weapon_projectile_pellet_count`). |

## Notes

- Runtime probe (2026-01-18) sample entry confirms indexing scheme:
  - `weapon_id=2` (Assault Rifle) resolved to entry index **2**.
  - Observed fields: `clip_size=25`, `shot_cooldown=0.117`, `reload_time=1.2`, `spread_heat=0.09`,
    `shot_sfx_base=34`, `shot_sfx_count=1`, `reload_sfx=35`, `hud_icon_id=1`, `flags=1`,
    `projectile_meta=50`, `damage_scale=1`, `pellet_count=1`, `ammo_class=0` (from `-0x04`).

- UI text for weapons is pulled directly from the `weapon_table` name field (`offset 0x00`).
  Examples:
  - **HUD** (`ui_render_hud`): passes `&weapon_table + player_weapon_id * 0x1f` into
    `grim_text_width`/`grim_text_draw` (`grim_interface_ptr + 0x14c/0x144`), then draws the name.
  - **End‑of‑game stats**: uses `param_2 + 0x2b` (most‑used weapon id) to index
    `&weapon_table + id * 0x1f` for the “Most used weapon” label.
  - **Quest completion**: uses `quest_unlock_weapon_id` via `weapon_table_entry()` to render
    the unlocked weapon name.
  This means `ui_itemTexts.jaz` is **not** the weapon list source; it’s used for menu labels.
- Ammo class values (offset `-0x04`): `0` bullet (`ui_ui_indBullet.jaz`), `1` fire
  (`ui_ui_indFire.jaz`), `2` rocket (`ui_ui_indRocket.jaz`), `>= 3` electric
  (`ui_ui_indElectric.jaz`).
- Flag bits (offset `0x68`): `0x1` spawn muzzle flash / shot burst effect
  (`FUN_0042e120(0x12, ...)`), `0x4` use the smaller crosshair size, `0x8` hide
  the crosshair entirely.
- Pellet count (offset `0x74`, `weapon_projectile_pellet_count`) is used by the Fire Bullets bonus
  to spawn multiple `0x2d` pellets per shot.
- Several weapons bypass the main projectile pool and use particle or secondary
  projectile pools instead (Plasma Rifle `0x9`, HR Flamer `0x10`, Mini-Rocket
  Swarmers `0x11`, Seeker Rockets `0x0d`, Plasma Shotgun `0x0e`, Rocket Minigun
  `0x12`, Pulse Gun `0x13`, Rainbow Gun `0x2b`).
- Secondary projectile type behavior and particle style ids are tracked in
  [Effects pools](effects-struct.md).
- The alt-weapon swap stores per-player runtime state in parallel arrays:
  `player_alt_weapon_id` (`DAT_00490b8c`), `player_alt_clip_size` (`DAT_00490b90`),
  `player_alt_reload_active` (`DAT_00490b94`), `player_alt_ammo` (`DAT_00490b98`),
  `player_alt_reload_timer` (`DAT_00490b9c`), `player_alt_shot_cooldown`
  (`DAT_00490ba0`), and `player_alt_reload_timer_max` (`DAT_00490ba4`).
- The same stride is used by projectile metadata lookups (`weapon_projectile_meta`,
  `weapon_projectile_damage_scale`) keyed by projectile type ids in `projectile_spawn` and
  `projectile_update`.
- Many fields are only written in `FUN_004519b0`; only a subset are referenced
  by symbol elsewhere (reload/spread/sfx/flags/damage).
