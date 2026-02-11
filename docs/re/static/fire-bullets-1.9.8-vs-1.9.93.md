---
tags:
  - status-analysis
---

# Fire Bullets behavior comparison (1.9.8 vs 1.9.93)

## Scope

- Compare how Fire Bullets modifies player shots in Crimsonland **1.9.8** vs **1.9.93**.
- Include full per-weapon coverage (`weapon_id` `1..53`) and how each weapon combines with Fire Bullets.
- Cross-check against the rewrite (`src/crimson/gameplay.py`) for parity status.

## Evidence anchors

- **1.9.8 recursive add-on shot** (`sub_41fc20`): owner filter + `arg3 != 0x2d` guard + self-call with `0x2d`.

  - `crimsonland_1.9.8.txt:25166`
  - `crimsonland_1.9.8.txt:25170`
  - `crimsonland_1.9.8.txt:25188`

- In the exported 1.9.8 HLIL, the only direct `sub_41fc20(..., 0x2d, ...)` callsite is that self-call line above.
- **1.9.93 in-place override** (`projectile_spawn`): same owner filter, but rewrites local `type_id_1 = 0x2d` (no recursive spawn).

  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:27925`
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:27929`
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:27948`

- **1.9.93 dedicated Fire Bullets fire path in `player_update`**: paired SFX, pellet-count loop, single-pellet fallback cadence/spread.

  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:20782`
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:20797`
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:20803`
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:20812`
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:20838`

- Fire Bullets fallback constants initialized in weapon table init (`0.14`, `0.22`).

  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:67796`
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:67798`

- Weapon pellet-count field used by Fire Bullets logic.

  - `docs/weapon-table.md:102`

- Rewrite mirrors 1.9.93 behavior (in-place override + dedicated fire branch).

  - `src/crimson/gameplay.py:623`
  - `src/crimson/gameplay.py:831`

## Version-level comparison

### Hook location

- 1.9.8: `sub_41fc20` (projectile spawn).
- 1.9.93: `projectile_spawn` plus a dedicated Fire Bullets branch in `player_update`.

### Fire Bullets conversion model

- 1.9.8: additive recursion. An extra `0x2d` shot is spawned and the original shot remains.
- 1.9.93: replacement. Shot type is forced to `0x2d` instead of adding a second main projectile.

### `0x2d` recursion guard

- 1.9.8: yes (`arg3 != 0x2d`).
- 1.9.93: no recursion path in `projectile_spawn`, so no equivalent guard is needed.

### Multi-pellet outcomes

- 1.9.8: original pellets plus same-count extra `0x2d` pellets.
- 1.9.93: only `pellet_count[weapon_id]` fire bullets.

### Particle and secondary weapon outcomes

- 1.9.8: Fire Bullets hook does not inject `0x2d` for fire paths that avoid main `projectile_spawn`.
- 1.9.93: dedicated Fire Bullets branch still emits `0x2d` using weapon pellet count.

### Single-pellet cadence/spread fallback

- 1.9.8: not observed in `sub_41fc20` hook behavior.
- 1.9.93: uses `fire_bullets_fallback_shot_cooldown` and `fire_bullets_fallback_spread_heat` when pellet count is 1.

### Fire SFX while Fire Bullets is active

- 1.9.8: weapon-path dependent.
- 1.9.93: dedicated paired Fire Bullets SFX path (`primary` + `secondary`).

## Full weapon matrix (section format)

Interpretation notes:

- `Path basis` shows whether behavior is direct from explicit callsites/mappings or inferred from default behavior.
- `Base main spawn calls` counts main `projectile_spawn` calls per trigger with Fire Bullets off.
- `1.9.8 Fire Bullets` describes additive-recursive behavior.
- `1.9.93 Fire Bullets` describes replacement-model behavior from the dedicated branch.

### Weapon `1`: Pistol

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x01`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `2`: Assault Rifle

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x02`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `3`: Shotgun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x03`
- `Base main spawn calls`: 12
- `1.9.8 Fire Bullets`: +12 extra `0x2d` (base 12 shots kept)
- `1.9.93 Fire Bullets`: 12x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Keeps weapon cadence/spread (no fallback override)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `4`: Sawed-off Shotgun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x03`
- `Base main spawn calls`: 12
- `1.9.8 Fire Bullets`: +12 extra `0x2d` (base 12 shots kept)
- `1.9.93 Fire Bullets`: 12x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Keeps weapon cadence/spread (no fallback override)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `5`: Submachine Gun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x05`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `6`: Gauss Gun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x06`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `7`: Mean Minigun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x01`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `8`: Flamethrower

- `Path basis`: Direct (explicit non-main path)
- `Base fire path`: Particle pool (`fx_spawn_particle` style 0)
- `Base main spawn calls`: 0 (no main `projectile_spawn`)
- `1.9.8 Fire Bullets`: No Fire Bullets projectile from this fire path
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `9`: Plasma Rifle

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x09`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `10`: Multi-Plasma

- `Path basis`: Direct (explicit special-case branch)
- `Base fire path`: Main projectile pool, fixed 5-shot pattern (`0x09/0x0B`); primary types: `0x09,0x0b`
- `Base main spawn calls`: 5
- `1.9.8 Fire Bullets`: +5 extra `0x2d` (base 5 shots kept)
- `1.9.93 Fire Bullets`: 3x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Keeps weapon cadence/spread (no fallback override)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `11`: Plasma Minigun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x0b`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `12`: Rocket Launcher

- `Path basis`: Direct (explicit non-main path)
- `Base fire path`: Secondary projectile pool (rocket type 1)
- `Base main spawn calls`: 0 (no main `projectile_spawn`)
- `1.9.8 Fire Bullets`: No Fire Bullets projectile from this fire path
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `13`: Seeker Rockets

- `Path basis`: Direct (explicit non-main path)
- `Base fire path`: Secondary projectile pool (homing rocket type 2)
- `Base main spawn calls`: 0 (no main `projectile_spawn`)
- `1.9.8 Fire Bullets`: No Fire Bullets projectile from this fire path
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `14`: Plasma Shotgun

- `Path basis`: Direct (explicit special-case branch)
- `Base fire path`: Main projectile pool, 14-shot plasma spread (`0x0B`); primary types: `0x0b`
- `Base main spawn calls`: 14
- `1.9.8 Fire Bullets`: +14 extra `0x2d` (base 14 shots kept)
- `1.9.93 Fire Bullets`: 14x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Keeps weapon cadence/spread (no fallback override)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `15`: Blow Torch

- `Path basis`: Direct (explicit non-main path)
- `Base fire path`: Particle pool (`fx_spawn_particle` style 1)
- `Base main spawn calls`: 0 (no main `projectile_spawn`)
- `1.9.8 Fire Bullets`: No Fire Bullets projectile from this fire path
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `16`: HR Flamer

- `Path basis`: Direct (explicit non-main path)
- `Base fire path`: Particle pool (`fx_spawn_particle` style 2)
- `Base main spawn calls`: 0 (no main `projectile_spawn`)
- `1.9.8 Fire Bullets`: No Fire Bullets projectile from this fire path
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `17`: Mini-Rocket Swarmers

- `Path basis`: Direct (explicit non-main path)
- `Base fire path`: Secondary projectile pool (homing rockets; count = current ammo)
- `Base main spawn calls`: 0 (no main `projectile_spawn`)
- `1.9.8 Fire Bullets`: No Fire Bullets projectile from this fire path
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `18`: Rocket Minigun

- `Path basis`: Direct (explicit non-main path)
- `Base fire path`: Secondary projectile pool (rocket-minigun type 4)
- `Base main spawn calls`: 0 (no main `projectile_spawn`)
- `1.9.8 Fire Bullets`: No Fire Bullets projectile from this fire path
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `19`: Pulse Gun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x13`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `20`: Jackhammer

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x03`
- `Base main spawn calls`: 4
- `1.9.8 Fire Bullets`: +4 extra `0x2d` (base 4 shots kept)
- `1.9.93 Fire Bullets`: 4x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Keeps weapon cadence/spread (no fallback override)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `21`: Ion Rifle

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x15`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `22`: Ion Minigun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x16`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `23`: Ion Cannon

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x17`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `24`: Shrinkifier 5k

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x18`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `25`: Blade Gun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x19`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `26`: Spider Plasma

- `Path basis`: Inferred (default type_id == weapon_id)
- `Base fire path`: Main projectile pool; primary type(s): `0x1a`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `27`: Evil Scythe

- `Path basis`: Inferred (default type_id == weapon_id)
- `Base fire path`: Main projectile pool; primary type(s): `0x1b`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `28`: Plasma Cannon

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x1c`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `29`: Splitter Gun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x1d`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `30`: Gauss Shotgun

- `Path basis`: Direct (explicit special-case branch)
- `Base fire path`: Main projectile pool, 6-shot gauss spread (`0x06`); primary types: `0x06`
- `Base main spawn calls`: 6
- `1.9.8 Fire Bullets`: +6 extra `0x2d` (base 6 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `31`: Ion Shotgun

- `Path basis`: Direct (explicit special-case branch)
- `Base fire path`: Main projectile pool, 8-shot ion spread (`0x16`); primary types: `0x16`
- `Base main spawn calls`: 8
- `1.9.8 Fire Bullets`: +8 extra `0x2d` (base 8 shots kept)
- `1.9.93 Fire Bullets`: 8x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Keeps weapon cadence/spread (no fallback override)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `32`: Flameburst

- `Path basis`: Inferred (default type_id == weapon_id)
- `Base fire path`: Main projectile pool; primary type(s): `0x20`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `33`: RayGun

- `Path basis`: Inferred (default type_id == weapon_id)
- `Base fire path`: Main projectile pool; primary type(s): `0x21`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `34`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `35`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `36`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `37`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `38`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `39`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `40`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `41`: Plague Sphreader Gun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x29`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `42`: Bubblegun

- `Path basis`: Direct (explicit non-main path)
- `Base fire path`: Particle pool (`fx_spawn_particle_slow`)
- `Base main spawn calls`: 0 (no main `projectile_spawn`)
- `1.9.8 Fire Bullets`: No Fire Bullets projectile from this fire path
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `43`: Rainbow Gun

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x2b`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `44`: Grim Weapon

- `Path basis`: Inferred (default type_id == weapon_id)
- `Base fire path`: Main projectile pool; primary type(s): `0x2c`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `45`: Fire bullets

- `Path basis`: Direct (explicit mapping/callsite)
- `Base fire path`: Main projectile pool; primary type(s): `0x2d`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: Guarded (`arg3 == 0x2d`): no recursive extra shot
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `46`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `47`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `48`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `49`: Unknown / unlabelled

- `Path basis`: Unknown
- `Base fire path`: Unknown / unlabelled weapon id (no direct callsite evidence)
- `Base main spawn calls`: Unknown
- `1.9.8 Fire Bullets`: Unknown
- `1.9.93 Fire Bullets`: Unknown / unlabelled (no confirmed active path)
- `1.9.93 cadence/spread`: Unknown
- `Rewrite status`: Not represented in `WEAPON_TABLE`

### Weapon `50`: Transmutator

- `Path basis`: Inferred (default type_id == weapon_id)
- `Base fire path`: Main projectile pool; primary type(s): `0x32`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `51`: Blaster R-300

- `Path basis`: Inferred (default type_id == weapon_id)
- `Base fire path`: Main projectile pool; primary type(s): `0x33`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `52`: Lighting Rifle

- `Path basis`: Inferred (default type_id == weapon_id)
- `Base fire path`: Main projectile pool; primary type(s): `0x34`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

### Weapon `53`: Nuke Launcher

- `Path basis`: Inferred (default type_id == weapon_id)
- `Base fire path`: Main projectile pool; primary type(s): `0x35`
- `Base main spawn calls`: 1
- `1.9.8 Fire Bullets`: +1 extra `0x2d` (base 1 shots kept)
- `1.9.93 Fire Bullets`: 1x `0x2d` only (base fire path bypassed)
- `1.9.93 cadence/spread`: Uses Fire Bullets fallback cadence/spread (`0.14`, `0.22`)
- `Rewrite status`: Matches 1.9.93 semantics

## High-impact weapon deltas

- **Multi-Plasma (`id=10`)**: 1.9.8 yields 5 base projectiles + 5 extra `0x2d`; 1.9.93 yields only 3 `0x2d` (pellet-count driven).
- **Gauss Shotgun (`id=30`)**: 1.9.8 yields 6 gauss + 6 fire; 1.9.93 collapses to 1 fire bullet (pellet count is 1).
- **Rocket/particle family (`8,12,13,15,16,17,18,42`)**: 1.9.8 hook does not inject fire bullets through those paths; 1.9.93 still emits fire bullets via pellet count.
- **Fire Bullets weapon (`id=45`)**: recursion guard in 1.9.8 avoids self-duplication when requested type is already `0x2d`.

## Rewrite parity status

- Current Python gameplay matches the **1.9.93** model (replacement + dedicated Fire Bullets branch), not the **1.9.8 additive recursion** model.
- Core references:

  - Projectile override gate: `src/crimson/gameplay.py:623`
  - Dedicated Fire Bullets projectile loop: `src/crimson/gameplay.py:831`
  - Single-pellet fallback cadence: `src/crimson/gameplay.py:763`

## Confidence and caveats

- High confidence for hook semantics and Fire Bullets control flow (direct HLIL/decompile evidence).
- Unknown/unlabelled ids (`34..40`, `46..49`) remain marked unknown due missing direct active callsites in current symbolized maps.
- Rows with `Path basis = Inferred (default type_id == weapon_id)` rely on native default path semantics where no explicit special-case branch is present.
