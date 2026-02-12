---
icon: lucide/flame
tags:
  - status-analysis
---

# Fire Bullets behavior comparison (1.9.8 vs 1.9.93)

## Scope

Compare how Fire Bullets modifies player shots in Crimsonland 1.9.8 vs 1.9.93.
Cross-check against the rewrite (`src/crimson/gameplay.py`) for parity.

## Architectural differences

### Conversion model

- **1.9.8 (additive)**: `projectile_spawn` recursively spawns an extra `0x2d` alongside each original projectile. The base weapon fires normally; fire bullets are a bonus on top.
- **1.9.93 (replacement)**: a dedicated Fire Bullets branch in `player_update` completely bypasses the base weapon's fire path. Only `0x2d` projectiles are emitted, using the weapon's `pellet_count`.

### Cadence

- **1.9.8**: always uses the equipped weapon's native `shot_cooldown`.
- **1.9.93**: for `pellet_count == 1` weapons, cadence is forced to the fallback (0.14s). For `pellet_count > 1`, the weapon's own cadence is preserved.

### Ammo

- **1.9.8**: base weapon consumes ammo normally. Fire bullets stop during reloads.
- **1.9.93**: fire bullets bypass ammo consumption entirely. No reload downtime while the perk is active.

### Recursion guard

- **1.9.8**: `arg3 != 0x2d` prevents infinite recursion when the spawned type is already `0x2d`.
- **1.9.93**: no recursion path exists, so no guard is needed.

### SFX

- **1.9.8**: weapon-path dependent.
- **1.9.93**: dedicated paired Fire Bullets SFX.

## DPS comparison by weapon class

### Damage formula

Point-blank single-target DPS, using the standard projectile hit formula at minimum travel distance (dist=50):

```
hit_damage(scale) = ((100 / 50) * scale * 30 + 10) * 0.95 = (60 * scale + 10) * 0.95
```

- Fire bullet (`0x2d`, scale=0.25): **23.75** damage per hit
- 1.9.8 DPS = weapon_rate * (base_hit_damage + fb_hit_damage), since each `projectile_spawn` triggers both the base shot and a recursive fire bullet
- 1.9.93 DPS = fb_rate * fb_hit_damage, since the base weapon is fully replaced

Fire bullets also have damage_pool=240 (pierce ~240 enemies vs pool=1 for most projectiles), so crowd DPS is substantially higher than single-target. Not included here.

All values listed as **1.9.8 to 1.9.93**. 1.9.93 single-pellet DPS is always **170** (= 7.1 fb/s * 23.75).

### Particle and secondary-path weapons

These weapons bypass `projectile_spawn` entirely (particle pools, secondary projectile pools). In 1.9.8, the Fire Bullets hook never triggers. In 1.9.93, the dedicated branch emits fire bullets regardless. Base weapon damage goes through separate particle/secondary systems and is not included.

- 1.9.8: **0 fb/s**, **0** fb dps (perk has no effect)
- 1.9.93: **7.1 fb/s**, **170** dps (fallback cadence, infinite ammo)
- Flamethrower (8), Rocket Launcher (12), Seeker Rockets (13), Blow Torch (15), Mini-Rocket Swarmers (17), Rocket Minigun (18)

### Single-pellet weapons slowed by fallback cadence

Native cooldown < 0.14s. The 1.9.93 fallback cadence is slower than their natural fire rate. In 1.9.8, the base weapon also fires on top, making it strictly better.

- Mean Minigun (0.09s, scale 4.1): 11.1 to 7.1 fb/s, **2966 to 170** dps
- Plasma Minigun (0.11s, scale 2.1): 9.1 to 7.1 fb/s, **1390 to 170** dps
- Ion Minigun (0.1s, scale 1.4): 10.0 to 7.1 fb/s, **1131 to 170** dps
- Submachine Gun (0.088s, scale 1.0): 11.4 to 7.1 fb/s, **1026 to 170** dps
- Pulse Gun (0.1s, scale 1.0): 10.0 to 7.1 fb/s, **903 to 170** dps
- Assault Rifle (0.117s, scale 1.0): 8.5 to 7.1 fb/s, **771 to 170** dps

### Single-pellet weapons boosted by fallback cadence

Native cooldown > 0.14s. The 1.9.93 fallback cadence fires faster than the weapon natively would. Base weapon output is lost but fire rate increases. Whether total DPS improves depends on the base weapon's damage_scale.

- Blade Gun (0.35s, scale 11.0): 2.9 to 7.1 fb/s, **1886 to 170** dps
- Plasma Rifle (0.29s, scale 5.0): 3.4 to 7.1 fb/s, **1097 to 170** dps
- Plasma Cannon (0.9s, scale 28.0): 1.1 to 7.1 fb/s, **1810 to 170** dps
- Ion Cannon (1.0s, scale 16.7): 1.0 to 7.1 fb/s, **985 to 170** dps
- Splitter Gun (0.7s, scale 6.0): 1.4 to 7.1 fb/s, **536 to 170** dps
- Ion Rifle (0.4s, scale 3.0): 2.5 to 7.1 fb/s, **511 to 170** dps
- Pistol (0.71s, scale 4.1): 1.4 to 7.1 fb/s, **376 to 170** dps
- Shrinkifier 5k (0.21s, scale 0.0): 4.8 to 7.1 fb/s, **158 to 170** dps
- Gauss Gun (0.6s, scale 1.0): 1.7 to 7.1 fb/s, **150 to 170** dps

Only Shrinkifier 5k (zero base damage) and Gauss Gun (slow + low scale) come out ahead in 1.9.93.

### Multi-pellet weapons (count matches base spawns)

Both versions produce the same number of fire bullets per trigger. The weapon's own cadence is used since `pellet_count > 1`. In 1.9.8, each pellet also produces the base weapon's projectile.

- Plasma Shotgun (14 pellets, 0.48s, scale 2.1): 29.2 fb/s, **4461 to 693** dps
- Jackhammer (4 pellets, 0.14s, scale 1.2): 28.6 fb/s, **2904 to 679** dps
- Shotgun (12 pellets, 0.85s, scale 1.2): 14.1 fb/s, **1435 to 335** dps
- Sawed-off Shotgun (12 pellets, 0.87s, scale 1.2): 13.8 fb/s, **1402 to 328** dps
- Ion Shotgun (8 pellets, 0.85s, scale 1.4): 9.4 fb/s, **1064 to 224** dps

### Multi-pellet count mismatches

In 1.9.8, fire bullet count equals base spawn count; in 1.9.93, it equals `pellet_count`.

- **Multi-Plasma** (5 base spawns, pellet_count=3, 0.62s): 8.1 to 4.8 fb/s, **2033 to 115** dps. The 5-shot spread uses types 0x09 (scale 5.0) and 0x0B (scale 2.1). In 1.9.8, base spread + 5 fire bullets; in 1.9.93, only 3 fire bullets.
- **Gauss Shotgun** (6 base spawns, pellet_count=1, 1.05s): 5.7 to 7.1 fb/s, **516 to 170** dps. In 1.9.8, 6 gauss shots (scale 1.0) + 6 fire bullets. In 1.9.93, pellet_count=1 triggers the fallback cadence path.

## Weapons not in quest progression

These weapons are absent from `quest_database_init` and don't appear through standard quest unlocks. They have functional weapon table entries and fire paths but are likely secret, debug, or unfinished content. See `docs/re/static/secrets/weapon-candidates.md` for details.

The same behavior classes apply. Values listed as **1.9.8 to 1.9.93**.

### Particle / secondary path

- 1.9.8: **0 fb/s**, **0** fb dps. 1.9.93: **7.1 fb/s**, **170** dps
- HR Flamer (16), Bubblegun (42)

### Single-pellet, slowed

- Flameburst (0.02s, scale 1.0): 50.0 to 7.1 fb/s, **4513 to 170** dps
- Transmutator (0.04s, scale 1.0): 25.0 to 7.1 fb/s, **2256 to 170** dps
- Blaster R-300 (0.08s, scale 1.0): 12.5 to 7.1 fb/s, **1128 to 170** dps

### Single-pellet, boosted

- Rainbow Gun (0.2s, scale 1.0): 5.0 to 7.1 fb/s, **451 to 170** dps
- Spider Plasma (0.2s, scale 0.5): 5.0 to 7.1 fb/s, **309 to 170** dps
- Grim Weapon (0.5s, scale 1.0): 2.0 to 7.1 fb/s, **181 to 170** dps
- Plague Sphreader (0.2s, scale 0.0): 5.0 to 7.1 fb/s, **166 to 170** dps
- RayGun (0.7s, scale 1.0): 1.4 to 7.1 fb/s, **129 to 170** dps
- Evil Scythe (1.0s, scale 1.0): 1.0 to 7.1 fb/s, **90 to 170** dps
- Lighting Rifle (4.0s, scale 1.0): 0.25 to 7.1 fb/s, **23 to 170** dps
- Nuke Launcher (4.0s, scale 1.0): 0.25 to 7.1 fb/s, **23 to 170** dps

Several of these actually benefit from 1.9.93: Plague Sphreader (zero base damage), RayGun, Evil Scythe, Lighting Rifle, and Nuke Launcher all have higher total DPS with the replacement model.

### Fire Bullets weapon (id=45)

When Fire Bullets IS the equipped weapon (shot_cooldown=0.14s, pellet_count=1, scale=0.25):

- 1.9.8: recursion guard (`arg3 == 0x2d`) prevents self-duplication. Normal output.
- 1.9.93: dedicated branch emits 1x `0x2d` at fallback cadence. No behavioral difference.
- **7.1 fb/s**, **170 dps** in both.

## Rewrite parity

The Python gameplay matches the 1.9.93 model (replacement + dedicated fire branch).

- Projectile override gate: `src/crimson/gameplay.py:636`
- Dedicated Fire Bullets loop: `src/crimson/gameplay.py:831`
- Single-pellet fallback cadence: `src/crimson/gameplay.py:763`
- Ammo bypass: `src/crimson/gameplay.py:1024`

## Evidence anchors

### 1.9.8

- Recursive add-on shot in `sub_41fc20`: `crimsonland_1.9.8.txt:25166`, `25170`, `25188`
- Cooldown from weapon table in `player_update`: `crimsonland_1.9.8.txt:17517`, `18793`

### 1.9.93

- In-place type override in `projectile_spawn`: `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:27925`, `27929`, `27948`
- Dedicated fire branch in `player_update`: `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:20782`, `20797`, `20803`, `20812`, `20838`
- Fallback constants in `weapon_table_init`: `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:67796`, `67798`
- Pellet count field: `docs/mechanics/reference/weapon-table.md:102`
- Projectile hit damage formula: `src/crimson/projectiles.py:1183`, `1199`
