---
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

## Fire bullets output by weapon class

Each `0x2d` projectile has identical damage characteristics (projectile_meta=60, damage_scale=0.25), so fire bullets per second (fb/s) is directly proportional to perk DPS. In 1.9.8, the base weapon also fires alongside fire bullets; in 1.9.93, only fire bullets are emitted.

### Particle and secondary-path weapons

These weapons bypass `projectile_spawn` entirely (particle pools, secondary projectile pools). In 1.9.8, the Fire Bullets hook never triggers. In 1.9.93, the dedicated branch emits fire bullets regardless.

- 1.9.8: **0 fb/s** (perk has no effect)
- 1.9.93: **7.1 fb/s** (fallback cadence, infinite ammo)
- Flamethrower (8), Rocket Launcher (12), Seeker Rockets (13), Blow Torch (15), Mini-Rocket Swarmers (17), Rocket Minigun (18)

### Single-pellet weapons slowed by fallback cadence

Native cooldown < 0.14s. The 1.9.93 fallback cadence is slower than their natural fire rate, reducing fire bullets output. In 1.9.8, the base weapon also continues firing on top.

- Submachine Gun (0.088s): **11.4 -> 7.1** fb/s
- Mean Minigun (0.09s): **11.1 -> 7.1** fb/s
- Pulse Gun (0.1s): **10.0 -> 7.1** fb/s
- Ion Minigun (0.1s): **10.0 -> 7.1** fb/s
- Plasma Minigun (0.11s): **9.1 -> 7.1** fb/s
- Assault Rifle (0.117s): **8.5 -> 7.1** fb/s

1.9.8 is strictly better for these weapons: more fire bullets per second AND the base weapon still fires.

### Single-pellet weapons boosted by fallback cadence

Native cooldown > 0.14s. The 1.9.93 fallback cadence fires faster than the weapon natively would. Base weapon output is lost but fire rate increases.

- Shrinkifier 5k (0.21s): **4.8 -> 7.1** fb/s
- Plasma Rifle (0.29s): **3.4 -> 7.1** fb/s
- Blade Gun (0.35s): **2.9 -> 7.1** fb/s
- Ion Rifle (0.4s): **2.5 -> 7.1** fb/s
- Gauss Gun (0.6s): **1.7 -> 7.1** fb/s
- Splitter Gun (0.7s): **1.4 -> 7.1** fb/s
- Pistol (0.71s): **1.4 -> 7.1** fb/s
- Plasma Cannon (0.9s): **1.1 -> 7.1** fb/s
- Ion Cannon (1.0s): **1.0 -> 7.1** fb/s

### Multi-pellet weapons (count matches base spawns)

Both versions produce the same number of fire bullets per trigger. The weapon's own cadence is used since `pellet_count > 1`.

- Shotgun (12 pellets, 0.85s): **14.1 fb/s** in both
- Sawed-off Shotgun (12 pellets, 0.87s): **13.8 fb/s** in both
- Plasma Shotgun (14 pellets, 0.48s): **29.2 fb/s** in both
- Jackhammer (4 pellets, 0.14s): **28.6 fb/s** in both
- Ion Shotgun (8 pellets, 0.85s): **9.4 fb/s** in both

Same fire bullets rate, but 1.9.8 additionally keeps the base weapon's projectiles.

### Multi-pellet count mismatches

These weapons have `pellet_count` that differs from the number of `projectile_spawn` calls in their base fire path. In 1.9.8, fire bullet count equals base spawn count; in 1.9.93, it equals `pellet_count`.

- **Multi-Plasma** (5 base spawns, pellet_count=3, 0.62s): **8.1 -> 4.8** fb/s. The 5-shot plasma spread triggers 5 extra fire bullets in 1.9.8; only 3 in 1.9.93. Also loses the plasma projectiles.
- **Gauss Shotgun** (6 base spawns, pellet_count=1, 1.05s): **5.7 -> 7.1** fb/s. The 6-shot gauss spread triggers 6 extra fire bullets in 1.9.8; in 1.9.93, pellet_count=1 activates the fallback cadence path. Faster cadence but single-pellet output, and loses the gauss spread.

## Weapons not in quest progression

These weapons are absent from `quest_database_init` and don't appear through standard quest unlocks. They have functional weapon table entries and fire paths but are likely secret, debug, or unfinished content. See `docs/secrets/weapon-candidates.md` for details.

The same behavior classes apply. Rates listed as 1.9.8 -> 1.9.93.

### Particle / secondary path

- 1.9.8: **0 fb/s**, 1.9.93: **7.1 fb/s**
- HR Flamer (16), Bubblegun (42)

### Single-pellet, slowed

- Flameburst (0.02s): **50.0 -> 7.1** fb/s
- Transmutator (0.04s): **25.0 -> 7.1** fb/s
- Blaster R-300 (0.08s): **12.5 -> 7.1** fb/s

### Single-pellet, boosted

- Spider Plasma (0.2s): **5.0 -> 7.1** fb/s
- Plague Sphreader (0.2s): **5.0 -> 7.1** fb/s
- Rainbow Gun (0.2s): **5.0 -> 7.1** fb/s
- Grim Weapon (0.5s): **2.0 -> 7.1** fb/s
- RayGun (0.7s): **1.4 -> 7.1** fb/s
- Evil Scythe (1.0s): **1.0 -> 7.1** fb/s
- Lighting Rifle (4.0s): **0.25 -> 7.1** fb/s
- Nuke Launcher (4.0s): **0.25 -> 7.1** fb/s

### Fire Bullets weapon (id=45)

When Fire Bullets IS the equipped weapon (shot_cooldown=0.14s, pellet_count=1):

- 1.9.8: recursion guard (`arg3 == 0x2d`) prevents self-duplication. Normal output.
- 1.9.93: dedicated branch emits 1x `0x2d` at fallback cadence. No behavioral difference.
- **7.1 fb/s** in both.

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
- Pellet count field: `docs/weapon-table.md:102`
