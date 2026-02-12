---
tags:
  - mechanics
  - combat
  - weapons
---

# Weapons

Each weapon defines a fire rate, reload time, and damage profile. Perks
and bonuses modify these base values at runtime.

## Ammo classes

The HUD ammo indicator shows one of four icons depending on the weapon's
class: bullet, fire, rocket, or electric.

## Weapon table

All 33 selectable weapons in internal ID order, roughly following quest
unlock progression. Damage is the base multiplier. Fire interval and
reload are in seconds.

| Name | Clip | Damage | Fire | Reload | Pellets | Class |
|---|---:|---:|---:|---:|---:|---|
| Pistol | 10 | 4.1 | 0.712 | 1.2 | 1 | Bullet |
| Assault Rifle | 25 | 1.0 | 0.117 | 1.2 | 1 | Bullet |
| Shotgun | 12 | 1.2 | 0.85 | 1.9 | 12 | Bullet |
| Sawed-off Shotgun | 12 | 1.0 | 0.87 | 1.9 | 12 | Bullet |
| Submachine Gun | 30 | 1.0 | 0.088 | 1.2 | 1 | Bullet |
| Gauss Gun | 6 | 1.0 | 0.6 | 1.6 | 1 | Bullet |
| Mean Minigun | 120 | 1.0 | 0.09 | 4.0 | 1 | Bullet |
| Flamethrower | 30 | 1.0 | 0.008 | 2.0 | 1 | Fire |
| Plasma Rifle | 20 | 5.0 | 0.291 | 1.2 | 1 | Bullet |
| Multi-Plasma | 8 | 1.0 | 0.621 | 1.4 | 3 | Bullet |
| Plasma Minigun | 30 | 2.1 | 0.11 | 1.3 | 1 | Bullet |
| Rocket Launcher | 5 | 1.0 | 0.741 | 1.2 | 1 | Rocket |
| Seeker Rockets | 8 | 1.0 | 0.311 | 1.2 | 1 | Rocket |
| Plasma Shotgun | 8 | 1.0 | 0.48 | 3.1 | 14 | Bullet |
| Blow Torch | 30 | 1.0 | 0.006 | 1.5 | 1 | Fire |
| HR Flamer | 30 | 1.0 | 0.009 | 1.8 | 1 | Fire |
| Mini-Rocket Swarmers | 5 | 1.0 | 1.8 | 1.8 | 1 | Rocket |
| Rocket Minigun | 16 | 1.0 | 0.12 | 1.8 | 1 | Rocket |
| Pulse Gun | 16 | 1.0 | 0.1 | 0.1 | 1 | Electric |
| Jackhammer | 16 | 1.0 | 0.14 | 3.0 | 4 | Bullet |
| Ion Rifle | 8 | 3.0 | 0.4 | 1.35 | 1 | Electric |
| Ion Minigun | 20 | 1.4 | 0.1 | 1.8 | 1 | Electric |
| Ion Cannon | 3 | 16.7 | 1.0 | 3.0 | 1 | Electric |
| [Shrinkifier 5k](../secret-weapons.md#shrinkifier-5k) | 8 | 0.0 | 0.21 | 1.22 | 1 | Bullet |
| [Blade Gun](../secret-weapons.md#blade-gun) | 6 | 11.0 | 0.35 | 3.5 | 1 | Bullet |
| Spider Plasma | 5 | 0.5 | 0.2 | 1.2 | 1 | Bullet |
| Evil Scythe | 3 | 1.0 | 1.0 | 3.0 | 1 | Electric |
| Plasma Cannon | 3 | 28.0 | 0.9 | 2.7 | 1 | Bullet |
| [Splitter Gun](../secret-weapons.md#splitter-gun) | 6 | 6.0 | 0.7 | 2.2 | 1 | Bullet |
| Gauss Shotgun | 4 | 1.0 | 1.05 | 2.1 | 1 | Bullet |
| Ion Shotgun | 10 | 1.0 | 0.85 | 1.9 | 8 | Electric |
| Flameburst | 60 | 1.0 | 0.02 | 3.0 | 1 | Electric |
| RayGun | 12 | 1.0 | 0.7 | 2.0 | 1 | Electric |

## Special behaviors

Most weapons fire a single projectile per shot with standard collision.
Several deviate:

- **Multi-pellet**: Shotgun and Sawed-off (12 pellets), Plasma Shotgun
  (14), Ion Shotgun (8), Gauss Shotgun (6), Multi-Plasma (5-shot volley),
  Jackhammer (4). Pellets spawn with randomized speed and spread.
- **Homing**: Seeker Rockets track the nearest enemy.
- **Splitting**: Splitter Gun projectiles fork into two child projectiles
  on hit at +/-60 degrees, and children can split again on subsequent
  hits.
- **AoE chain**: Ion weapons (Ion Rifle, Ion Minigun, Ion Cannon) produce
  area-of-effect arcs that chain to nearby enemies.
- **Pushback**: Pulse Gun knocks enemies back on hit.
- **Shrink**: Shrinkifier 5k reduces targets to 65% size per hit;
  enemies below size 16 die instantly.
- **Particle streams**: Flamethrower, Blow Torch, and HR Flamer use
  particle rendering and drain fractional ammo per tick (0.1, 0.05, and
  0.1 respectively).
- **Full-clip dump**: Mini-Rocket Swarmers fire every round in the clip
  as individual rockets in a single burst.
- **Secondary homing burst**: Plasma Cannon fires a heavy primary shot
  followed by a spread of smaller homing projectiles.

## Availability

- Pistol is always available.
- [Quest](../modes/quests.md) progression unlocks weapons on first
  completion (see individual quest entries for specific unlocks).
- In Survival, Assault Rifle, Shotgun, and Submachine Gun are always in
  the starting rotation.
- Random weapon pickups draw from IDs 1–33 with a 50% one-time reroll
  to avoid repeating the most recently used weapon.
- Three weapons have special unlock paths outside quest progression:
  [Splitter Gun, Shrinkifier 5k, and Blade Gun](../secret-weapons.md).
