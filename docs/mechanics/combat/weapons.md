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

## Weapon reference

All 33 selectable weapons in internal ID order, roughly following quest
unlock progression. Damage is the base multiplier. Fire interval and
reload are in seconds.

### 1. Pistol

Clip 10 · Damage 4.1 · Fire 0.712 s · Reload 1.2 s · Bullet

### 2. Assault Rifle

Clip 25 · Damage 1.0 · Fire 0.117 s · Reload 1.2 s · Bullet

### 3. Shotgun

Clip 12 · Damage 1.2 · Fire 0.85 s · Reload 1.9 s · 12 pellets · Bullet

### 4. Sawed-off Shotgun

Clip 12 · Damage 1.0 · Fire 0.87 s · Reload 1.9 s · 12 pellets · Bullet

### 5. Submachine Gun

Clip 30 · Damage 1.0 · Fire 0.088 s · Reload 1.2 s · Bullet

### 6. Gauss Gun

Clip 6 · Damage 1.0 · Fire 0.6 s · Reload 1.6 s · Bullet

### 7. Mean Minigun

Clip 120 · Damage 1.0 · Fire 0.09 s · Reload 4.0 s · Bullet

### 8. Flamethrower

Clip 30 · Damage 1.0 · Fire 0.008 s · Reload 2.0 s · Fire

### 9. Plasma Rifle

Clip 20 · Damage 5.0 · Fire 0.291 s · Reload 1.2 s · Bullet

### 10. Multi-Plasma

Clip 8 · Damage 1.0 · Fire 0.621 s · Reload 1.4 s · 3 pellets · Bullet

### 11. Plasma Minigun

Clip 30 · Damage 2.1 · Fire 0.11 s · Reload 1.3 s · Bullet

### 12. Rocket Launcher

Clip 5 · Damage 1.0 · Fire 0.741 s · Reload 1.2 s · Rocket

### 13. Seeker Rockets

Clip 8 · Damage 1.0 · Fire 0.311 s · Reload 1.2 s · Rocket

### 14. Plasma Shotgun

Clip 8 · Damage 1.0 · Fire 0.48 s · Reload 3.1 s · 14 pellets · Bullet

### 15. Blow Torch

Clip 30 · Damage 1.0 · Fire 0.006 s · Reload 1.5 s · Fire

### 17. Mini-Rocket Swarmers

Clip 5 · Damage 1.0 · Fire 1.8 s · Reload 1.8 s · Rocket

### 18. Rocket Minigun

Clip 16 · Damage 1.0 · Fire 0.12 s · Reload 1.8 s · Rocket

### 19. Pulse Gun

Clip 16 · Damage 1.0 · Fire 0.1 s · Reload 0.1 s · Electric

### 20. Jackhammer

Clip 16 · Damage 1.0 · Fire 0.14 s · Reload 3.0 s · 4 pellets · Bullet

### 21. Ion Rifle

Clip 8 · Damage 3.0 · Fire 0.4 s · Reload 1.35 s · Electric

### 22. Ion Minigun

Clip 20 · Damage 1.4 · Fire 0.1 s · Reload 1.8 s · Electric

### 23. Ion Cannon

Clip 3 · Damage 16.7 · Fire 1.0 s · Reload 3.0 s · Electric

### 24. Shrinkifier 5k

Clip 8 · Damage 0.0 · Fire 0.21 s · Reload 1.22 s · Bullet
· [Secret weapon](../secret-weapons.md#shrinkifier-5k)

### 25. Blade Gun

Clip 6 · Damage 11.0 · Fire 0.35 s · Reload 3.5 s · Bullet
· [Secret weapon](../secret-weapons.md#blade-gun)

### 28. Plasma Cannon

Clip 3 · Damage 28.0 · Fire 0.9 s · Reload 2.7 s · Bullet

### 29. Splitter Gun

Clip 6 · Damage 6.0 · Fire 0.7 s · Reload 2.2 s · Bullet
· [Secret weapon](../secret-weapons.md#splitter-gun)

### 30. Gauss Shotgun

Clip 4 · Damage 1.0 · Fire 1.05 s · Reload 2.1 s · Bullet

### 31. Ion Shotgun

Clip 10 · Damage 1.0 · Fire 0.85 s · Reload 1.9 s · 8 pellets · Electric

## Unobtainable weapons

These weapons exist in the weapon table but have no known unlock path.

!!! tip
    You can view these unfinished developer prototypes in the remake
    using `crimson view arsenal`.

### 16. HR Flamer

Clip 30 · Damage 1.0 · Fire 0.009 s · Reload 1.8 s · Fire

### 26. Spider Plasma

Clip 5 · Damage 0.5 · Fire 0.2 s · Reload 1.2 s · Bullet

### 27. Evil Scythe

Clip 3 · Damage 1.0 · Fire 1.0 s · Reload 3.0 s · Electric

### 32. Flameburst

Clip 60 · Damage 1.0 · Fire 0.02 s · Reload 3.0 s · Electric

### 33. RayGun

Clip 12 · Damage 1.0 · Fire 0.7 s · Reload 2.0 s · Electric

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
