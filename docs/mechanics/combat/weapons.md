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

## How projectile damage works

Each projectile carries a few key stats from its weapon.

### Damage multiplier

The **Damage** value in each weapon entry is a multiplier applied to
the base damage formula:

```
damage = ((100 / distance) * multiplier * 30 + 10) * 0.95
```

Distance is measured from the shot origin to the point of impact,
clamped to a minimum of 50. This means point-blank shots deal roughly
twice as much as long-range hits. A 1.0x weapon at minimum distance
deals about 67 damage; the Plasma Cannon at 28x deals about 1606.

<div data-widget="damage-calculator"></div>

### Hit radius

Most projectiles use a hit radius of 1 — they have to land close to
connect. Ion weapons have larger collision spheres: Ion Minigun 3,
Ion Rifle 5, Ion Cannon and Plasma Cannon 10. This is what makes ion
shots feel like they have area-of-effect even before chain arcs.

### Damage pool

Every projectile has a damage pool that determines whether it stops
or pierces through on hit. Most weapons have a pool of 1, so the
projectile is consumed on first contact and deals the full formula
damage.

Three weapons get elevated pools that enable piercing: Gauss Gun
(300), Fire Bullets (240), and Blade Gun (50).

When a piercing projectile hits, it deals the current pool value as
damage instead of the distance formula, then subtracts the target's
HP from the pool. The projectile keeps going until the pool is
drained. Piercing shots shred crowds of weak enemies but get eaten
quickly by a few tough targets.

<div data-widget="damage-pool"></div>

### Projectile speed

The weapon table field `projectile_meta` controls how many collision
sub-steps a projectile takes per frame — higher values mean a faster
projectile that covers more ground per tick. The
[Barrel Greaser](../perks.md#34-barrel-greaser) perk doubles this
value, making projectiles twice as fast.

## Weapon reference

All 33 selectable weapons in internal ID order, roughly following quest
unlock progression. Fire interval and reload are in seconds.

### 1. Pistol

Clip 10 · Damage 4.1 · Fire 0.712 s · Reload 1.2 s · Bullet

Starter weapon. Hits hard per shot but slow fire rate and tiny clip
limit sustained output. While you're holding the Pistol, 75% of bonus
drops are forced to be weapon pickups and the overall drop rate
increases — the game actively tries to get you off it.

### 2. Assault Rifle

Clip 25 · Damage 1.0 · Fire 0.117 s · Reload 1.2 s · Bullet

Fast automatic with a generous clip. Reliable all-rounder that stays
useful throughout the game.

### 3. Shotgun

Clip 12 · Damage 1.2 · Fire 0.85 s · Reload 1.9 s · 12 pellets · Bullet

12-pellet spread. Devastating at close range, falls off with distance
as pellets scatter.

### 4. Sawed-off Shotgun

Clip 12 · Damage 1.0 · Fire 0.87 s · Reload 1.9 s · 12 pellets · Bullet

Wider spread than the Shotgun with slightly less damage per pellet.
Better for sweeping crowds, worse for focused fire.

### 5. Submachine Gun

Clip 30 · Damage 1.0 · Fire 0.088 s · Reload 1.2 s · Bullet

Fastest fire rate among bullet weapons. Large clip and quick reload
make it excellent for sustained crowd control.

### 6. Gauss Gun

Clip 6 · Damage 1.0 · Fire 0.6 s · Reload 1.6 s · Bullet

Piercing shots with a damage pool of 300 that punch through multiple
enemies. Spread builds fast, so accuracy degrades quickly under
sustained fire.

### 7. Mean Minigun

Clip 120 · Damage 1.0 · Fire 0.09 s · Reload 4.0 s · Bullet

Enormous clip dumps a wall of bullets. Movement speed is reduced while
firing, and the 4-second reload leaves you exposed.

### 8. Flamethrower

Clip 30 · Damage 1.0 · Fire 0.008 s · Reload 2.0 s · Fire

Continuous particle stream that drains 0.1 ammo per tick. Short range
but high damage density against anything you can walk into.

### 9. Plasma Rifle

Clip 20 · Damage 5.0 · Fire 0.291 s · Reload 1.2 s · Bullet

5x damage multiplier makes each plasma bolt hit like a truck. Moderate
fire rate rewards aim over spray.

### 10. Multi-Plasma

Clip 8 · Damage 1.0 · Fire 0.621 s · Reload 1.4 s · 3 pellets · Bullet

Fires a 5-shot volley of plasma bolts at fixed offsets. Slow cadence
but each trigger pull covers a wide arc.

### 11. Plasma Minigun

Clip 30 · Damage 2.1 · Fire 0.11 s · Reload 1.3 s · Bullet

Rapid plasma stream at 2.1x damage. One of the best sustained DPS
weapons in the game.

### 12. Rocket Launcher

Clip 5 · Damage 1.0 · Fire 0.741 s · Reload 1.2 s · Rocket

Slow explosive rockets with splash damage. Small clip means every shot
counts.

### 13. Seeker Rockets

Clip 8 · Damage 1.0 · Fire 0.311 s · Reload 1.2 s · Rocket

Homing rockets that track the nearest enemy. Faster fire rate and
larger clip than the standard launcher, at the cost of less direct
control.

### 14. Plasma Shotgun

Clip 8 · Damage 1.0 · Fire 0.48 s · Reload 3.1 s · 14 pellets · Bullet

14 plasma pellets per shot. Devastating burst but the 3.1-second
reload is punishing if you empty the clip at a bad time.

### 15. Blow Torch

Clip 30 · Damage 1.0 · Fire 0.006 s · Reload 1.5 s · Fire

Short-range particle stream like the Flamethrower but drains only 0.05
ammo per tick, making it more ammo-efficient.

### 17. Mini-Rocket Swarmers

Clip 5 · Damage 1.0 · Fire 1.8 s · Reload 1.8 s · Rocket

Dumps the entire clip as individual rockets in a single burst. One
trigger pull, five rockets, then a full reload.

### 18. Rocket Minigun

Clip 16 · Damage 1.0 · Fire 0.12 s · Reload 1.8 s · Rocket

Rapid-fire rocket stream. Sustained explosive output that chews
through dense packs.

### 19. Pulse Gun

Clip 16 · Damage 1.0 · Fire 0.1 s · Reload 0.1 s · Electric

Electric bolts that knock enemies back on hit. Near-instant reload
means you're almost never caught empty. Great for keeping distance.

### 20. Jackhammer

Clip 16 · Damage 1.0 · Fire 0.14 s · Reload 3.0 s · 4 pellets · Bullet

Automatic shotgun firing 4 pellets per shot at rifle speed. Long
reload but the sustained burst shreds anything close.

### 21. Ion Rifle

Clip 8 · Damage 3.0 · Fire 0.4 s · Reload 1.35 s · Electric

3x damage electric shots that arc to nearby enemies on impact. Strong
single-target with crowd bonus in tight groups.

### 22. Ion Minigun

Clip 20 · Damage 1.4 · Fire 0.1 s · Reload 1.8 s · Electric

Rapid electric stream with chain arcs. Lower per-hit damage than the
Ion Rifle but much higher volume.

### 23. Ion Cannon

Clip 3 · Damage 16.7 · Fire 1.0 s · Reload 3.0 s · Electric

Massive 16.7x damage electric blast with AoE chains. Only 3 rounds
and a slow cycle, but each shot can clear a cluster.

### 24. Shrinkifier 5k

Clip 8 · Damage 0.0 · Fire 0.21 s · Reload 1.22 s · Bullet
· [Secret weapon](../secret-weapons.md#shrinkifier-5k)

Shrinks targets to 65% size per hit. Enemies below size 16 die
instantly, so most fall in a few shots regardless of health.

### 25. Blade Gun

Clip 6 · Damage 11.0 · Fire 0.35 s · Reload 3.5 s · Bullet
· [Secret weapon](../secret-weapons.md#blade-gun)

Piercing projectile at 11x damage with a damage pool of 50. Cuts
through multiple enemies but the 3.5-second reload limits sustained
use.

### 28. Plasma Cannon

Clip 3 · Damage 28.0 · Fire 0.9 s · Reload 2.7 s · Bullet

Highest damage weapon in the game at 28x. Each shot fires a heavy
primary bolt followed by a spread of smaller homing projectiles.

### 29. Splitter Gun

Clip 6 · Damage 6.0 · Fire 0.7 s · Reload 2.2 s · Bullet
· [Secret weapon](../secret-weapons.md#splitter-gun)

Projectiles fork into two children on hit, and children split again on
subsequent hits. Scales explosively in dense enemy packs.

### 30. Gauss Shotgun

Clip 4 · Damage 1.0 · Fire 1.05 s · Reload 2.1 s · Bullet

Fires 6 high-penetration gauss pellets per shot. Slow and small clip
but each blast hits hard at range.

### 31. Ion Shotgun

Clip 10 · Damage 1.0 · Fire 0.85 s · Reload 1.9 s · 8 pellets · Electric

8 electric pellets with chain arcs. Combines shotgun spread with ion
AoE for strong crowd damage.

## Unobtainable weapons

These weapons exist in the weapon table but have no known unlock path.

!!! tip
    You can view these unfinished developer prototypes in the remake
    using `crimson view arsenal`.

### 16. HR Flamer

Clip 30 · Damage 1.0 · Fire 0.009 s · Reload 1.8 s · Fire

Particle stream similar to the Flamethrower. Slightly slower tick rate
and longer reload, drains 0.1 ammo per tick.

### 26. Spider Plasma

Clip 5 · Damage 0.5 · Fire 0.2 s · Reload 1.2 s · Bullet

Low-damage plasma bolts with a tiny clip. Appears to be a creature
weapon repurposed into the weapon table.

### 27. Evil Scythe

Clip 3 · Damage 1.0 · Fire 1.0 s · Reload 3.0 s · Electric

Shares the Ion Cannon's fire rate and reload but at base 1x damage.
Likely an early prototype of the Ion Cannon.

### 32. Flameburst

Clip 60 · Damage 1.0 · Fire 0.02 s · Reload 3.0 s · Electric

Large clip with very fast fire rate in the electric class. Functions
as a rapid-fire electric stream.

### 33. RayGun

Clip 12 · Damage 1.0 · Fire 0.7 s · Reload 2.0 s · Electric

Mid-speed electric weapon with no distinctive mechanics. Generic stats
suggest an unfinished design.

## Special behaviors

Most weapons fire a single projectile per shot with standard collision.
Several deviate:

- **Piercing**: Gauss Gun, Fire Bullets, and Blade Gun pierce through
  targets using elevated [damage pools](#damage-pool).
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
