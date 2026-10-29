---
icon: lucide/crosshair
tags:
  - mechanics
  - combat
  - weapons
---

# Weapons

Numbers on this page are base values. [Perks](../perks.md) and
[bonuses](../systems/bonuses.md) change them.

## Damage

### Bullet hits

Every gun projectile's direct hit deals:

```
damage = ((100 / distance) * multiplier * 30 + 10) * 0.95
```

Distance runs from where the shot was fired to where it hits, never less
than 50. So a hit deals a flat 9.5 plus 2850 × multiplier ÷ distance: each
doubling of distance roughly halves it. A 1x hit deals 66.5 up close, 38 at
100 px and 15 at 500 px. A Plasma Cannon bolt (28x) deals about 1606 up
close. Bullets have no range limit; they fly until they leave the arena.

In the weapon list, **Hit** is a direct hit at 50 px or closer. The chart
groups weapons by the shot they fire.

<div data-widget="damage-calculator"></div>

Rockets, flames and ion blasts don't use this formula. Their damage is
listed with each weapon.

### Damage types

Perks that raise bullet damage ([Uranium Filled Bullets](../perks.md#28-uranium-filled-bullets),
[Doctor](../perks.md#29-doctor), [Barrel Greaser](../perks.md#34-barrel-greaser),
[Living Fortress](../perks.md#55-living-fortress)) apply to any gun
projectile's direct hit: bullets, pellets, plasma, direct ion hits,
[Fire Bullets](../systems/bonuses.md#14-fire-bullets) and the perk rings.
They don't apply to flames, rocket hits and explosions, ion blasts, poison
or Mr. Melee. Flames get [Pyromaniac](../perks.md#39-pyromaniac)'s ×1.5
instead; ion blasts get [Ion Gun Master](../perks.md#51-ion-gun-master)'s
×1.2.

Enemy shots deal you a flat 10 that only Shield (and Death Clock) blocks.

### Hit radius

A shot hits a creature when it comes within the creature's reach (3 px plus
a seventh of its size) plus the shot's own radius: 1 for most bullets, 3
for Ion Minigun bolts, 5 for Ion Rifle, 10 for Ion Cannon and Plasma
Cannon.

For about 0.4 s after a creature dies, its body still stops ordinary
bullets. Piercing shots pass through.

### Piercing

Gauss Gun and Gauss Shotgun slugs, Fire Bullets rounds and Blade Gun shots
carry a damage pool: 300, 240 and 50. Every other shot stops on its first
hit.

On each hit a piercing shot spends 1 from its pool and deals the rest,
ignoring distance. Its pool then becomes twice the damage it just dealt
minus the target's health. A fresh Gauss slug hits for 299; if that kills
a 200 HP zombie, the slug moves on with 398. Weak enemies feed it, so a
slug that keeps killing keeps getting stronger. It stops on a target with
at least twice its damage (598 HP for a fresh Gauss slug, 98 for a fresh
Blade), then lands one last normal hit and vanishes. The widget below fires
one shot through a line of identical enemies, without damage perks.

<div data-widget="damage-pool"></div>

### Projectile speed

| Speed (px/s) | Shots |
| ---: | --- |
| 4320 | Gauss Gun, Gauss Shotgun |
| 1200 | Shotgun, Sawed-off and Jackhammer pellets, Fire Bullets |
| 1140 | Pistol, Mean Minigun |
| 1020 | Assault Rifle |
| 900 | Submachine Gun, Shrinkifier 5k |
| 720 | Plasma Minigun, Plasma Shotgun, Multi-Plasma outer bolts |
| 600 | Plasma Rifle, Multi-Plasma inner bolts, Splitter Gun |
| 420 | Pulse Gun, Ion Minigun, Ion Shotgun, Blade Gun |
| 300 | Ion Rifle |
| 240 | Ion Cannon, Plasma Cannon |

Shotgun-type pellets get a random 1.0–2.0× speed boost each (1.4–2.2× for
Ion Shotgun and Gauss Shotgun). [Barrel Greaser](../perks.md#34-barrel-greaser)
doubles the speed of your shots.

## Accuracy

Each shot adds 1.3 × the weapon's spread to your spread, up to 0.48. Spread
recovers 0.4 per second, down to 0.01. A shot lands at a random point
around your crosshair. The scatter grows with the crosshair's distance, so
spread is an angle: at the cap a shot can stray up to about 13.5°, near or
far. [Bites](player.md#bites) widen it too.
[Sharpshooter](../perks.md#2-sharpshooter) pins spread near zero.

| Spread per shot | Weapons |
| ---: | --- |
| 0.68 | Ion Cannon |
| 0.6 | Plasma Cannon |
| 0.42 | Gauss Gun, Rocket Launcher |
| 0.32 | Multi-Plasma, Seeker Rockets |
| 0.28 | Splitter Gun |
| 0.27 | Shotgun, Gauss Shotgun, Ion Shotgun |
| 0.22 | Pistol |
| 0.182 | Plasma Rifle |
| 0.16 | Jackhammer |
| 0.13 | Sawed-off Shotgun |
| 0.12 | Mini-Rocket Swarmers, Rocket Minigun |
| 0.112 | Ion Rifle |
| 0.11 | Plasma Shotgun |
| 0.097 | Plasma Minigun |
| 0.09 | Assault Rifle, Ion Minigun |
| 0.082 | Submachine Gun |
| 0.062 | Mean Minigun |
| 0.04 | Shrinkifier 5k, Blade Gun |
| 0 | Pulse Gun |

The top four reach the cap in one shot. Flames ignore spread and go
straight at the crosshair.

Shotgun-type weapons add a pellet cone on top: Shotgun and Jackhammer ±7°,
Gauss Shotgun ±11.5°, Plasma Shotgun and Ion Shotgun ±15°, Sawed-off ±23°.

## Weapon reference

Fire interval and reload are in seconds. A gun fires at most once per
frame, so at 60 fps an interval rounds up to whole frames: 0.088 s and
0.09 s both become 0.1 s, and the flamers fire every frame. The icon class
(bullet, fire, rocket, electric) is what the HUD ammo bar shows.

### 1. Pistol

Clip 12 · Hit 243 (4.1x) · Fire 0.712 s · Reload 1.2 s · Bullet

Always available.

Hits hard but fires slowly. Survival starts you with a 10-round clip; quests
and any Pistol you pick up get the full 12.

While you hold the Pistol, 3 kills in 4 try to drop a Weapon pickup (never
the Pistol). The try is cancelled if a Weapon pickup is already on the
ground or you have My Favourite Weapon, and Bonus Magnet doesn't apply to
it. The other kills use the normal 1-in-9 roll plus an extra 1-in-5. See
[drop chances](../systems/bonuses.md#drop-chances).

### 2. Assault Rifle

Clip 25 · Hit 67 (1x) · Fire 0.117 s · Reload 1.2 s · Bullet

Unlocked by quest 1.1 (*Land Hostile*); always in the Survival drop pool.

Fast and accurate (spread 0.09) with a 25-round clip.

### 3. Shotgun

Clip 12 · 12 pellets × 78 (1.2x) · Fire 0.85 s · Reload 1.9 s · Bullet

Unlocked by quest 1.2 (*Minor Alien Breach*); always in the Survival drop
pool.

Tight ±7° cone, so most pellets land on one target up close.

### 4. Sawed-off Shotgun

Clip 12 · 12 pellets × 78 (1.2x) · Fire 0.87 s · Reload 1.9 s · Bullet

Unlocked by quest 2.8 (*Land Of Lizards*).

Same pellets as the Shotgun in a cone three times wider (±23°). Better for
sweeping crowds, worse for focused fire.

### 5. Submachine Gun

Clip 30 · Hit 67 (1x) · Fire 0.088 s · Reload 1.2 s · Bullet

Unlocked by quest 1.6 (*The Random Factor*); always in the Survival drop
pool.

The shortest fire interval outside the flamers, with low spread (0.082)
and a 30-round clip.

### 6. Gauss Gun

Clip 6 · Hit 299, pierces · Fire 0.6 s · Reload 1.6 s · Bullet

Unlocked by quest 1.8 (*Alien Squads*).

Near-instant slugs (4320 px/s) that [pierce](#piercing) and don't lose
damage with distance. One shot maxes out your spread.

### 7. Mean Minigun

Clip 120 · Fires Pistol rounds: Hit 243 (4.1x) · Fire 0.09 s · Reload 4.0 s · Bullet

Unlocked by quest 2.6 (*Evil Zombies At Large*).

Pistol-strength bullets at minigun speed: about twice the Plasma Minigun's
damage per second. While you hold it your top speed drops to 40%, firing or
not, and the 4-second reload leaves you exposed.

### 8. Flamethrower

Clip 30 · Flame up to 10 · Fire every frame · Reload 2.0 s · Fire

Unlocked by quest 1.4 (*Frontline Assault*).

Throws 60 flames a second at 0.1 ammo each: 5 s of fire per clip. Each
flame burns the first creature it touches for 10 × its remaining strength,
fading to nothing over about 1.1 s (roughly 130 px).

### 9. Plasma Rifle

Clip 20 · Hit 295 (5x) · Fire 0.291 s · Reload 1.2 s · Bullet

Unlocked by quest 2.2 (*Spider Spawns*).

Each bolt hits like a Pistol shot and a bit more, at more than twice the
rate.

### 10. Multi-Plasma

Clip 8 · 3 × 295 (5x) + 2 × 129 (2.1x) · Fire 0.621 s · Reload 1.4 s · Bullet

Unlocked by quest 3.2 (*Lizard Kings*).

Fires five bolts in a fixed fan: Plasma Rifle bolts straight ahead and at
±18°, Plasma Minigun bolts at ±30°.

### 11. Plasma Minigun

Clip 30 · Hit 129 (2.1x) · Fire 0.11 s · Reload 1.3 s · Bullet

Unlocked by quest 2.10 (*Spideroids*).

Rapid plasma stream with a quick 1.3 s reload.

### 12. Rocket Launcher

Clip 5 · Hit 500–600 + 80 px blast · Fire 0.741 s · Reload 1.2 s · Rocket

Unlocked by quest 1.10 (*8-legged Terror*).

Rockets leave at 90 px/s and speed up to 500. A fresh rocket hits harder
(600, down to 500 after 2 s). The blast grows to 80 px over 1/3 s and deals
up to about 245 near its centre. A rocket that hits nothing explodes after
2 s with a 40 px blast. Blasts never hurt you.

### 13. Seeker Rockets

Clip 8 · Hit 80–120 + 28 px blast · Fire 0.311 s · Reload 1.2 s · Rocket

Unlocked by quest 3.4 (*Hidden Evil*).

Each rocket locks onto the enemy nearest your crosshair when fired. If that
target dies, it turns to the enemy nearest the rocket. About a fifth of the
Rocket Launcher's hit, with a small blast (up to about 85). Seekers last
4 s.

### 14. Plasma Shotgun

Clip 8 · 14 pellets × 129 (2.1x) · Fire 0.48 s · Reload 3.1 s · Bullet

Unlocked by quest 4.4 (*The Collaboration*).

Fires 14 Plasma Minigun bolts in a ±15° cone. Devastating burst, but the
3.1-second reload punishes an empty clip.

### 15. Blow Torch

Clip 30 · Flame 8–10 · Fire every frame · Reload 1.5 s · Fire

Unlocked by quest 3.6 (*The Lizquidation*).

Flames die at 80% strength, after about 0.22 s, so the reach is only about
55 px, but every flame that lands burns for 8–10. At 0.05 ammo per flame a
clip lasts 10 s.

### 17. Mini-Rocket Swarmers

Clip 5 · 5 Seeker rockets per shot · Fire 1.8 s · Reload 1.8 s · Rocket

Unlocked by quest 4.6 (*The Unblitzkrieg*).

One trigger pull fires the whole clip as homing [Seeker rockets](#13-seeker-rockets),
then reloads.

!!! bug "Original bug"
    The original fans the rockets by an angle that grows with clip size. At
    6 rockets ([Ammo Maniac](../perks.md#12-ammo-maniac)) they all leave on
    one heading and fly as one. The remake fans them evenly over 120°;
    `--preserve-bugs` restores the clump.

### 18. Rocket Minigun

Clip 16 · Hit 40–80 + 20 px blast · Fire 0.12 s · Reload 1.8 s · Rocket

Unlocked by quest 3.8 (*Lizard Raze*).

Rapid rockets that speed up from 90 to 600 px/s. Each blast deals up to
about 60.

### 19. Pulse Gun

Clip 16 · Hit 67 (1x) · Fire 0.1 s · Reload 0.1 s · Electric

Unlocked by quest 4.2 (*Zombie Time*).

Each hit shoves the target back about 10 px. No spread at all, and the
0.1 s reload means you're almost never empty. That reload is too short to
trigger [Angry Reloader](../perks.md#50-angry-reloader).

### 20. Jackhammer

Clip 16 · 4 pellets × 78 (1.2x) · Fire 0.14 s · Reload 3.0 s · Bullet

Unlocked by quest 3.10 (*Zombie Masters*).

Automatic shotgun: four Shotgun pellets in the Shotgun's ±7° cone, at rifle
speed. The 3-second reload is the price.

### 21. Ion Rifle

Clip 8 · Hit 181 (3x) + 27 blast · Fire 0.4 s · Reload 1.35 s · Electric

Unlocked by quest 2.4 (*Two Fronts*).

Each impact leaves a blast that hits everything within 88 px for about 27
more.

### 22. Ion Minigun

Clip 20 · Hit 89 (1.4x) + 11 blast · Fire 0.1 s · Reload 1.8 s · Electric

Unlocked by quest 4.8 (*Syntax Terror*).

Rapid ion bolts. Each impact hits everything within 60 px for about 11
more.

### 23. Ion Cannon

Clip 3 · Hit 961 (16.7x) + 115 blast · Fire 1.0 s · Reload 3.0 s · Electric

Unlocked by quest 4.10 (*The End of All*).

Slow bolts (240 px/s) that hit hard and leave a 128 px blast worth about
115 to everything inside. Only 3 rounds, and one shot maxes out your
spread.

### 24. Shrinkifier 5k

Clip 8 · Hit 9.5 + shrink · Fire 0.21 s · Reload 1.22 s · Bullet

[Secret weapon](../secret-weapons.md#shrinkifier-5k).

Each hit shrinks the target to 65% of its size. Anything that drops below
size 16 dies on the spot, whatever its health: a size-50 creature dies on
the third hit, a size-64 one on the fourth.

When the shot that shrinks it away also finishes its health (9.5 damage),
the kill pays its XP twice, with two chances at a bonus, and one more hit on
the corpse right after pays it a third time
([original bug](../../rewrite/original-bugs.md#54-a-shrinkifier-kill-pays-twice-and-once-more-on-the-corpse-documented-not-fixed)).
Frozen targets pay once.

### 25. Blade Gun

Clip 6 · Hit 49, pierces; last hit 637 (11x) · Fire 0.35 s · Reload 3.5 s · Bullet

[Secret weapon](../secret-weapons.md#blade-gun).

[Pierces](#piercing) with a 50 pool: it cuts through anything under 98 HP,
and weak kills make it stronger. Once its pool runs out, its last hit uses
the 11x multiplier.

### 28. Plasma Cannon

Clip 3 · Hit 1606 (28x) + ring of 12 × 295 · Fire 0.9 s · Reload 2.7 s · Bullet

Unlocked by quest 5.10 (*The Gathering*).

The biggest multiplier in the game, on a slow bolt (240 px/s). When it hits,
it bursts into a ring of 12 Plasma Rifle bolts flying outward from the
target. One shot maxes out your spread.

### 29. Splitter Gun

Clip 6 · Hit 352 (6x), splits · Fire 0.7 s · Reload 2.2 s · Bullet

[Secret weapon](../secret-weapons.md#splitter-gun).

Every hit splits the shot into two fragments at ±60°, and fragments split
again on their own hits. Fragments start at the impact point, so they hit
at close-range damage (about 350). They can also hit you for 10 each.

### 30. Gauss Shotgun

Clip 4 · 6 slugs × 299, pierce · Fire 1.05 s · Reload 2.1 s · Bullet

Unlocked by quest 5.4 (*The Gang Wars*).

Six full Gauss slugs in a ±11.5° cone. Each [pierces](#piercing) and keeps
its damage at any range.

### 31. Ion Shotgun

Clip 10 · 8 pellets × 89 (1.4x) + 11 blast each · Fire 0.85 s · Reload 1.9 s · Electric

Unlocked by quest 5.1 (*The Beating*).

Eight Ion Minigun bolts in a ±15° cone. Each impact hits everything within
60 px for about 11 more.

## Unobtainable weapons

Nothing unlocks these, so they never drop. You can still look at them in
the remake with `crimson view arsenal`.

| Weapon | Clip | Fire | Reload | In your hands |
| --- | ---: | ---: | ---: | --- |
| 16. HR Flamer | 30 | every frame | 1.8 s | A Blow Torch-range flamer at 0.1 ammo per flame |
| 26. Spider Plasma | 5 | 0.2 s | 1.2 s | Fires nothing. Plasma spiders shoot its bolts at you |
| 27. Evil Scythe | 3 | 1.0 s | 3.0 s | Fires nothing |
| 32. Flameburst | 60 | 0.02 s | 3.0 s | Fires nothing |
| 33. RayGun | 12 | 0.7 s | 2.0 s | Fires nothing |

The four blanks still spend ammo and play a firing sound.

## Availability

- Pistol is always available.
- Each [quest](../modes/quests.md) unlocks its weapon on first completion;
  see each weapon above.
- In Survival, the Assault Rifle, Shotgun and Submachine Gun can always
  drop, even before you've unlocked them in quests.
- [Splitter Gun](../secret-weapons.md#splitter-gun) unlocks after hardcore
  4.10. [Shrinkifier 5k](../secret-weapons.md#shrinkifier-5k) and
  [Blade Gun](../secret-weapons.md#blade-gun) are one-run Survival rewards.
- Weapon pickups and the [Random Weapon](../perks.md#16-random-weapon) perk
  pick an unlocked weapon at random. If the roll lands on a gun you've ever
  been handed (your save keeps the count across all runs), there's a 50%
  chance to roll once more, so guns you've never had come up more often.
  Quest 5.10 never drops the Ion Cannon.
