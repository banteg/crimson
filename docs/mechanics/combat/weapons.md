---
tags:
  - mechanics
  - combat
  - weapons
---

# Weapons and behavior

Your weapon determines three things immediately:

- how long you must wait between shots,
- how long a reload takes,
- how wide your spread is while you keep firing.

Each of those values comes from the weapon card and then gets modified by perks and
bonuses. No hidden modifiers are introduced by the docs layer.

## Weapon availability

- Pistol is always available.
- In quests, new weapons become available as progression index advances.
- In Survival, Assault Rifle, Shotgun, and Submachine Gun are always in the
  rotation.
- Random pick logic only uses weapon ids **1 through 33** (33 weapons), with a 50%
  one-time reroll to avoid the same recently used weapon.
- Quest 5.10 never drops **Ion Cannon**.
- [Splitter Gun](../secret-weapons.md) becomes available in hardened progression at
  the full unlock point (full index >= 40).
- Weapon ids 34–40 and 46–49 are currently unnamed in the table and do not
  participate in normal progression rotation.

## Ammo, clip size, and reload timing

- When you equip a weapon, ammo is set to full clip.
- [Ammo Maniac](../perks.md#12-ammo-maniac) and [My Favourite Weapon](../perks.md#48-my-favourite-weapon) increase clip size on equip, so swaps and pickups benefit automatically.
- [Fastloader](../perks.md#3-fastloader) reduces reload duration to 70% of weapon base.
- [Weapon Power Up](../systems/bonuses.md) reduces reload duration to 60% of weapon base and
  refills the clip immediately.
- If you are completely out of ammo and can still fire, a reload starts immediately.
- Reloading usually works normally, but if the gun is empty while you hold fire, reload
  is restarted from the current frame at the end of a near-empty timer.
- [Stationary Reloader](../perks.md#52-stationary-reloader) speeds reload while you are not
  moving.
- [Anxious Loader](../perks.md#18-anxious-loader) subtracts `0.05` seconds from reload time each
  fire press while reloading.
- [Alternate Weapon](../perks.md#9-alternate-weapon) swaps weapons immediately but adds
  `0.1` seconds cooldown before you can shoot again.

## Fire timing and accuracy

Fire timing is mostly:

- one base interval from the weapon table,
- **×0.88** with [Fastshot](../perks.md#14-fastshot),
- **×1.05** with [Sharpshooter](../perks.md#2-sharpshooter).

Accuracy uses a spread heat value:

- each shot raises spread by `1.3 ×` the weapon’s spread increment,
- spread recovers by `0.4/s` while you are not holding perfect control,
- [Sharpshooter](../perks.md#2-sharpshooter) locks spread heat at `0.02` instead of
  decaying toward a floor.

## Fire while reloading

- [Regression Bullets](../perks.md#23-regression-bullets) — allowed during reload and spends experience per shot.
  - Ammo class `1` (flamethrower-class): `reload_time × 4`.
  - All other ammo classes: `reload_time × 200`.
- [Ammunition Within](../perks.md#35-ammunition-within) — allowed during reload and costs player health per shot.
  - `1.0` health for most weapons,
  - `0.15` health for flamethrower-class weapons.
- [Fire Bullets](../systems/bonuses.md), when active, bypasses standard projectile routing for one shot burst
  path and enforces a fixed fire cadence.

## Weapon behavior by type

### Single-shot weapons (most guns)

- Pistol, Assault Rifle, Shotgun variants, Gauss Gun family, plasma/ion rifles, most heavy guns:
  one projectile per trigger pull, scaled by cooldown and spread.

### Shotgun-style weapons

- Shotgun, Sawed-off Shotgun, Jackhammer: multi-pellet spread with randomized speed
  variation.
- Plasma Shotgun: 14 plasma-minigun pellets with per-pellet jitter and variable speed.
- Gauss Shotgun: 6 gauss pellets.
- Ion Shotgun: 8 ion-minigun pellets.
- Multi-Plasma: fixed 5-shot volley at wide/close offsets.

### Rocket-family weapons

- Rocket Launcher: one rocket projectile.
- Seeker Rockets: one homing rocket, and target guidance.
- Mini-Rocket Swarmers: fires one rocket per ammo in the clip at one moment (same pattern spreads automatically).
- Rocket Minigun: rapid heavy rocket stream with secondary handling.

### Continuous/particle weapons

- Flamethrower, Blow Torch, HR Flamer, Bubblegun: projectile visuals are particle-based.
- Flamethrower and HR Flamer drain `0.1` ammo each shot.
- Blow Torch drains `0.05` per shot.
- Bubblegun drains `0.15` per shot.

## Known weapon cards

Unless stated otherwise, listed values are base weapon card values.

| Weapon | Clip | Fire interval (s) | Reload (s) | Note |
| --- | ---: | ---: | ---: | --- |
| Pistol | 10 | 0.7117 | 1.20 | starter baseline |
| Assault Rifle | 25 | 0.117 | 1.20 | default rapid option |
| Shotgun | 12 | 0.85 | 1.90 | 12-pellet spread |
| Sawed-off Shotgun | 12 | 0.87 | 1.90 | spreadier than shotgun |
| Submachine Gun | 30 | 0.0881 | 1.20 | fast control |
| Gauss Gun | 6 | 0.6 | 1.60 | high heat growth |
| Mean Minigun | 120 | 0.09 | 4.00 | movespeed capped while firing |
| Flamethrower | 30 | 0.0081 | 2.00 | particle stream, 0.1 ammo |
| Plasma Rifle | 20 | 0.2908 | 1.20 | 5.0x damage scaling |
| Multi-Plasma | 8 | 0.6208 | 1.40 | 5-projectile fixed volley |
| Plasma Minigun | 30 | 0.11 | 1.30 | |
| Rocket Launcher | 5 | 0.7408 | 1.20 | heavy splash rocket |
| Seeker Rockets | 8 | 0.3108 | 1.20 | homing |
| Plasma Shotgun | 8 | 0.48 | 3.10 | 14 pellets |
| Blow Torch | 30 | 0.0061 | 1.50 | particle stream, 0.05 ammo |
| HR Flamer | 30 | 0.0085 | 1.80 | particle stream |
| Mini-Rocket Swarmers | 5 | 1.8 | 1.8 | fires full clip as rockets |
| Rocket Minigun | 16 | 0.12 | 1.8 | secondary projectile stream |
| Pulse Gun | 16 | 0.1 | 0.1 | short-cycle electric weapon |
| Jackhammer | 16 | 0.14 | 3.00 | 4-shot shotgun feel |
| Ion Rifle | 8 | 0.4 | 1.35 | electric high-damage single-shot |
| Ion Minigun | 20 | 0.1 | 1.8 | |
| Ion Cannon | 3 | 1.0 | 3.0 | very slow, high-damage charge profile |
| Shrinkifier 5k | 8 | 0.21 | 1.22 | secret handout; no listed base damage |
| Blade Gun | 6 | 0.35 | 3.5 | secret handout |
| Spider Plasma | 5 | 0.2 | 1.2 | |
| Evil Scythe | 3 | 1.0 | 3.0 | |
| Plasma Cannon | 3 | 0.9 | 2.7 | very heavy single shot |
| Splitter Gun | 6 | 0.7 | 2.2 | split projectile behavior |
| Gauss Shotgun | 4 | 1.05 | 2.1 | 6 gauss pellets |
| Ion Shotgun | 10 | 0.85 | 1.9 | 8 ion pellets |
| Flameburst | 60 | 0.02 | 3.0 | |
| RayGun | 12 | 0.7 | 2.0 | |
| Plague Sphreader Gun | 5 | 0.2 | 1.2 | hidden interaction weapon |
| Bubblegun | 15 | 0.1613 | 1.2 | slow particle burst, 0.15 ammo |
| Rainbow Gun | 10 | 0.2 | 1.2 | |
| Grim Weapon | 3 | 0.5 | 1.2 | |
| Fire Bullets | 112 | 0.14 | 1.2 | often used as bonus routing path |
| Transmutator | 50 | 0.04 | 5.0 | |
| Blaster R-300 | 20 | 0.08 | 2.0 | |
| Lighting Rifle | 500 | 4.0 | 8.0 | |
| Nuke Launcher | 1 | 4.0 | 8.0 | |

## Where to read next

- Fire timing and cooldown edge cases: [Fire and reload loop](./fire-and-reload.md).
- Damage outcomes from what those weapons connect with: [Damage and death](./damage.md).
