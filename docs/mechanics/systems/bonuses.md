---
tags:
  - mechanics
  - systems
  - bonuses
---

# Bonuses

Bonuses are pickup items that spawn from creature deaths. Walking within
26 units of one collects it instantly. There are 14 types: some grant a
timed effect, some fire a one-shot burst, and some give a passive reward.

All timed durations listed below are base values. [Bonus Economist](../perks.md#32-bonus-economist)
multiplies every timed duration by 1.5.

## 1. Points

Adds experience directly. Amount is either 500 or 1000 (roughly 3-in-8
chance for 1000). Points from this bonus are not affected by Double
Experience.

## 2. Energizer

Duration: 8 seconds. Drop rate: 0.01% (1-in-10368), by far the rarest
bonus.

Creatures with less than 500 max HP flee from the player (reversed
heading). Creatures with less than 380 max HP that come within 20 units
are eaten on contact, dying instantly and awarding XP. Contact damage
from creatures is disabled while Energizer is active.

## 3. Weapon

Assigns a random unlocked weapon. If the player has [Alternate Weapon](../perks.md#9-alternate-weapon)
and the second slot is empty, the weapon goes into the second slot
instead. Equipping a weapon resets ammo to full clip, clears reload
state, and resets shot cooldown.

When a Weapon bonus spawns within 56 units of a player, it is converted
into a 100-point bonus instead. Weapon bonuses are suppressed entirely
when [My Favourite Weapon](../perks.md#48-my-favourite-weapon) is active.

## 4. Weapon Power Up

Duration: 10 seconds.

Shot cooldown decays 50% faster (×1.5 recovery rate) and reload time is
reduced to 60% of base. On pickup, ammo is refilled, reload is cancelled,
and shot cooldown is reset to zero.

## 5. Nuke

Instant. Spawns 4–7 pistol projectiles and 2 gauss projectiles in random
directions from the pickup point, each with randomized speed. Deals
explosion damage to all creatures within 256 units: (256 − distance) × 5.
Shakes the camera.

Kills from the explosion do not spawn further bonuses.

## 6. Double Experience

Duration: 6 seconds.

All XP from creature kills is doubled while active.

## 7. Shock Chain

Instant. Fires an Ion Rifle projectile at the nearest creature. On hit,
the projectile chains to the next nearest creature (minimum 100 units
away), up to 32 links total. There is no range limit per link beyond the
minimum distance, so chains can cross the entire arena.

A new Shock Chain cannot spawn while a previous chain is still active.

## 8. Fireblast

Instant. Fires 16 Plasma Rifle projectiles in an evenly spaced radial
ring (22.5° apart) from the pickup point.

Kills from the burst do not spawn further bonuses.

## 9. Reflex Boost

Duration: 3 seconds.

Slows the entire game world to 30% speed (×0.3 time scale). During the
final second the scale ramps linearly back to 1.0. Player movement is
compensated so you move at ×2 relative to the slowed world. On pickup,
all players have their ammo refilled and reload cancelled.

## 10. Shield

Duration: 7 seconds. Per-player timer.

Blocks all incoming damage (contact, projectile, and self-damage from
perks like [Ammunition Within](../perks.md#35-ammunition-within)) for the duration. The shield is purely
time-based and does not expire on hit.

In co-op, each player has an independent shield timer.

## 11. Freeze

Duration: 5 seconds.

All creatures stop moving and stop attacking. A new Freeze cannot spawn
while a previous Freeze is still active.

## 12. MediKit

Instant. Restores 10 HP (capped at 100). No effect if already at full
health. Suppressed from the drop pool when [Death Clock](../perks.md#47-death-clock) is active.

## 13. Speed

Duration: 8 seconds. Per-player timer.

The player's base speed multiplier is 2.0. Speed adds 1.0, bringing it to
3.0 — a 50% boost. In co-op, each player has an independent speed timer.

## 14. Fire Bullets

Duration: 5 seconds. Per-player timer.

Overrides the player's projectiles with fire-type pellets. Pellet count
is determined by the current weapon. On pickup, ammo is refilled, reload
is cancelled, and shot cooldown is reset to zero.

In co-op, each player has an independent Fire Bullets timer.

For a detailed comparison of Fire Bullets behavior across game versions,
see [Fire Bullets 1.9.8 vs 1.9.93](../../re/static/fire-bullets-1.9.8-vs-1.9.93.md).

## Drop mechanics

Each creature kill has an 11.1% base chance (1-in-9) to spawn a bonus.
When that roll fails and [Bonus Magnet](../perks.md#27-bonus-magnet) is active, a second chance
roll gives a 10% (1-in-10) chance.

When the player is holding the Pistol, there is a 75% (3-in-4) chance to
force a Weapon bonus instead of the normal roll. This stacks with Bonus
Magnet.

Once a bonus is determined to spawn, the type is selected from a weighted
distribution:

| Bonus | Weight | Chance |
| --- | ---: | ---: |
| Weapon | 1343 | 12.95% |
| Weapon Power Up | 1280 | 12.35% |
| Nuke | 1152 | 11.11% |
| Points | 832 | 8.02% |
| Double Experience | 640 | 6.17% |
| Shock Chain | 640 | 6.17% |
| Fireblast | 640 | 6.17% |
| Reflex Boost | 640 | 6.17% |
| Shield | 640 | 6.17% |
| Freeze | 640 | 6.17% |
| MediKit | 640 | 6.17% |
| Speed | 640 | 6.17% |
| Fire Bullets | 640 | 6.17% |
| Energizer | 1 | 0.01% |

If the selected type is suppressed (see below), the game rerolls up to
100 times, then falls back to Points.

### Suppression rules

- **Shock Chain**: rerolled if a chain is already active.
- **Freeze**: rerolled if Freeze timer is already active.
- **Shield**: rerolled if any player has an active shield.
- **Weapon**: rerolled if [My Favourite Weapon](../perks.md#48-my-favourite-weapon) is active, or if a Fire
  Bullets bonus is already sitting in the pickup pool.
- **MediKit**: rerolled if [Death Clock](../perks.md#47-death-clock) is active.
- **Nuke**: suppressed in quests 2.10, 4.10, 5.10, and also 3.10 on
  hardcore.
- **Freeze**: suppressed in quest 4.10, and also 2.10 on hardcore.

### Spawn constraints

- Maximum 16 bonuses on screen at once.
- Minimum 32 units between bonuses.
- Unpicked bonuses vanish after 10 seconds (never in tutorial).
- Bonuses must spawn at least 32 pixels from the world edge.

## Mode availability

- **Survival**: full bonus system active.
- **Quest**: full bonus system active, with stage-specific Nuke/Freeze
  suppression on certain quests.
- **Rush**: bonuses completely disabled.
- **Typ-o-Shooter**: bonuses completely disabled. Weapon Power Up and
  Reflex Boost timers are also cleared every frame.
- **Tutorial**: normal spawning disabled. The tutorial script places
  specific bonuses at fixed stages: Speed, Weapon, Double Experience,
  Nuke, Reflex Boost.
