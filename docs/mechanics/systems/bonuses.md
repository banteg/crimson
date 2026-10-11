---
icon: lucide/gift
tags:
  - mechanics
  - systems
  - bonuses
---

# Bonuses

Bonuses drop from killed creatures. Walk within 26 units of one to collect
it. There are 14 types: timed effects, one-shot bursts and instant rewards.

Durations below are base values. [Bonus Economist](../perks.md#32-bonus-economist)
makes every timed bonus last 1.5× as long. Picking up a timed bonus that is
already running adds its full duration to the time left. While Reflex Boost
runs, every bonus timer counts down in slow motion too.

## 1. Points

Adds 500 XP, or 1000 XP with a 3-in-8 chance. Double Experience doesn't
double it.

## 2. Energizer

Duration: 8 seconds. The rarest bonus: 1 in 8,576 drop rolls.

Creatures under 500 max HP run away from you. Creatures under 380 max HP
that come within 20 units are eaten: they die instantly, pay their XP twice
(three times with Double Experience) and drop no bonus. The extra payment
ignores [Bloody Mess](../perks.md#1-bloody-mess-quick-learner), so with it
an eaten creature pays 2.3× (3.6× with Double Experience). No creature can hurt
you by touch, but ranged shots still hit.

## 3. Weapon

Replaces the gun in your hands with a random unlocked weapon, fully loaded
and ready to fire. With [Alternate Weapon](../perks.md#9-alternate-weapon) the
other slot is left alone. The gun is chosen when the bonus drops. A gun
you've been handed before, in any run, gets rerolled half the time, so the
pick favours guns you've never had.

A Weapon from the normal drop roll that lands within 56 units of a player
turns into a 100-point bonus instead. Weapon drops stop entirely with
[My Favourite Weapon](../perks.md#48-my-favourite-weapon).

!!! bug "Original bug"
    In the original executable, the 56-unit conversion checks player 1's
    position only. Run with `--preserve-bugs` to keep that co-op asymmetry.

## 4. Weapon Power Up

Duration: 10 seconds.

You fire 50% faster and reloads take 60% as long (42% with
[Fastloader](../perks.md#3-fastloader)). Pickup refills your clip and
cancels any reload. The timer is shared: in co-op it powers up both
players, but only the one who picks it up gets the refill.

## 5. Nuke

Instant. A blast hits every creature within 256 units for (256 − distance) × 5
damage: 1,280 at the centre, nothing at the edge. It also throws 4–7 pistol
bullets and 2 gauss shots in random directions.

Blast kills drop no bonuses. Kills by the stray bullets can.

## 6. Double Experience

Duration: 6 seconds.

Every kill pays double XP.

## 7. Shock Chain

Instant. Fires an Ion Rifle shot at the nearest creature. Each hit jumps to
the nearest creature at least 100 units away, up to 32 links. There is no
maximum jump distance, so a chain can cross the whole arena.

No second Shock Chain drops while one is still jumping. Chain shots don't
count toward your shots fired.

## 8. Fireblast

Instant. Fires 16 Plasma Rifle shots in a ring, 22.5° apart, from the pickup
point.

The shots don't count toward your shots fired, and Fire Bullets doesn't
convert them. Their kills drop bonuses as usual.

## 9. Reflex Boost

Duration: 3 seconds of game time, about 8.4 real seconds (13.4 with Bonus
Economist).

The world runs at 30% speed, ramping back to full speed over the last
second. You move at 60% speed, twice as quick as everything else, but your
gun slows down with the world. Shots cost no ammo while it runs. Pickup
refills every player's clip and cancels their reloads.

## 10. Shield

Duration: 7 seconds. In co-op, each player has their own.

Blocks all damage: contact, enemy shots, and self-damage from perks like
[Ammunition Within](../perks.md#35-ammunition-within). Hits don't shorten it.

## 11. Freeze

Duration: 5 seconds.

Creatures stop moving and attacking. Anything killed while frozen shatters
and leaves no corpse, and pickup shatters any corpses already lying around.
No second Freeze drops while one is running.

## 12. MediKit

Instant. Restores 10 HP, up to 100. Never drops while
[Death Clock](../perks.md#47-death-clock) is active.

A dead player's body still collects bonuses. A MediKit brings them back if
the killing blow left them above −10 HP and it lands in reach before the
run ends; see [Death](../combat/player.md#death).

## 13. Speed

Duration: 8 seconds. In co-op, each player has their own.

You move 50% faster.

## 14. Fire Bullets

Duration: 5 seconds. In co-op, each player has their own.

Every shot becomes fire bullets, one per pellet of your current gun, and
costs no ammo. Pickup refills your clip and cancels any reload.

For how Fire Bullets changed between versions, see
[Fire Bullets 1.9.8 vs 1.9.93](../../re/static/fire-bullets-1.9.8-vs-1.9.93.md).

!!! bug "Original bug"
    In the original executable, either player's Fire Bullets converts both
    players' shots. Holding G while firing also grants 10 seconds of Fire
    Bullets. The rewrite drops both; `--preserve-bugs` restores them.

## Drop chances

Each kill rolls 1-in-9 (11.1%) for a drop.
[Bonus Magnet](../perks.md#27-bonus-magnet) gives a failed roll a second
1-in-10 chance (20% in all).

While you hold the Pistol, 3 kills in 4 try to drop a Weapon instead (never
the Pistol). The try is cancelled if a Weapon is already on the ground, and
Bonus Magnet doesn't apply to it. The other kills roll 1-in-9, then an extra
1-in-5 (28.9%), then Bonus Magnet (36%).

A drop is cancelled if:

- the kill is within 32 units of the arena edge;
- another bonus lies within 32 units;
- 16 bonuses are already out;
- a bonus of the same type (other than Points) is already on the ground;
- it's a Weapon you or a co-op partner already carries, in either slot.

The type comes from this table:

| Bonus | Weight | Chance |
| --- | ---: | ---: |
| Points | 832 | 9.70% |
| Weapon | 703 | 8.20% |
| Weapon Power Up | 640 | 7.46% |
| Nuke | 640 | 7.46% |
| Double Experience | 640 | 7.46% |
| Shock Chain | 640 | 7.46% |
| Fireblast | 640 | 7.46% |
| Reflex Boost | 640 | 7.46% |
| Shield | 640 | 7.46% |
| Freeze | 640 | 7.46% |
| MediKit | 640 | 7.46% |
| Speed | 640 | 7.46% |
| Fire Bullets | 640 | 7.46% |
| Energizer | 1 | 0.012% |

A suppressed type is rerolled, up to 100 times, then the drop becomes Points.

### Suppression rules

- **Shock Chain**: while a chain is still jumping.
- **Freeze**: while Freeze is running.
- **Shield**: while any player has a shield.
- **Weapon**: with [My Favourite Weapon](../perks.md#48-my-favourite-weapon),
  or while a Fire Bullets bonus lies on the ground.
- **MediKit**: with [Death Clock](../perks.md#47-death-clock).
- **Nuke**: in quests 2.10, 4.10 and 5.10, and in 3.10 on hardcore.
- **Freeze**: in quest 4.10, and in 2.10 on hardcore.

!!! bug "Original bug"
    The original cancels any drop whose amount matches player 1's weapon
    number, whatever the bonus. Some bonuses never drop with certain guns:
    Nuke, Double Experience, Shock Chain and Fireblast with the Pistol;
    Reflex Boost with the Shotgun; Fire Bullets with the Sawed-off Shotgun;
    Freeze with the Submachine Gun; Shield with the Mean Minigun; Speed and
    Energizer with the Flamethrower; Weapon Power Up and MediKit with the
    Multi-Plasma. The rewrite only cancels Weapons you already carry;
    `--preserve-bugs` restores the original rule.

### On the ground

Unpicked bonuses vanish after 10 seconds, except in the tutorial.

## By mode

- **Survival** and **Quests**: all bonuses drop, minus the quest rules above.
- **Rush** and **Typ-o-Shooter**: no bonuses.
- **Tutorial**: no random drops. The script places three Points bonuses, then
  Speed, Weapon (Submachine Gun), Double Experience, Nuke and Reflex Boost.
