---
tags:
  - mechanics
  - combat
  - creatures
---

# Creatures

Everything you shoot is one of five creature types. Each spawn sets its own
health, speed, bite and XP, so a type tells you how it moves, not how tough
it is. Numbers here are for normal difficulty; see
[Hardcore](../modes/quests.md#hardcore) and
[Retries](../modes/quests.md#retries) for how quests change them, and
[What spawns](../modes/survival.md#what-spawns) for Survival.

## The creature types

- **Aliens**: the most varied type, from 5 HP near-invisible aliens to the
  3,800 HP red boss.
- **Lizards**: [Radioactive](../perks.md#13-radioactive) can't finish them off.
- **Zombies**: mostly slow. In Survival they move at 60% speed and have
  1.5× health.
- **Jerky spiders**: move in bursts (see [Stop-and-go](#stop-and-go)). The
  Spider Boss and the spiders of the quest 5.7 grids are the exceptions.
- **Spiders**: the second spider kind. They run steadily. Splitters are
  this kind.

## Movement

Speed is in game units: speed 1 covers 30 units a second. You run at 100
units a second, so anything faster than 3.33 outruns you. Survival
creatures top out at 3.5 (105 units a second). A creature turns at a rate
that grows with its speed, so slow ones swing wide.

### Closing in

Most creatures don't run straight at you. Each one picks a fixed compass
bearing and aims at a point on that side of you, 85% as far from you as it
is. The point slides in as the creature does, so it curls in from that
side. It heads straight at you instead when:

- it is more than 800 units from you;
- its aim point is more than 400 units from it, or less than 40.

So far-off creatures beeline and close ones curve. A few use other
patterns:

- The blue-tinted quest aliens and lizards and the lizard chain leader curl
  in tighter, at 55%.
- Rush aliens swing wider, at 90%, and never beeline.
- Grid leaders, Plasma Shooters and Typ-o-Shooter creatures chase you
  directly.

A jerky spider drops back to the standard 85% approach after its first
pause.

### Co-op targeting

Each creature hunts one player. It keeps checking, and switches to the other
player whenever they're alive and closer. If its player dies, it switches at
once.

## How they hurt you

### Bites and contact

Creatures bigger than size 16 bite from 30 units, at most once a second, and
can't get closer than 20. [Player](player.md#bites) has the rules and
what changes a bite.

A creature of size 30 or less dies when it touches you. You get **no XP and
no bonus** for it, though it counts as a kill. This catches the 64 small
green aliens of quest 5.1 (size 30) and anything the
[Shrinkifier 5k](./weapons.md#24-shrinkifier-5k) has shrunk that far.

### Ranged attacks

Two creatures shoot, and only while they are more than 64 units from you.
Shots fly the way the shooter is facing.

- **Spider Boss**: a Plasma Rifle bolt (600 units a second) once a second.
- **Plasma Shooter**: a slow plasma bolt (200 units a second) every
  0.4–0.7 s.

Shots and bites share one cooldown. An enemy shot that hits you deals a
flat 10; see [Enemy shots](player.md#enemy-shots).

Enemy shots also hit creatures in their path, for the same damage your own
shot of that kind would deal, boosted by your bullet-damage perks. A Spider
Boss bolt hits a creature for up to 295; a Plasma Shooter bolt for up
to 38. Those kills pay you XP.

## Special creatures

### Stop-and-go

Jerky spiders run for 0.7–1.7 s, then stand still for 0.5–1.0 s, at random.
They still bite and shoot while paused. Jerky spiders get a speed bonus:
1.2× in quests (except the fast yellow spider), 1.3× in Survival and 1.4×
in Rush. Speeds on this page include it.

### Nests

Nests appear only in quests. A nest never moves and never leaves the arena.
You can't walk into a nest, or into a giant zombie. Nests have no bite, but
you can get close enough to the small ones for them to "bite" you for 0:
that still triggers [Mr. Melee](../perks.md#17-mr-melee),
[Veins of Poison](../perks.md#36-veins-of-poison) and
[Toxic Avenger](../perks.md#37-toxic-avenger) on the nest.

A nest releases a creature on a timer until it reaches its limit. Kill it and
it stops; what it already released stays.

| Nest | Health | Releases | Every | Up to | XP |
| --- | ---: | --- | ---: | ---: | ---: |
| Alien nest | 1,000 | aliens | 2.4 or 3.0 s | 100 | 3,000 |
| Small alien nest | 450 | aliens | 2.2 s | 16 | 1,000 |
| Spider nest | 1,000 | jerky spiders | 5.2 s | 100 | 3,000 |
| Fragile spider nest | 50 | jerky spiders | 2.5 s | 100 | 800 |
| Lizard nest | 50 | lizards | 2.2 or 6.2 s | 100 | 1,000 |
| Ringed lizard nest (2.8) | 50 | blue lizards | 1.05 s | 64 | 5,000 |
| Plasma Shooter nest | 3,500 | Plasma Shooters | 6.2 s | 100 | 5,000 |

The ringed lizard nest's ring of 24 red aliens (40 HP, speed 4.0, bite 30,
350 XP) carries on after the nest dies.

### Splitters

A splitter spider splits in two when it dies, as long as its size is over
35. Each half:

- is 8 smaller;
- has a quarter of the original splitter's health: 100 for the 400 HP
  splitter, in every generation and on every difficulty;
- is 0.1 faster, bites for 70% as much and pays ⅔ of the XP.

A size-80 splitter splits six times: 127 spiders in all, worth 19,388 XP
before perks. The last generation moves at 2.6 and bites for 2. A splitter
shrunk to size 35 or less dies without splitting.

### Linked groups

Some quest creatures arrive in formation around a leader. When the leader
dies, some groups die with it and some fight on. Followers that die with
their leader still pay their XP and can drop bonuses.

| Group | Where | Followers | Without the leader |
| --- | --- | --- | --- |
| Ring: 200 HP leader | Survival level 5; quests 1.8, 5.1, 5.4 | 8 aliens, 40 HP | Fight on |
| Patrol: 50 HP fast leader | Quest 2.9 | 5 translucent guards, 220 HP | Die |
| Bronze grid: 500 HP leader | Quest 2.9 | 27 translucent aliens, 260 HP | Fight on |
| Lizard chain: 1,500 HP leader | Quest 3.2 | 4 lizards trailing it, 60 HP | Fight on |
| Alien chain: 200 HP leader | Quest 5.4 | 10 aliens, 60 HP | Fight on |
| White grid: 1,500 HP leader | Quest 5.7 | 27 aliens, spiders or lizards, 40 HP | Die |

White-grid followers don't hold formation: each hunts you on its own until
the leader falls. Kill the leader of a 5.7 grid and all 27 die with it.

In every group except the bronze grid, the last follower is a plain 20 HP
alien, even in a lizard chain or a spider grid. In every group, hardcore
and retries change only that last follower; see
[Formations](../modes/quests.md#formations).

## Bosses and named creatures

| Creature | Health | Speed | Bite | XP | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| Giant zombie | 8,500 | 1.3 | 50 | 6,600 | Sheds a zombie every 0.9 s, up to 812. Quests 3.10, 5.10 |
| Spider Boss | 4,500 | 2.0 | 50 | 4,500 | Shoots. Survival levels 17 and 32; quests 1.10, 5.10 |
| Red boss alien | 3,800 | 2.0 | 40 | 1,500 | Survival level 9 |
| Green brute zombie | 2,000 | 2.1 | 15 | 460 | Quest 5.5 |
| Lizard chain leader | 1,500 | 2.1 | 150 | 1,000 | Its bite is more than your full health. Quest 3.2 |
| White grid leader | 1,500 | 2.0 | 40 | 600 | Quest 5.7 |
| Big gray alien | 800 | 2.5 | 20 | 450 | Quests 1.2, 1.4, 1.6, 5.1 |
| Splitter spider | 400 | 2.0 | 17 | 1,000 | Survival levels 19 and 21; quests 2.10, 5.6, 5.10 |
| Plasma Shooter | 200 | 2.4 | 20 | 200 | Shoots; jerky. Survival levels 26 and 32; quests 4.10, 5.6, 5.10 |
| White zombie | 200 | 1.7 | 15 | 160 | Quests 5.2, 5.5 |
| Fast yellow spider | 50 | 4.8 | 10 | 433 | Jerky. Survival level 15; quests 2.2, 3.7 |
| Bonus carrier | 50 | 2.1 | 10 | 125 | Yellow alien; always drops a Submachine Gun. Quests 5.1, 5.2; Tutorial |
| Deadly Fast alien | 30 | 3.6 | 20 | 450 | Outruns you. Survival level 13; quests 2.9, 3.1, 3.6, 4.5, 4.9 |

!!! bug "Original bug"
    In the original executable, a bonus carrier killed twice over, for
    example by a rocket and its blast, drops its Submachine Gun twice. Use
    `--preserve-bugs` to keep it.

## XP per kill

Each creature carries a fixed XP value, paid to the team's shared pool when
it dies. Fractions are dropped.

- **Quest creatures**: the values above. Ordinary aliens, spiders, lizards
  and zombies pay 50–280. [Retries](../modes/quests.md#retries) cut it.
- **Survival creatures**: worked out from each one's health, speed and
  bite; see [What spawns](../modes/survival.md#what-spawns).
- [Bloody Mess](../perks.md#1-bloody-mess-quick-learner) pays 1.3× (rounded
  down).
- [Double Experience](../systems/bonuses.md#6-double-experience) pays the
  kill again, Bloody Mess bonus included.

Some kills pay less:

- Contact deaths of small creatures pay nothing.
- [Breathing Room](../perks.md#46-breathing-room) and
  [Lifeline 50-50](../perks.md#57-lifeline-50-50) pay nothing.
- [Radioactive](../perks.md#13-radioactive) and
  [Jinxed](../perks.md#42-jinxed) kills pay base XP only.
- [Energizer](../systems/bonuses.md#2-energizer) kills pay base XP plus the
  normal kill payment.

## What bonuses and perks do to them

- [Freeze](../systems/bonuses.md#11-freeze): everything stops. Creatures
  don't move, bite, shoot or release, and poison and plague pause.
- [Energizer](../systems/bonuses.md#2-energizer): creatures under 500 max
  HP run from you; under 380 they're eaten on contact. Nobody bites.
- [Evil Eyes](../perks.md#11-evil-eyes): the creature under your crosshair
  stands still and can't bite, shoot or release.
- [Monster Vision](../perks.md#30-monster-vision): highlights every
  creature; purely visual.
- [Plaguebearer](../perks.md#10-plaguebearer): infected creatures run from
  you.
- [Shrinkifier 5k](./weapons.md#24-shrinkifier-5k): shrinks creatures until
  they die, or until they're small enough to die on contact.
- For about 0.4 s after death a body still stops ordinary bullets; see
  [Hit radius](./weapons.md#hit-radius).
