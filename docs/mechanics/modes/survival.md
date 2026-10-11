---
icon: lucide/infinity
tags:
  - mechanics
  - modes
  - survival
---

# Survival

Endless mode. Creatures arrive faster as the clock runs, and get tougher
as your XP grows. You level up, pick perks and last as long as you can.
Score is total XP.

## Starting conditions

- Weapon: Pistol.
- Weapon drops: Pistol, Assault Rifle, Shotgun and Submachine Gun, plus
  every gun your quests have unlocked, and the Splitter Gun after 40
  hardcore quests.
- Bonuses: on.
- Perks: on.

## XP and levels

You reach the next level once your total XP passes
`1000 + 1000 × L^1.8` (rounded down), where L is your current level:
2,000 for level 2, 4,482 for level 3, 8,224 for level 4. In co-op the team
shares one XP pool and one level.

Each level earns a perk pick. A level-up sign appears; click it, or press
Pick Perk or Space, to choose. Picks wait until you take them.

## Spawning

### Waves

Creatures come in one at a time from just outside a random edge. The gap
between them shrinks by 33 ms every minute of game time:

| Time | Gap | Creatures per second |
| ---: | ---: | ---: |
| 0:00 | 500 ms | 2 |
| 5:00 | 334 ms | 3 |
| 10:00 | 167 ms | 6 |
| 12:00 | 100 ms | 10 |
| 14:00 | 34 ms | 29 |

In co-op the rate doubles.

At 15:00 the gap bottoms out at 1 ms, and from then on each spawn brings
one extra creature for every 3.6 seconds past 15:00. The arena fills to its
384-creature cap. See [original bug 37](../../rewrite/original-bugs.md#37-survival-spawning-grows-without-bound-after-fifteen-minutes).

### What spawns

The mix depends on your XP, not the clock:

| XP | Mix |
| --- | --- |
| Under 12,000 | 90% aliens, 10% jerky spiders |
| 12,000–25,000 | 40% zombies, 50% jerky spiders, 10% aliens |
| 25,000–42,000 | 50% aliens, 25% jerky spiders, 25% spiders |
| 42,000–50,000 | Aliens |
| 50,000–90,000 | Spiders |
| 90,000–110,000 | Zombies |
| 110,000+ | 60% aliens, 30% spiders, 10% zombies |

Any spawn has a 1-in-32 chance to become a jerky spider instead.

- Health: 52–67, plus 1 per 800 XP.
- Speed: 0.9, plus 0.045 per 4,000 XP, up to 3.5. Jerky spiders move
  1.3× faster; zombies move at 60% (at least 1.3) with 1.5× health.
- Contact damage: 4.2–6, by size.
- XP: `0.8 × (10 to 19 + 5 × speed + 0.8 × contact damage + 0.4 × health)`,
  about 30–45 at the start, rising as health and speed grow.

Rare variants:

| Odds | Variant | Health | XP |
| --- | --- | ---: | ---: |
| 1 in 90 | Red | 65 | 256 |
| 1 in 120 | Green | 85 | 336 |
| 1 in 180 | Blue | 125 | 416 |
| 1 in 330 | Purple giant | +230 | 480 |
| 1 in 405 | Gold giant | +2,230 | 720 |

### Milestone waves

Reaching these levels sends one scripted wave, once per run:

| Level | XP (more than) | Wave |
| ---: | ---: | --- |
| 5 | 13,125 | Two alien rings, one off each side: a 200 HP leader circled by 8 aliens, 7 of 40 HP and one of 20 HP |
| 9 | 43,224 | Red boss alien (3,800 HP) from the right |
| 11 | 64,095 | 12 spiders in a column from the right |
| 13 | 88,604 | 4 Deadly Fast aliens (30 HP, very fast) from the right |
| 15 | 116,619 | 8 jerky spiders (50 HP, very fast), 4 per side |
| 17 | 148,033 | Spider Boss (4,500 HP, shoots plasma) from the right |
| 19 | 182,756 | One 400 HP splitter spider inside the arena, right of centre |
| 21 | 220,712 | Two more splitters inside the arena, up-left and down-right of centre |
| 26 | 329,315 | 8 Plasma Shooter spiders, 4 per side |
| 32 | 484,560 | 2 Spider Bosses (left and right) and 8 Plasma Shooters (4 top, 4 bottom) |

Splitters [split into a swarm of smaller spiders](../combat/creatures.md#splitters)
as they die.

## Secret weapon handouts

Two one-time weapon handouts can trigger in single-player Survival. See
[Secret weapons](../secret-weapons.md) for full conditions.

## Scoring

Ranked by XP. The score card also shows rank, game time, most-used weapon,
kills and hit %.

## Game over

The run ends once the last player's death animation finishes.
