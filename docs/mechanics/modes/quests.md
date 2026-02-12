---
icon: lucide/scroll
tags:
  - mechanics
  - modes
  - quests
---

# Quests

Scripted encounters with a fixed spawn timeline. The player clears all
enemies to complete the quest.

## Starting conditions

- Weapon: defined per quest (Pistol unless noted).
- Bonuses: enabled, with stage-specific suppression (see
  [Bonuses — suppression rules](../systems/bonuses.md#suppression-rules)).
- Perks: enabled, manual selection on level-up.
- Terrain: defined per quest.

## Spawning

Each quest has a spawn table of timed entries. A timeline counter
advances with game time, and entries fire when their trigger time is
reached. Each entry can spawn one or more creatures in a formation with
fixed spacing.

If no living creatures remain and the spawn table still has entries, the
timeline keeps advancing. If the table has entries but no creatures have
been active for over 3 seconds (and timeline > ~1700 ms), the next entry
is force-triggered to prevent stalls.

### Hardcore scaling

On hardcore difficulty, most multi-spawn entries get +8 extra creatures.
One special entry class gets +2.

## Completion

A quest is complete when both conditions are met:

1. Spawn table is empty.
2. No living creatures remain.

The completion transition takes about 2.5 seconds: feedback sound at
~0.8 s, music transition at ~2 s, result finalized at ~2.5 s.

## Failure

If all players die before completion, the run is marked as failed. A
record is still written for stats and score tables.

## Scoring

Ranked by fastest completion time. Failed attempts are ranked behind
completed ones. The record includes elapsed time, kills, shots
fired/hit, and most used weapon.

---

## Quest list

Each quest unlocks a weapon or perk on first completion. Start weapon is
Pistol unless noted otherwise.

### Tier 1

Aliens only. Introduces spawner nests and basic formations.

#### 1.1. Land Hostile

Unlocks Assault Rifle.
Four small waves of aliens from edges and corners.

#### 1.2. Minor Alien Breach

Unlocks Shotgun.
Escalating alien stream from the right. A brute alien appears mid-quest.

#### 1.3. Target Practice

Unlocks [Uranium Filled Bullets](../perks.md#28-uranium-filled-bullets).
Orbiters spawn at random positions around the center with accelerating
tempo. Randomized layout.

#### 1.4. Frontline Assault

Unlocks Flamethrower.
Steady bottom-edge stream, adds corners over time. Blue-tinted aliens
mid-quest. Two brutes from the sides at wave 10.

#### 1.5. Alien Dens

Unlocks [Doctor](../perks.md#29-doctor).
Spawner nests that produce child aliens. The center nest scales with
player count.

#### 1.6. The Random Factor

Unlocks Submachine Gun.
Alternating left/right waves of random alien types. Brutes appear
randomly (~20% chance per wave). Randomized layout.

#### 1.7. Spider Wave Syndrome

Unlocks [Monster Vision](../perks.md#30-monster-vision).
First spider quest. Repeated spider waves from the left edge every 5.5
seconds. Wave size scales with player count.

#### 1.8. Alien Squads

Unlocks Gauss Gun.
Ring formations of 8 aliens from offscreen, then a steady stream of
individual aliens.

#### 1.9. Nesting Grounds

Unlocks [Hot Tempered](../perks.md#31-hot-tempered).
Mix of random alien waves and spawner nests. Multiple spawner phases,
ending with tougher alien variants.

#### 1.10. 8-legged Terror

Unlocks Rocket Launcher.
Opens with a shock boss spider. Random spider packs from all four
corners for the rest of the quest.

### Tier 2

Introduces zombies, lizard-producing spawners, and splitter spiders.

#### 2.1. Everred Pastures

Unlocks [Bonus Economist](../perks.md#32-bonus-economist).
Four different spider types from all four edges simultaneously.
Escalating wave sizes. Blue-tinted spider burst at wave 4.

#### 2.2. Spider Spawns

Unlocks Plasma Rifle.
Spawner nests in all four corners producing spiders. Timer-based spider
bosses patrol from the edges.

#### 2.3. Arachnoid Farm

Unlocks [Thick Skinned](../perks.md#33-thick-skinned).
Lines of spawner nests. Slow spawners first, then fast spawners.

#### 2.4. Two Fronts

Unlocks Ion Rifle.
Aliens from the right, spiders from the left simultaneously. Spawner
nests appear at waves 10, 20, and 30.

#### 2.5. Sweep Stakes

Starts with Gauss Gun. Unlocks [Barrel Greaser](../perks.md#34-barrel-greaser).
Short quest (35 s time limit). Radial orbiter spawns with accelerating
tempo, same pattern as Target Practice.

#### 2.6. Evil Zombies At Large

Unlocks Mean Minigun.
First zombie quest. Zombie waves from all four edges, escalating from
4 to 13 per edge.

#### 2.7. Survival Of The Fastest

Starts with Submachine Gun. Unlocks [Ammunition Within](../perks.md#35-ammunition-within).
Spiral pattern of fast spawner nests wrapping inward, plus corner
spawners at the end.

#### 2.8. Land Of Lizards

Unlocks Sawed-off Shotgun.
Four spawner nests that produce lizard rings, placed one at a time in
each quadrant.

#### 2.9. Ghost Patrols

Unlocks [Veins of Poison](../perks.md#36-veins-of-poison).
Fast red aliens, then alternating left/right ring formations of 5
aliens. Ends with a grid formation.

#### 2.10. Spideroids

Unlocks Plasma Minigun.
Splitter spiders from edges. Only 3–6 spawns, but each spider splits
on death into smaller ones.

### Tier 3

Introduces ghosts, lizard enemy types, and mixed-species quests.

#### 3.1. The Blighting

Unlocks [Toxic Avenger](../perks.md#37-toxic-avenger).
Fast red aliens plus spawner nests in all four corners. Alternating
alien and lizard waves from rotating edges.

#### 3.2. Lizard Kings

Unlocks Multi-Plasma.
Chain formations of 4 lizards from the sides, plus a ring of 28
individual lizards spiraling around the center.

#### 3.3. The Killing

Unlocks [Regeneration](../perks.md#38-regeneration).
Cycling alien/spider/lizard waves from rotating edges. Every 5th wave
spawns random-position spawner nests instead. Randomized layout.

#### 3.4. Hidden Evil

Unlocks Seeker Rockets.
Ghost aliens exclusively. 160 total: 50 purple, 30 green, 50 small
green, 30 more green. Pure crowd control.

#### 3.5. Surrounded By Reptiles

Unlocks [Pyromaniac](../perks.md#39-pyromaniac).
Lizard spawner nests in two perpendicular lines — vertical pairs first,
then horizontal pairs.

#### 3.6. The Lizquidation

Unlocks Blow Torch.
Escalating lizard waves from both sides (6 → 15 per wave). Fast red
aliens at wave 4.

#### 3.7. Spiders Inc.

Starts with Plasma Minigun. Unlocks [Ninja](../perks.md#40-ninja).
Timer-based spider bosses plus blue spiders. Escalating paired waves
from top and bottom.

#### 3.8. Lizard Raze

Unlocks Rocket Minigun.
Paired lizard waves from the sides every 6 seconds, plus three lizard
spawner nests.

#### 3.9. Deja vu

Starts with Gauss Gun. Unlocks [Highlander](../perks.md#41-highlander).
Same radial pattern as Sweep Stakes (2.5), but spawns lizard spawner
nests instead of orbiters.

#### 3.10. Zombie Masters

Unlocks Jackhammer.
Zombie boss spawners at staggered positions. Spawner count scales with
player count.

### Tier 4

High-volume quests mixing all enemy types and complex spawner patterns.

#### 4.1. Major Alien Breach

Starts with Rocket Minigun. Unlocks [Jinxed](../perks.md#42-jinxed).
Massive alien flood from right and top edges with accelerating spawn
interval. 100 spawn entries total.

#### 4.2. Zombie Time

Unlocks Pulse Gun.
Zombie waves of 8 from both sides every 8 seconds. Straightforward
endurance test.

#### 4.3. Lizard Zombie Pact

Unlocks [Perk Master](../perks.md#43-perk-master).
Zombie waves from both sides plus lizard spawner nests every 5th wave,
with escalating spawner counts.

#### 4.4. The Collaboration

Unlocks Plasma Shotgun.
All four enemy types at once: aliens right, spiders bottom, lizards
left, zombies top. Escalating counts per wave.

#### 4.5. The Massacre

Unlocks [Reflex Boosted](../perks.md#44-reflex-boosted).
Zombie stream from the right. Fast red aliens join on even waves.

#### 4.6. The Unblitzkrieg

Unlocks Mini-Rocket Swarmers.
Slow-building spiral of spawner nests placed along the edges. Each
successive loop places nests faster.

#### 4.7. Gauntlet

Unlocks [Greater Regeneration](../perks.md#45-greater-regeneration).
Inner ring of spawner nests, then zombie waves from all four edges,
then an outer ring of spawner nests.

#### 4.8. Syntax Terror

Unlocks Ion Minigun.
Spawner nests at mathematically computed positions (polynomial hash
pattern). Multiple waves with pseudorandom placement.

#### 4.9. The Annihilation

Unlocks [Breathing Room](../perks.md#46-breathing-room).
Fast red aliens plus two phases of spawner nests in staggered columns.

#### 4.10. The End of All

Unlocks Ion Cannon.
Ranged spider bosses in all four corners, spawner ring at center, more
ranged spiders from the sides, a second spawner ring. Nuke and Freeze
bonuses suppressed.

### Tier 5

The hardest quests. Boss encounters, grid formations, and heavy spawner
use. All 8 minutes long.

#### 5.1. The Beating

Unlocks Ion Shotgun.
Weapon bonus alien first, then brutes, green alien floods from both
sides, brown transparent aliens, and ring formations from below.

#### 5.2. The Spanking Of The Dead

Unlocks [Death Clock](../perks.md#47-death-clock).
Two weapon bonus aliens, then 130 zombies spawning in a tightening
spiral around the center, followed by grey zombie waves from both
sides.

#### 5.3. The Fortress

Unlocks [My Favourite Weapon](../perks.md#48-my-favourite-weapon).
Blue spiders, then limited spawner nests along one side, then a grid
of spider spawner nests filling most of the map.

#### 5.4. The Gang Wars

Unlocks Gauss Shotgun.
Ring formations of 8 aliens from both sides in alternating phases.
Chain formation of 10 aliens mid-quest. Second ring phase and triple
chain formation finale.

#### 5.5. Knee-deep in the Dead

Unlocks [Bandage](../perks.md#49-bandage).
Relentless zombie stream from the left. Green zombie brute every 8th
wave. Adds more spawn lanes as the quest progresses, up to five
simultaneous streams.

#### 5.6. Cross Fire

Unlocks [Angry Reloader](../perks.md#50-angry-reloader).
Blue spiders, escalating ranged spider bosses, splitter spiders in
the center, and more blue spiders from top and bottom.

#### 5.7. Army of Three

No unlock.
Three phases: alien grid formations, spider grid formations, lizard
grid formations. Finale: triple alien grids from below and triple
spider grids from above.

#### 5.8. Monster Blues

Unlocks [Ion Gun Master](../perks.md#51-ion-gun-master).
All types in sequence: lizards, aliens, spiders. Then a long mixed
phase cycling all types with escalating counts.

#### 5.9. Nagolipoli

Unlocks [Stationary Reloader](../perks.md#52-stationary-reloader).
Spider rings around the center, then lizard waves from all four
corners, then spawner nests on both sides, ending with ranged spider
spawners at center.

#### 5.10. The Gathering

Unlocks Plasma Cannon.
Boss parade: splitter spiders, shock boss spiders, zombie boss
spawners, ranged spider bosses from all corners, more shock bosses,
and a final splitter wave. Nuke suppressed.
