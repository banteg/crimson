---
icon: lucide/scroll
tags:
  - mechanics
  - modes
  - quests
---

# Quests

Fifty scripted fights in five tiers. Each quest sends fixed waves on a fixed
clock. Kill everything it sends to win.

## Starting out

- You start at the centre of the map with the quest's weapon: the Pistol,
  unless the tier table says otherwise.
- Bonuses drop as usual. Four quests block Nuke or Freeze, noted on each
  quest (see [Bonuses — suppression rules](../systems/bonuses.md#suppression-rules)).
- Level-ups work as usual, offering the perks you've unlocked.
- Ten quests add creatures or nests for a second player: 1.5, 1.6, 1.7, 1.9,
  1.10, 2.3, 2.10, 3.10, 4.7 and 4.8.

## Waves

Groups arrive at set times. A group of several spreads out in a line from
its spawn point, 40 units apart.

Wipe the field and you don't wait for the script: after 3 s with nothing on
the field (and at least 1.7 s into the quest), the next group arrives early.
Nests count as creatures, so a living nest keeps the script on schedule.

## Completion

A quest ends when the script has sent everything and nothing is left on the
field. The quest clock stops there. The 2.5 s wind-down to the results
screen isn't counted.

The clock runs on game time. It slows under Reflex Boost and stops while the
game is paused.

Beating a quest unlocks the next one and the quest's reward. Every quest
except 5.7 unlocks a weapon or a perk.

## Scoring

Your score is your time, and lower ranks higher:

**Final time = quest clock − 50 ms per health point left − 1 s per unspent perk pick**

- Player 1's health counts in whole points, so full health takes 5 s off.
  In co-op player 2's health counts too, fractions included. A fallen
  player's health is below zero, so it adds a little time.
- A perk pick you never spent is worth 1 s.
- The high-score record keeps the final time, kills, shots fired and hit,
  and your most used weapon.

## Failure

If every player dies, the quest fails. It counts as played but never reaches
the high-score table.

## Retries

Fail, hit **Play Again**, and the quest eases off. Each retry weakens the
creatures it spawns (formations only in part; see
[Formations](#formations)):

| Retry | Health | Speed | Contact damage | XP |
| ---: | ---: | ---: | ---: | ---: |
| 1st | 95% | 95% | 95% | 90% |
| 2nd | 90% | 90% | 90% | 85% |
| 3rd | 80% | 80% | 80% | 85% |
| 4th | 70% | 70% | 70% | 80% |
| 5th and later | 50% | 60% | 50% | 80% |

Nests also spawn 0.35 s slower per retry, up to 3 s, except the ringed
lizard nests of 2.8. Picking another quest, going to the main menu or
winning resets the count. Hardcore never eases off.

## Hardcore

Hardcore unlocks once you beat 4.10 in the full game. It keeps its own
progress, starting again from 1.1. Hardcore wins also count toward normal
progress.

- Any group of two or more gets 8 more of the same, whether creatures,
  nests or whole formations. Deadly Fast aliens get 2 more and Plasma
  Shooter spiders none. Single spawns stay single, but in co-op a group of
  2 becomes 10.
- Every creature has 20% more health, 5% more speed and hits 40% harder,
  nests included. Fast yellow spiders are the exception for speed: they end
  up 26% slower. Formations get this only in part; see
  [Formations](#formations).
- Nests spawn 0.4 s faster than on normal, never faster than every 0.1 s.
  The ringed lizard nests of 2.8 are the exception.
- Some quests add their own extras: more splitters in Spideroids (2.10),
  four extra players' worth in Gauntlet (4.7) and Syntax Terror (4.8), and
  a ring of 12 more nests in The End of All (4.10). Nuke stops dropping in
  Zombie Masters (3.10) and Freeze in Spideroids (2.10).

The totals swing hard: Major Alien Breach (4.1) goes from 400 aliens to
2,000.

Beating 4.10 on hardcore unlocks the
[Splitter Gun](../secret-weapons.md#splitter-gun).

## Formations

Rings, chains and grids arrive as one group around a leader (see
[Linked groups](../combat/creatures.md#linked-groups)), and the ringed
lizard nest of 2.8 arrives inside its ring. Hardcore and retries change
only the last creature to join the group. The leader, the nest and every
other member keep their normal stats, so a hardcore ring is barely tougher
than a normal one.

Every ring and chain, and every grid in 5.7, also swaps that last member
for a plain 20 HP alien, on any difficulty and whatever the group is made
of. The 2.9 bronze grid and the 2.8 rings keep theirs.

---

## Quest list

Nest stats below are on normal: hardcore nests spawn 0.4 s faster, except
in 2.8.

### Tier 1

Mostly aliens, plus two spider quests (1.7, 1.10). Introduces nests and
formations.

| Quest | Start weapon | Unlock |
| --- | --- | --- |
| 1.1 Land Hostile | Pistol | [Assault Rifle](../combat/weapons.md#2-assault-rifle) |
| 1.2 Minor Alien Breach | Pistol | [Shotgun](../combat/weapons.md#3-shotgun) |
| 1.3 Target Practice | Pistol | [Uranium Filled Bullets](../perks.md#28-uranium-filled-bullets) |
| 1.4 Frontline Assault | Pistol | [Flamethrower](../combat/weapons.md#8-flamethrower) |
| 1.5 Alien Dens | Pistol | [Doctor](../perks.md#29-doctor) |
| 1.6 The Random Factor | Pistol | [Submachine Gun](../combat/weapons.md#5-submachine-gun) |
| 1.7 Spider Wave Syndrome | Pistol | [Monster Vision](../perks.md#30-monster-vision) |
| 1.8 Alien Squads | Pistol | [Gauss Gun](../combat/weapons.md#6-gauss-gun) |
| 1.9 Nesting Grounds | Pistol | [Hot Tempered](../perks.md#31-hot-tempered) |
| 1.10 8-legged Terror | Pistol | [Rocket Launcher](../combat/weapons.md#12-rocket-launcher) |

**1.1 Land Hostile.** 10 gray aliens in waves of 1, 2, 3 and 4, from the
bottom edge and three corners, all out by 11.5 s.

**1.2 Minor Alien Breach.** 39 aliens. One comes from the right every 3.6 s.
A second right lane joins at 18 s and a left lane at 32.4 s. One big gray
alien (800 hp) comes from below at 39.6 s.

**1.3 Target Practice.** 30 aliens pop up 64–288 units from you, freeze for
1.5 s, then charge. They have 10 hp. A new one arrives every 2 s, speeding
up to every 1.1 s.

**1.4 Frontline Assault.** 50 aliens. A steady stream from the bottom edge,
with the top-left corner joining at the 4th wave and the top-right at the
10th. Waves 4–8 are blue. Two big gray aliens hit from the sides at 16 s.

**1.5 Alien Dens.** 5 nests (1,000 hp, an alien every 3 s, up to 100 each).
Two at 1.5 s, one at the centre at 23.5 s (one per player), and two more at
38.5 s.

**1.6 The Random Factor.** 6 aliens from the right and 6 from the left every
10 s, 10 waves. The right side grows to 8 with two players. Each wave has a
1-in-5 chance of adding a big gray alien from below.

**1.7 Spider Wave Syndrome.** 144 blue spiders from the left, 8 every 5.5 s
(10 with two players), 18 waves.

**1.8 Alien Squads.** 8 rings, each a 200-hp leader with 8 aliens, from
offscreen between 1.5 s and 30 s. Then 52 gray aliens, one from the
top-left and one from the bottom-right every 1.8 s, until 81.2 s.

**1.9 Nesting Grounds.** Alien waves from below at 1.5, 25 and 39 s (8, 8
and 6). Small nests (450 hp, 16 aliens each) arrive at 8, 13 and 18 s,
three more at 41–43 s, and a 1,000-hp nest at the centre at 44 s. It ends
with tougher aliens: 7 at 50 s and 4 at 55 s. Every alien wave grows with
two players.

**1.10 8-legged Terror.** A Spider Boss (4,500 hp, shoots plasma) lands
right of you at 1 s. Then a spider from each corner every 2.2 s from 6 s to
34.6 s. The left corners send one per player.

### Tier 2

Introduces zombies, nests that make lizards, and splitter spiders.

| Quest | Start weapon | Unlock |
| --- | --- | --- |
| 2.1 Everred Pastures | Pistol | [Bonus Economist](../perks.md#32-bonus-economist) |
| 2.2 Spider Spawns | Pistol | [Plasma Rifle](../combat/weapons.md#9-plasma-rifle) |
| 2.3 Arachnoid Farm | Pistol | [Thick Skinned](../perks.md#33-thick-skinned) |
| 2.4 Two Fronts | Pistol | [Ion Rifle](../combat/weapons.md#21-ion-rifle) |
| 2.5 Sweep Stakes | [Gauss Gun](../combat/weapons.md#6-gauss-gun) | [Barrel Greaser](../perks.md#34-barrel-greaser) |
| 2.6 Evil Zombies At Large | Pistol | [Mean Minigun](../combat/weapons.md#7-mean-minigun) |
| 2.7 Survival Of The Fastest | [Submachine Gun](../combat/weapons.md#5-submachine-gun) | [Ammunition Within](../perks.md#35-ammunition-within) |
| 2.8 Land Of Lizards | Pistol | [Sawed-off Shotgun](../combat/weapons.md#4-sawed-off-shotgun) |
| 2.9 Ghost Patrols | Pistol | [Veins of Poison](../perks.md#36-veins-of-poison) |
| 2.10 Spideroids | Pistol | [Plasma Minigun](../combat/weapons.md#11-plasma-minigun) |

**2.1 Everred Pastures.** 160 spiders. Four kinds, one per edge, all at
once every 13 s, growing from 1 to 8 per edge. 16 blue spiders burst from
top and bottom at 40.5 s.

**2.2 Spider Spawns.** Four fragile spider nests in the corners at 1.5 s.
A 1,000-hp nest at the centre at 18 s, then four more fragile nests around
it by 31.5 s. Pairs of fast yellow spiders (50 hp) charge from the left at
3 s and the right at 21 s.

**2.3 Arachnoid Farm.** Two rows of 5 tough spider nests (1,000 hp, a spider
every 5.2 s) at 0.5 s and 10.5 s. From 40.5 s, a middle row of 8 fragile,
fast nests (50 hp, a spider every 2.5 s), 3.5 s apart. Each row gets one
more nest per extra player.

**2.4 Two Fronts.** 40 blue aliens from the right and 40 blue spiders from
the left, one per side every 2 s, 1 s apart. A spider nest and an alien
nest drop in at 22.5 s, 42.5 s and 62.5 s.

**2.5 Sweep Stakes.** 64 aliens in 16 spokes of 4 radiating from you, a new
spoke every 2 s down to 0.88 s, all out by 23.6 s. They freeze for 1.5 s on
arrival.

**2.6 Evil Zombies At Large.** 340 zombies from all four edges every 5.5 s,
growing from 4 to 13 per edge.

**2.7 Survival Of The Fastest.** 22 fragile spider nests (50 hp, a spider
every 2.5 s) laid in a spiral that closes in on the centre, one every
0.9 s. Then 2 spider nests and 2 alien nests in the corners at 22.3 s and
24.3 s.

**2.8 Land Of Lizards.** Four lizard nests, one per quadrant every 10 s. Each
sends a blue lizard every 1.05 s, up to 64, on either difficulty, and sits
inside a ring of 24 fast red aliens.

**2.9 Ghost Patrols.** 2 Deadly Fast aliens at 1.5 s. Then, alternating left
and right every 2.5 s until 30 s, 12 fast leaders, each with 5 translucent
220-hp guards. Another Deadly Fast at 27.5 s. It ends at 37.5 s with a grid
of 27 translucent 260-hp aliens behind a leader.

**2.10 Spideroids.** Just 3 splitter spiders (4 with two players, 6 on
hardcore), but each one [splits into a swarm](../combat/creatures.md#splitters)
as it dies. No Nuke drops, and no Freeze on hardcore.

### Tier 3

Lizards take over: five of the ten are lizard quests. Hidden Evil brings
near-invisible aliens.

| Quest | Start weapon | Unlock |
| --- | --- | --- |
| 3.1 The Blighting | Pistol | [Toxic Avenger](../perks.md#37-toxic-avenger) |
| 3.2 Lizard Kings | Pistol | [Multi-Plasma](../combat/weapons.md#10-multi-plasma) |
| 3.3 The Killing | Pistol | [Regeneration](../perks.md#38-regeneration) |
| 3.4 Hidden Evil | Pistol | [Seeker Rockets](../combat/weapons.md#13-seeker-rockets) |
| 3.5 Surrounded By Reptiles | Pistol | [Pyromaniac](../perks.md#39-pyromaniac) |
| 3.6 The Lizquidation | Pistol | [Blow Torch](../combat/weapons.md#15-blow-torch) |
| 3.7 Spiders Inc. | [Plasma Minigun](../combat/weapons.md#11-plasma-minigun) | [Ninja](../perks.md#40-ninja) |
| 3.8 Lizard Raze | Pistol | [Rocket Minigun](../combat/weapons.md#18-rocket-minigun) |
| 3.9 Deja vu | [Gauss Gun](../combat/weapons.md#6-gauss-gun) | [Highlander](../perks.md#41-highlander) |
| 3.10 Zombie Masters | Pistol | [Jackhammer](../combat/weapons.md#20-jackhammer) |

**3.1 The Blighting.** Alien nests in all four corners at 2 s. Waves of 12
blue aliens and blue lizards in turn, every 16 s from rotating edges, 7
waves. 20 Deadly Fast aliens: 2 per side at 1.5 s, then 4 at 36, 52, 68 and
69 s.

**3.2 Lizard Kings.** Three chains at 1.5 s, two from the right and one from
the left, each a 1,500-hp lizard leading 4 lizards. Then 28 lizards around
a 256-unit circle, one every 0.9 s, going around about one and a half
times.

**3.3 The Killing.** 10 waves every 6 s: 12 blue aliens, spiders or lizards
in turn, from the right, left, bottom and top. Waves 5 and 10 drop 9 alien
nests at random spots instead.

**3.4 Hidden Evil.** 160 near-invisible aliens from below: 50 faint purple,
then 110 green ones you can barely see, all out by 35 s. Until you take it,
Monster Vision is always your first perk choice.

**3.5 Surrounded By Reptiles.** 20 lizard nests (50 hp, a lizard every
6.2 s) box you in: two columns at 1–4.2 s, then two rows at 8–11.2 s.

**3.6 The Lizquidation.** 210 lizards from both sides every 8 s, growing from
6 to 15 per side. Two Deadly Fast aliens open the quest at 1.5 s.

**3.7 Spiders Inc.** 2 fast yellow spiders (50 hp) from below and 4 blue
spiders from above at 0.5 s. From 17 s, fast yellow spiders from top and
bottom every 6 s, growing from 3 to 10 per side: 190 in all.

**3.8 Lizard Raze.** 180 lizards, 6 per side every 6 s until 85.5 s. Three
lizard nests (50 hp, a lizard every 2.2 s) on the left at 10 s.

**3.9 Deja vu.** Sweep Stakes with nests: 72 lizard nests (50 hp, a lizard
every 6.2 s) in 18 spokes of 4 around you, a spoke every 2 s down to
0.72 s, all placed by 25.1 s.

**3.10 Zombie Masters.** Four giant zombies (8,500 hp) that walk and shed a
zombie every 0.9 s, arriving at 1, 6, 14 and 18 s. The first and third
double with two players. No Nuke on hardcore.

### Tier 4

High-volume quests that mix every enemy type with heavy nest patterns.

| Quest | Start weapon | Unlock |
| --- | --- | --- |
| 4.1 Major Alien Breach | [Rocket Minigun](../combat/weapons.md#18-rocket-minigun) | [Jinxed](../perks.md#42-jinxed) |
| 4.2 Zombie Time | Pistol | [Pulse Gun](../combat/weapons.md#19-pulse-gun) |
| 4.3 Lizard Zombie Pact | Pistol | [Perk Master](../perks.md#43-perk-master) |
| 4.4 The Collaboration | Pistol | [Plasma Shotgun](../combat/weapons.md#14-plasma-shotgun) |
| 4.5 The Massacre | Pistol | [Reflex Boosted](../perks.md#44-reflex-boosted) |
| 4.6 The Unblitzkrieg | Pistol | [Mini-Rocket Swarmers](../combat/weapons.md#17-mini-rocket-swarmers) |
| 4.7 Gauntlet | Pistol | [Greater Regeneration](../perks.md#45-greater-regeneration) |
| 4.8 Syntax Terror | Pistol | [Ion Minigun](../combat/weapons.md#22-ion-minigun) |
| 4.9 The Annihilation | Pistol | [Breathing Room](../perks.md#46-breathing-room) |
| 4.10 The End of All | Pistol | [Ion Cannon](../combat/weapons.md#23-ion-cannon) |

**4.1 Major Alien Breach.** 400 green aliens, 2 from the right and 2 from the
top per wave, 100 waves. The gap shrinks from 2 s to 0.53 s. The last wave
lands at 129 s.

**4.2 Zombie Time.** 192 zombies, 8 per side every 8 s until 89.5 s.

**4.3 Lizard Zombie Pact.** 192 zombies, 6 per side every 7 s, 16 waves.
Lizard nests (50 hp, a lizard every 2.2 s) drop left of centre on waves 1,
6, 11 and 16, in groups of 3, 5, 7 and 9.

**4.4 The Collaboration.** 808 creatures. Every 11 s, 16 waves: blue aliens
from the right, blue spiders from the bottom, blue lizards from the left
and zombies from the top, growing from 7 to 19 per edge.

**4.5 The Massacre.** Zombies from the right every 5 s, growing from 3 to 20.
Every other wave, from the first, adds Deadly Fast aliens, growing from 1
to 17. 288 in all.

**4.6 The Unblitzkrieg.** 81 nests, alien and lizard in turn. They trace a
square about 200 units in from the walls twice, plus one at the centre.
The gap between nests drops from 1.8 s to 0.7 s, with the last placed at
82.7 s.

**4.7 Gauntlet.** 10 spider nests (1,000 hp) in a ring 158 units around
you. Then zombies from all four edges every 5.5 s, growing from 2 to 11 per
edge. From 42.5 s, 18 more nests in a ring at 258 units. Each extra player
adds a nest to each ring and a zombie wave.

**4.8 Syntax Terror.** Four waves, 30 s apart, of 10 alien nests (1,000 hp,
an alien every 2.4 s) scattered in a fixed pattern. One more nest per wave
per extra player.

**4.9 The Annihilation.** 2 Deadly Fast aliens on the left at 0.5 s. 12 alien
nests in a zigzag column on the right, 0.5 s apart. From 45 s, 12 more in
the same column, 0.3 s apart.

**4.10 The End of All.** Plasma Shooter spiders from the four corners at 3,
6, 9 and 12 s. Six alien nests 80 units around you from 13 s, and a
3,500-hp Plasma Shooter nest dead centre at 14.8 s. 8 Plasma Shooters from
the sides at 18–21 s, six more nests at 43 s, and 8 more Plasma Shooters at
48–51 s. No Nuke or Freeze drops.

### Tier 5

The hardest quests: bosses, big formations and heavy nest use.

| Quest | Start weapon | Unlock |
| --- | --- | --- |
| 5.1 The Beating | Pistol | [Ion Shotgun](../combat/weapons.md#31-ion-shotgun) |
| 5.2 The Spanking Of The Dead | Pistol | [Death Clock](../perks.md#47-death-clock) |
| 5.3 The Fortress | Pistol | [My Favourite Weapon](../perks.md#48-my-favourite-weapon) |
| 5.4 The Gang Wars | Pistol | [Gauss Shotgun](../combat/weapons.md#30-gauss-shotgun) |
| 5.5 Knee-deep in the Dead | Pistol | [Bandage](../perks.md#49-bandage) |
| 5.6 Cross Fire | Pistol | [Angry Reloader](../perks.md#50-angry-reloader) |
| 5.7 Army of Three | Pistol | None |
| 5.8 Monster Blues | Pistol | [Ion Gun Master](../perks.md#51-ion-gun-master) |
| 5.9 Nagolipoli | Pistol | [Stationary Reloader](../perks.md#52-stationary-reloader) |
| 5.10 The Gathering | Pistol | [Plasma Cannon](../combat/weapons.md#28-plasma-cannon) |

**5.1 The Beating.** A yellow alien that drops a Submachine Gun at 0.5 s.
3 big gray aliens (800 hp) from the right at 8 s, then 64 small green
aliens at 10 s. The same from the left at 18 s and 20 s. At 40 s, 24 ghost
aliens from above and 12 rings of 9 aliens from below.

**5.2 The Spanking Of The Dead.** Two yellow aliens that drop Submachine Guns
at 0.5 s. From 5 s, 128 zombies, one every 0.3 s, on a spiral that closes
from 512 units to under 30 around the centre. Then 16 white zombies
(200 hp) from the right at 48.4 s and 16 from the left at 58.4 s.

**5.3 The Fortress.** 6 blue spiders from the left at 0.1 s. Then 7 small
alien nests (450 hp, 16 aliens each) in a column right of centre by 4.7 s.
From 10.3 s to 30.1 s, 34 spider nests (1,000 hp) fill a 6×6 block in the
upper middle, leaving two gaps.

**5.4 The Gang Wars.** Rings of a 200-hp leader and 8 aliens: one from each
side at the start, then 2 from the right every 4 s until 41.5 s. A chain
of 10 aliens circling a leader comes from below at 50.5 s. Then 2 rings
from the left every 4 s until 95.5 s, and 3 chains at 107.5 s.

**5.5 Knee-deep in the Dead.** Zombies from the left every 1.5 s, two at a
time from 50 s. A 2,000-hp green brute leads at 0.1 s and returns every
12 s, 9 in all. Extra lanes open after 12.5, 24.5, 36.5 and 48.5 s, the
last two sending white zombies: five streams at once.

**5.6 Cross Fire.** 6 blue spiders from the right at 0.1 s. Plasma Shooters
from the left: 4 at 5.5 s, 6 at 15.5 s and 8 at 25.5 s. 2 splitter spiders
at the centre at 18.5 s, and 12 blue spiders from top and bottom at 26 s.

**5.7 Army of Three.** 15 grids, each a 1,500-hp leader with 27 followers:
420 creatures. Three alien grids, three spider grids, then three lizard
grids from the left by 42.5 s. The finale is 3 alien grids from below at
52.5 s and 3 spider grids from above at 56.5 s.

**5.8 Monster Blues.** 10 lizards from the left at 0.5 s, 10 aliens from the
right at 7.5 s, 24 spiders from top and bottom at 17.5 s. From 27.5 s, 64
groups from the left, one every 0.9 s, cycling aliens and two spider kinds,
growing from 2 to 9 each. 396 in all.

**5.9 Nagolipoli.** Rings of 8 and 12 blue spiders around you at 2 s and
8 s. From 13 s to 37.8 s, blue lizards from all four corners every 0.8 s,
growing from 1 to 4 per corner: 320 lizards. Then 6 spider nests down each
side at 49.6 s and 50.6 s, Plasma Shooter nests above and below the centre
at 53.6 s, and 16 lizards from top and bottom at 54.1 s.

**5.10 The Gathering.** A boss parade. 3 splitter spiders by 9.5 s, then 4
Spider Bosses by 24.5 s, then 4 giant zombies by 39.5 s. 6 Plasma Shooters
from the corners at 54.5 s, 6 Spider Bosses from the left at 90.5 s, and 6
more splitters from the right by 109.5 s. No Nuke drops.
