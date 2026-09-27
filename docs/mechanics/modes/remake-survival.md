---
tags:
  - mechanics
  - modes
  - survival
  - remake
---

# Survival in the remake

The 2014 remake by 10tons keeps the classic spawn interval and creature mix,
but retunes almost everything built on top of them. Remake numbers come from
its final console build (1.03). Classic numbers are the ones on the
[Survival](survival.md) page.

Hover the charts for exact values.

## At a glance

| System | Classic | Remake |
| --- | --- | --- |
| Level curve | `1000 + 1000 × level^1.8` | Hand table, then much steeper curves |
| Level 10 | 53,195 XP | 378,000 XP |
| Milestone waves | 10, gated on player level, last at level 32 | 19, gated on XP, last at 6.3M |
| Spawn interval | `500 − elapsed_ms / 1800` | Same |
| Spawn catch-up | Spawns until the cooldown is paid off | At most one spawn tick per frame |
| Creature mix | By XP tier | Same tiers, plus rare beetles |
| Creature speed | `0.9 + 0.045` per 4k XP, max 3.5 | `0.9 + 0.03` per 4k XP, max 4.0 |
| Creature health | Linear in XP | Scales with size, extra ramps past 200k, 1M and 2M XP |
| Dens | None | 1 in 30 spawn ticks adds a den |

## Spawn rate

Both games shorten the spawn interval by 1 ms every 1.8 seconds of real time.
The classic spawns as many creatures as the elapsed time allows. The remake
spawns at most once per frame. It also rounds each frame down to whole
milliseconds, 16 ms at 60 fps, which makes it about 4% slower.

The two curves overlap until the interval drops below one frame, about
14.5 minutes in. After that the remake's rate follows the frame rate. Past
15 minutes each spawn tick also adds extra creatures in both games. From
there the creature limit, not the spawner, decides how crowded the arena gets.

The chart assumes one player at 60 fps and leaves out dens.

<div data-widget="survival-spawn-rate"></div>

## Leveling

Each level is one perk pick. The remake needs far more XP per level, and the
gap widens: 2.5× at level 2, 7× at level 10, 21× at level 20.

| Level | Classic XP | Remake XP | Ratio |
| ---: | ---: | ---: | ---: |
| 2 | 2,000 | 5,000 | 2.5× |
| 3 | 4,482 | 20,000 | 4.5× |
| 5 | 13,125 | 70,000 | 5.3× |
| 10 | 53,195 | 378,000 | 7.1× |
| 15 | 116,619 | 1,044,000 | 9.0× |
| 20 | 201,334 | 4,220,000 | 21.0× |
| 25 | 306,056 | 13,332,500 | 43.6× |

In the remake, levels 10 to 15 follow `round(0.2 × level^2.5) × 6000`, and
levels 16 and up follow `round((level − 5)^4 / 30) × 2500`. Two remake perks
shrink each level step to 50% or 75%.

<div data-widget="survival-levels"></div>

## Milestone waves

Scripted waves spawn on top of the continuous stream. The classic triggers
them at [player levels](survival.md#milestone-waves). The remake triggers
them at XP stages and has almost twice as many, adding a zombie boss,
Spideroids and beetles late in the run.

<div data-widget="survival-milestones"></div>

| Stage | Remake XP | Blitz XP | Wave |
| ---: | ---: | ---: | --- |
| 2 | 16,167 | 3,524 | Two alien leaders with ring followers |
| 3 | 22,542 | 7,167 | Huge green zombie |
| 4 | 31,786 | 12,450 | 12 random blue spiders |
| 5 | 45,190 | 20,109 | 4 weak lizard dens |
| 6 | 64,625 | 31,215 | 4 Deadly Fast aliens |
| 7 | 92,807 | 47,319 | 8 jerky spiders |
| 8 | 133,671 | 70,670 | Spider Boss |
| 9 | 192,923 | 104,528 | Spideroid |
| 10 | 278,838 | 153,622 | 8 Plasma Shooter spiders |
| 11 | 403,415 | 224,809 | 12 Plasma Shooter spiders |
| 12 | 700,000 | 394,286 | Zombie boss |
| 13 | 1,400,000 | 794,286 | 2 Spider Bosses and 8 Plasma Shooters |
| 14 | 2,100,000 | 1,194,286 | 2 Spideroids |
| 15 | 2,800,000 | 1,594,286 | 2 emerald beetles |
| 16 | 3,500,000 | 1,994,286 | 2 Spider Bosses |
| 17 | 4,200,000 | 2,394,286 | 2 ancient beetles |
| 18 | 4,900,000 | 2,794,286 | 5 Spider Bosses |
| 19 | 5,600,000 | 3,194,286 | 3 ancient beetles |
| 20 | 6,300,000 | 3,594,286 | 4 ancient beetles |

The remake's stages are a fixed XP table up to stage 11, then one stage
every 700,000 XP. Nothing new spawns after stage 20.

## Creatures

The creature type mix by XP is the same in both games. The remake adds a
1-in-32 roll that turns an edge spawn into a beetle once XP passes 50,000.

The charts below show an average edge spawn, before type modifiers and rare
variants.

<div data-widget="survival-creature-health"></div>

<div data-widget="survival-creature-speed"></div>

| Stat | Classic | Remake |
| --- | --- | --- |
| Health | `52 + rand(0..15) + 0.00125 × XP` | `size / 64 × (40 + rand(0..32) + 0.00125 × XP + late ramp)` |
| Late health ramp | None | `+0.002` per XP past 200k, again past 1M, again past 2M |
| Speed | `0.9 + 0.045` per 4k XP, max 3.5 | `0.9 + 0.03` per 4k XP, max 4.0 |
| Contact damage | `size × 0.095` | `size × 0.1` |

Classic creatures hit the speed cap at about 230k XP. Remake creatures
start slower and pass the classic cap at about 350k XP. Remake health
pulls away past 200k XP. At 5M XP an average remake creature has roughly
four times the classic health.

### Rare variants

| Variant | Chance | Classic | Remake |
| --- | --- | --- | --- |
| Red | 2 in 180 | 65 hp | Same |
| Green | 2 in 240 | 85 hp | Same |
| Blue | 2 in 360 | 125 hp | Same |
| Purple | 4 in 1320 | +230 hp, size 80 | +1,430 hp, size 80, 4× contact damage |
| Yellow | 4 in 1620 | +2,230 hp, size 85 | +5,230 hp, size 85, 5× contact damage |

### Dens

On 1 in 30 spawn ticks the remake also spawns a den (lizard, spider or alien).
Each den adds 20 ms to that spawn interval. Classic Survival has no dens.

## Weapon drops

The remake adds a dedicated weapon-drop roll: 4% by default, 9% during the
first minute of a run. The roll is biased away from handing out the Pistol.

## Blitz

Blitz is the remake's Survival with the whole game running 1.5× faster, so
movement, firing, bonus timers and spawn cooldowns all speed up. The spawn
interval still shrinks on the real-time clock, which gives 1.5× the Survival
spawn rate at any point in wall-clock time.

Blitz also reaches milestone stages early. It checks `XP × 1.75 + 10,000`
against the stage table (the Blitz XP column above), so the first wave
arrives at about 3.5k XP. Perks, weapons, bonuses and the player are the
same as in the remake's Survival.
