---
tags:
  - mechanics
  - combat
  - player
---

# Player

You have 100 HP and nothing else between you and the swarm. This page covers
how you take damage, move, aim, reload and die. [Perks](../perks.md) and
[bonuses](../systems/bonuses.md) change many of these numbers.

## Health and damage

You start every run with 100 HP. Nothing heals you past 100.

### Bites

A creature bites when it comes within 30 units of you. Each creature bites
at most once a second, but you get no grace period after a hit: a pack
around you can all bite in the same instant. Bite damage depends on the
creature: [Survival](../modes/survival.md#what-spawns) creatures bite for
4.2–6.

- Creatures of size 16 or less never bite.
- A creature of size 30 or less dies when it touches you, right after its
  bite.
- In co-op a creature only bites the player it's chasing (see
  [Co-op targeting](creatures.md#co-op-targeting)).
- [Energizer](../systems/bonuses.md#2-energizer) and
  [Freeze](../systems/bonuses.md#11-freeze) stop all bites.

These change what a bite does to you:

| Effect | Bite |
| --- | --- |
| [Shield](../systems/bonuses.md#10-shield), [Death Clock](../perks.md#47-death-clock) | Blocked |
| [Tough Reloader](../perks.md#56-tough-reloader) | ×0.5 while you reload |
| [Thick Skinned](../perks.md#33-thick-skinned) | ×0.666 |
| [Dodger](../perks.md#26-dodger) / [Ninja](../perks.md#40-ninja) | Misses 1 time in 5 / 1 in 3 |
| [Highlander](../perks.md#41-highlander) | No damage, but 1 in 10 kills you outright |

A bite that lands also knocks you about:

- Your body swings up to about 115° either way. Mouse aim is unaffected, but
  you slow down while your legs turn back (see [Moving](#moving)), and
  with Relative movement the hit throws you off course.
- Your spread grows by 1% of the damage (see
  [Accuracy](weapons.md#accuracy)).

[Unstoppable](../perks.md#22-unstoppable) prevents both.

### Enemy shots

Creature projectiles take a flat 10 HP. Only Shield and Death Clock block
them: Thick Skinned, Tough Reloader, Dodger, Ninja and Highlander do
nothing, and shots don't knock you about.

A shot hits you when it passes within about 10 units of your centre, plus
the shot's own radius. With friendly fire on, your partner's shots hit you
for the same 10.

!!! bug "Original bug"
    In the original executable, enemy shots still hit you through Death
    Clock, and until the first Shock Chain of a session finishes, an
    occasional enemy shot passes straight through you. Use
    `--preserve-bugs` to keep both.

## Moving

Your top speed is 100 units a second. You reach it in 0.4 s and stop from
it in 0.13 s.

| Situation | Top speed |
| --- | ---: |
| Normal | 100 |
| [Long Distance Runner](../perks.md#5-long-distance-runner) | 140 |
| [Speed](../systems/bonuses.md#13-speed) | 150 |
| Speed and Long Distance Runner | 210 |
| [Mean Minigun](weapons.md#7-mean-minigun) in hand | 40 (60 with Speed) |

[Alternate Weapon](../perks.md#9-alternate-weapon) multiplies all of these
by 0.8.

With every scheme except Relative, your legs turn toward the direction you
want to go, closing 5× the remaining angle per second. Your speed depends on
how far they still have to turn: full when lined up, half at 90° off,
nothing at 180°. A full reversal stalls you: you're back to half speed
after 0.14 s and 90% after 0.46 s.

Creatures don't block you. You can walk straight through a crowd; they stop
20 units short of you. Nests are solid: you slide along them instead
of walking through.

## Controls

Each player picks a movement scheme and an aim scheme. The defaults are
Static movement on WASD and Mouse aim, with Mouse1 to fire and Mouse3 to
reload. In single-player the arrow keys also move you, whatever your
bindings.

### Movement

- **Static**: the four keys move you up, down, left and right on screen,
  and pairs give the diagonals.
- **Relative**: tank controls. Forward and back drive along your facing, left
  and right turn you. Turning starts at about 29°/s and builds to 200°/s over
  0.6 s; it drops back once you stop both turning and moving. Reversing is as
  fast as going forward and ignores the Mean Minigun's speed cap.
- **Dual Action Pad**: the move stick. Any tilt past 20% is full speed.
- **Mouse point&click**: hold the reload key to set your destination at the
  cursor. You walk there and stop within 20 units of it. The key no longer
  reloads.

### Aim

- **Mouse**: you aim at the cursor. The cursor stays on screen, so you can't
  aim further than you can see.
- **Keyboard**: the aim keys (Q and E) turn your aim at 172°/s. They only
  work with Relative or Static movement. Turning your body with the
  movement keys turns your aim too.
- **Joystick**: the hat turns your aim at 229°/s.
- **Mouse relative**: you aim the way the cursor points from a fixed spot
  200 pixels right of and below the screen's top-left corner.
- **Dual Action Pad**: the aim stick. The crosshair sits 42 units out at
  rest and up to 138 at full tilt.

With Keyboard, Joystick and Mouse relative aim the crosshair sits 60 units
in front of you.

!!! bug "Original bug"
    In the original executable, the Dual Action Pad aim stick has no dead
    zone: letting go swings your aim to face left, and a worn stick makes it
    twitch. The rewrite keeps your last direction inside 20% tilt. Use
    `--preserve-bugs` to keep the original.

## Reloading

Firing your last round starts a reload. You can't fire until it ends,
unless you have [Regression Bullets](../perks.md#23-regression-bullets) or
[Ammunition Within](../perks.md#35-ammunition-within).

Each gun's base reload time is in [Weapons](weapons.md#weapon-reference).
[Fastloader](../perks.md#3-fastloader) and
[Weapon Power Up](../systems/bonuses.md#4-weapon-power-up) shorten it;
[Stationary Reloader](../perks.md#52-stationary-reloader) and
[Anxious Loader](../perks.md#18-anxious-loader) speed it up.

The reload key starts a reload whenever none is running, even on a full
clip. Holding it reloads over and over. It only works in single-player, and
not with Alternate Weapon (the key swaps guns, every 0.2 s while held) or
point-and-click movement (the key moves you). There you reload only when
the clip runs dry.

Picking up a weapon gives you a full clip, ready to fire at once, and
cancels any reload.

Shots cost no ammo while [Reflex Boost](../systems/bonuses.md#9-reflex-boost)
runs or while you have [Fire Bullets](../systems/bonuses.md#14-fire-bullets).

## Death

You die at 0 HP. The run ends 0.8 s later, once your death animation
finishes; in co-op, 0.8 s after the last player falls. A failed quest goes
to the quest-failed screen.

Your body stays where it fell and still collects any bonus within 26 units.
A [MediKit](../systems/bonuses.md#12-medikit) adds 10 HP to it, so if the
killing blow left you above −10 HP, a MediKit that lands within reach brings
you back; a death from an enemy shot always qualifies. In co-op that
works for as long as your partner lives; in single-player only in the 0.8 s
before the run ends. Regeneration, Bandage and Death Clock skip dead
players.

## The arena

The arena is 1024 × 1024 units. You can't leave it: your centre stays at
least 24 units from every edge.

The camera centres on you and stops at the arena's edges. You see as much
as your screen resolution shows: 800 × 600 by default, the arena's full
width at 1024. [Ranked runs](../../rewrite/ranked-rules.md) fix the view at
1024 × 768. In co-op the camera
[centres between the players](../systems/co-op.md#targeting-and-the-camera).

Creatures arrive from outside the edges and aren't fenced in: they can
wander off the map. Nests stay inside it.

The ground is decoration. There are no walls, obstacles or slow ground;
blood, scorch marks and corpses are only painted on.
