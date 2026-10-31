---
tags:
  - mechanics
  - systems
  - co-op
---

# Co-op

Two players share one screen and one run. The rewrite also plays three or
four. This page collects the co-op rules and links to the pages with the
details.

## Playing together

- Pick **2 players** from the player list in the Play Game menu, then a
  mode. The rewrite lists up to 4 players.
- Survival, Rush and Quests play in co-op. Typ-o-Shooter and the Tutorial
  disappear from the menu.
- Set each player's aiming method, moving method and keys in Options →
  Controls, under *Configure for*. The Level Up key sits on player 1's
  page and opens the menu for the whole team.
- There is one mouse. Two players on Mouse aiming share one crosshair.
- The *Computer* aiming and moving methods hand a player to the game's
  autopilot.
- In the rewrite, player 1 uses the first gamepad and player 2 the second.
  A player still on the stock bindings switches to twin-stick controls the
  first time they use their pad.
- Player 1 is tinted blue, player 2 orange.
- Each player count keeps its own high-score tables.

## What you share

- **XP and level.** One pool. Every kill, by anyone, and every Points bonus
  adds to it. Survival's creature mix and milestone waves read the team's
  XP and level.
- **Perks.** One set: a pick applies to everyone. [Perks](../perks.md)
  notes how each one works in co-op.
- **The perk menu.** One sign for the team. Open it with the Level Up key,
  Space or keypad +, or click the sign. The game pauses for everyone while
  the menu is open. It opens while anyone is alive.
- **Most bonus timers.** Weapon Power Up, Double Experience, Reflex Boost,
  Freeze and Energizer run for the whole team. See
  [Bonuses](bonuses.md).
- **The score.** One entry for the team. Kills, shots fired and hit %
  count everyone. The most-used weapon on the score card is player 1's.

## What each player has

- 100 HP. Creatures and enemy shots hurt only the player they hit.
- A weapon, clip and reload. Weapon bonuses and MediKits go to whoever
  picks them up.
- Shield, Speed and Fire Bullets timers.
- Fire Cough and Hot Tempered elapsed timers and next randomized intervals.
  `--preserve-bugs` retains the original shared intervals.

If two players reach a bonus at the same moment, both collect it: a Nuke
goes off twice.

In the original the Reload key doesn't reload in co-op: your gun reloads
only when the clip runs dry. The rewrite reloads on the key in co-op too
([bug 40](classic-quirks.md#co-op)). It is one key for the team, so it
reloads every player who can.

Six perks are never offered with two players: Grim Deal, Alternate Weapon,
Fatal Lottery, Random Weapon, Final Revenge and Highlander (see
[how perk offers work](../perks.md#how-perk-offers-work)). The rewrite
leaves them out with three or four players too.

## More players, more creatures

Creatures don't get tougher in co-op. There are just more of them.

- **Survival**: the spawn clock runs once per player, so two players face
  twice the stream. See [Survival](../modes/survival.md#waves).
- **Rush**: creature pairs arrive twice as often. See
  [Rush](../modes/rush.md#spawning).
- **Quests**: some quests add creatures or nests for each extra player. See
  [Quests](../modes/quests.md#starting-out).

With three or four players the rewrite scales the same way.

## Targeting and the camera

Each creature chases the nearer living player and switches when the other
one gets closer or its target falls; see
[Co-op targeting](../combat/creatures.md#co-op-targeting). It only bites the
player it's chasing.

The camera centres on the midpoint between the living players. When one
falls it follows the survivor. Nothing holds you together: walk apart and
one of you can leave the screen.

## Death and game over

When one player falls, the other plays on. The run ends 0.8 s after the
last player falls. A quest fails only when every player is down.

A fallen player's body stays where it fell and still collects bonuses. If
the killing blow left them above −10 HP, a MediKit that lands within reach
of the body brings them back; see [Death](../combat/player.md#death).

The quest life bonus counts every player's health, a fallen player's too;
see [Quests](../modes/quests.md#scoring).

## Friendly fire

Off by default. Open the console with `~` and enter `cv_friendlyFire 1`.

Your shots then hit your partner for 10 HP each, Fire Bullets, perk rings
and Fireblast included. Shield blocks the hit; nothing else reduces it.
Flames, rockets, explosions and Shock Chain never hurt a partner.

## Single-player only

- Typ-o-Shooter and the Tutorial.
- The Shrinkifier 5k and Blade Gun handouts in Survival. See
  [Secret weapons](../secret-weapons.md).
- Ranked runs on one machine. A pair playing online ranks on its own
  [boards](../../rewrite/ranked-rules.md#boards-and-scores).

## Player-one quirks of the original

The original reads player 1's state in places where it should read each
player's own. Regeneration heals only player 1; Doctor, Pyrokinetic and
Evil Eyes follow player 1's crosshair; either player's Fire Bullets
converts both players' shots. The rewrite fixes all of these by default,
along with the Reload key's single-player gate.
[Classic quirks](classic-quirks.md#co-op) lists them all.
