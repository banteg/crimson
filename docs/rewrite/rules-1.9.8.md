---
tags:
  - rewrite
  - parity
---

# 1.9.8 rules

The rewrite plays Crimsonland 1.9.93, the last classic release. A run can play
the rules of 1.9.8, a 2003 release, instead: tick **1.9.8** in the Play Game
menu, left of **Ranked**; tick both for a ranked 1.9.8 run. The replay keeps
the choice, so watching the run later plays the same rules. In online co-op,
the Host's box picks the rules for both players.

1.9.8 runs keep high score tables of their own, as 1.9.8 kept its scores apart
from 1.9.93's. While the box is ticked, the High scores screen shows them, with
1.9.8 in its title, along with 1.9.8's online boards.

## What changes

- **Fire Bullets adds to your gun instead of replacing it.** While it lasts,
  every shot your gun fires gets a Fire Bullets shot alongside it, and the gun
  keeps its own fire rate, ammo and reloads. The Flamethrower, Blow Torch, HR
  Flamer, the rocket weapons and the Bubblegun fire flames, rockets and
  bubbles rather than shots, so they get nothing from it. See
  [Fire Bullets 1.9.8 vs 1.9.93](../re/static/fire-bullets-1.9.8-vs-1.9.93.md).
- **The Fire Bullets bonus doesn't drop** while any player holds the
  Flamethrower, Blow Torch, HR Flamer, Flameburst, Rocket Launcher, Seeker
  Rockets, Mini-Rocket Swarmers or Rocket Minigun.
- **Fewer shots fit in the air**: 64 at once, player and enemy shots together,
  against 96 in 1.9.93. With the air full, each new shot takes the last of the
  64 places from the shot there, so under Fire Bullets the gun's shot replaces
  the Fire Bullets shot fired with it. With one place free, the Fire Bullets
  shot takes it and the gun's shot takes the last place.
- **Four perks don't exist yet**: [Man Bomb](../mechanics/perks.md#53-man-bomb),
  [Fire Cough](../mechanics/perks.md#54-fire-cough),
  [Living Fortress](../mechanics/perks.md#55-living-fortress) and
  [Tough Reloader](../mechanics/perks.md#56-tough-reloader) are never offered,
  and the Statistics menu's perk database leaves them out while the box is ticked.
- **[Angry Reloader](../mechanics/perks.md#50-angry-reloader) fires on every
  reload**, the short ones included.
- **[Radioactive](../mechanics/perks.md#13-radioactive) kills lizards** like
  any other creature, instead of leaving them at 1 HP.
- **Typ-o-Shooter names use fewer words**: "sleep", "onyx", "mill", "blue",
  "below", "scape", "reap", "damo", "break" and "boom" are missing from the
  [word list](../mechanics/modes/typo-shooter.md#names).
- **The G key does nothing**, even with `--preserve-bugs`: 1.9.8 never had
  the [Fire Bullets shortcut](original-bugs.md#24-holding-g-while-firing-grants-free-fire-bullets).

Everything else plays as in 1.9.93, including the rewrite's fixes for the
original's bugs.

## What stays 1.9.93's

A 1.9.8 run brings back 1.9.8's rules, not the whole 2003 release. Apart
from the rules above, the weapons, creatures, spawns, modes, quests, unlocks
and art are the same in both releases. Where 1.9.8 differs in other ways, a
1.9.8 run plays as 1.9.93:

- **Arithmetic.** 1.9.8 was built with an older compiler that orders and
  rounds some calculations differently, in code both releases share too. A
  1.9.8 run calculates as 1.9.93 does, so the same moves can play out a little
  differently than in the original 1.9.8.
- **Menus and controls.** The menus, the console, key binding and the way the
  game reads keys, mouse and joysticks are 1.9.93's, and so are the game's
  messages. 1.9.8's birthday balloons and Christmas snow don't appear on the
  menus.
- **Smoke.** With the screen full of smoke from guns and rocket trails, a new
  puff replaces an old one as 1.9.93 picks it.
- **Shareware.** 1.9.8's trial limits, purchase screens and Reflexive Arcade
  code are left out.

## 1.9.8's own bugs

1.9.8 has a few bugs that later releases fixed: Radioactive pays twice for
some kills, Jinxed kills during Freeze, Infernal Contract charges only player
1, and My Favourite Weapon loses its clip bonus and lets some weapon drops
through. A 1.9.8 run plays these as 1.9.93 does; `--preserve-bugs` brings
them back, along with the rest of the original's bugs. They are listed with
the other [classic quirks](../mechanics/systems/classic-quirks.md#198-rules).

## Ranking

A ranked 1.9.8 run ranks on boards of its own, never mixed with 1.9.93's: its
rank, the board's best runs and its player's best count 1.9.8 runs only. The
verifier plays 1.9.8 runs as the Python port does, and every other ranked rule
holds as for 1.9.93. A play ranks on one board only: a replay whose inputs
another build's board already holds is refused
([leaderboard identity](leaderboard-identity.md#duplicates-and-stolen-runs)).
The site's high score pages switch between the 1.9.93 and 1.9.8 boards, and a
1.9.8 run's page says so. See [Ranked rules](ranked-rules.md).
