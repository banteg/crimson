---
tags:
  - mechanics
  - systems
  - secrets
---

# Secrets and easter eggs

Everything hidden in Crimsonland Classic 1.9.93 that a player can find, and
what each one gives you. Most give you nothing but the find.

## Secret weapons

The Splitter Gun, Shrinkifier 5k and Blade Gun come from outside the quest
list. Their conditions are on [Secret weapons](../secret-weapons.md).

## The Secret Path

A puzzle in the credits. Open them from the main menu: **Statistics →
Credits**. The credits scroll one line per second and loop.

- Click every line that contains a lowercase "o": 37 lines, headings
  included, down to *Click the ones with the round ones!* at the very end.
  A capital "O" doesn't count.
- A correct click highlights the line and chimes.
- Clicking a line without an "o" plays a grunt and unmarks the nearest
  marked line at or above it.
- Leaving the credits clears every mark.

Once every "o" line is marked, a **Secret** button appears next to **Back**,
and a riddle replaces *You can stop watching now.* and the blank lines
around it:

```text
Inside Dead Let Mighty Blood
Do Firepower See Mark Of
The Sacrifice Old Center
Yourself Ground First For
Triangle Cube Last Not Flee
0001001110000010101110011
0101001011100010010101100
011111001000111
(4 bits for index) <- OOOPS I meant FIVE!
(4 bits for index)
```

Number the 23 words 1 to 23 in reading order. Split the binary into 5-bit
groups, read each as a word number, and you get:

**Dead Center Inside The Triangle Of The First Blood Sacrifice Yourself For
Firepower**

That's the [Blade Gun](../secret-weapons.md#blade-gun) handout: in
single-player Survival, your first three kills mark a triangle, and standing
at its centre with your health below 15 gets you the gun.

## AlienZooKeeper

The **Secret** button opens *AlienZooKeeper*, "a puzzle game unfinished
..or something more?". It's a match-3 game on a 6×6 board of alien heads in
five colours.

- **Reset** starts a game: a fresh board with no ready-made lines, score 0,
  9.6 s on the clock.
- Click a tile, then any other tile, and they swap. They don't need to be
  next to each other, and a swap that matches nothing stays.
- Three of a colour in a row or column clear, one line per swap, for +1
  score and +2 s.
- Cleared cells stay empty until the next Reset.
- When the clock runs out, it's Game Over.

It unlocks nothing, and the score isn't saved. The board stays as you left
it until you quit the game.

## Orbes Volantes Exstare

On March 3 (your computer's date), the Statistics screen can flash
*Orbes Volantes Exstare* in faint green near the top-left corner. The game
rolls once per launch, so 1 launch in 32 shows it, and it's gone the
instant it appears.

## Holding G

In the original, holding **G** while you fire gives you 10 s of Fire
Bullets on every shot, with no cheat mode needed. Each shot resets the timer
to 10 s, even when a Fire Bullets pickup had left you more.

The rewrite ignores G; `--preserve-bugs` brings it back
([original bug 24](../../rewrite/original-bugs.md#24-holding-g-while-firing-grants-free-fire-bullets)).

## Hidden control schemes

The Controls screen lists three movement schemes and five aim schemes. Two
more exist.

**Mouse point&click movement.** In the original, type
`cv_enableMousePointAndClickMovement 1` in the console and the movement list
gains *Mouse point&click*. Your Reload key becomes **Move to cursor**: hold
it to send your trooper to the crosshair, where it stops within 20 units.
The rewrite doesn't read that console variable; it lists the scheme only
when your `crimson.cfg` already selects it. Point&click runs rank.

**Computer.** An autopilot for movement and an aimbot for aim. No menu ever
lists them; only an edited `crimson.cfg` selects them.

- Both lock on to the nearest creature, switching only to one at least 64
  units closer.
- The autopilot walks at its target while you're within 300 units of the
  arena centre, and heads back to the centre beyond that. With no target it
  circles the centre.
- The aimbot drags your crosshair onto the target and fires on its own once
  the crosshair is within 128 units of it.

Computer runs never rank, and the **Ranked** box is off while player 1 uses
either scheme ([ranked rules](../../rewrite/ranked-rules.md#controls-and-aim)).

## Console

Press **~** (the key left of 1) to open the console. Type a variable's name
to see its value, or the name and a value to set it. Tab completes names.
Commands in `autoexec.txt` in the game folder run at every launch.

| Variable | Default | Effect | Rewrite |
| --- | ---: | --- | --- |
| `cv_friendlyFire` | 0 | 1: your shots, and your bonus and perk bursts, hit other players for 10 HP each. A shield blocks them. | From the next run. Ranked needs 0. |
| `cv_bodiesFade` | 1 | 0: a body is gone the moment it's painted onto the ground, instead of fading out on top of it, which frees room for new creatures sooner. | Ignored: corpses always fade. |
| `cv_showFPS` | 0 | 1: frame-rate counter. | Works |
| `cv_uiTransparency` | 1 | HUD opacity, 0 to 1. | Works |
| `cv_uiSmallIndicators` | 0 | 1: compact bonus timers without names. | Works |
| `cv_aimEnhancementFade` | 0.7 | Crosshair glow opacity, 0 to 1. | Works |
| `cv_padAimDistMul` | 96 | Dual Action Pad aim reach: the aim sits 42 + stick × this units out. | Works. Ranked uses 96. |
| `cv_terrainBodiesTransparency` | 0 | Opacity of corpses on the ground: 0 gives 80%, anything else 1 ÷ value. | Works |
| `cv_enableMousePointAndClickMovement` | 0 | 1: lists Mouse point&click in Controls. | Ignored |

| Command | Effect |
| --- | --- |
| `telltimesurvived` | Prints the current run's time in whole seconds. |
| `generateterrain` | Paints a new random ground. |
| `setGammaRamp <x>` | Multiplies screen brightness by x. |
| `extendconsole` / `minimizeconsole` | Makes the console taller or shorter. |
| `cmdlist` / `vars` | Lists every command or variable. |
| `exec <file>` | Runs a file of console lines. |
| `quit` | Quits the game. |

## Dead ends

- The executable holds hints that never reach the screen: "Inside
  AlienZooKeeper" combinations such as *CyanYellowRedYellow*, "few secret
  weapons hidden inside the game", and "Brave little haxx0r aren't you?".
  They sit in startup code that never runs.
- On September 12, November 8 and December 18 the game loads a balloon
  image at startup, then never draws it.

Source notes: [easter eggs](../../re/static/secrets/easter-eggs.md),
[console](../../re/static/systems/console.md).
