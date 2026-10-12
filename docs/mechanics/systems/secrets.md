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
- A correct click highlights the line, with a chime the first time.
- Clicking a line without an "o" unmarks the nearest marked line at or above
  it, with a grunt.
- Leaving the credits clears every mark.

While every "o" line is marked, a **Secret** button sits next to **Back**.
Unmark one and it goes away until you mark it again.

The first time you get there, a riddle also replaces *You can stop watching
now.* and the blank lines around it:

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

It shows once per launch: solve the puzzle again before you quit and you
get the button but not the riddle.

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

- Until your first **Reset**, the board is all red, *Game Over* flashes, and
  the tiles ignore clicks.
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

On March 3, the Statistics screen can flash *Orbes Volantes Exstare* in
faint green near the top-left corner. It's gone the instant it appears.

The game rolls once per launch, so 1 launch in 32 shows it. Each time it
shows, the game rolls again, so it can come back. The original reads the
date when it starts; the rewrite reads it each frame.

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

## Hotkeys

Fixed keys that no menu mentions and the Controls screen can't rebind.

| Key | Where | Effect | Rewrite |
| --- | --- | --- | --- |
| **F12** | Anywhere | Saves a screenshot as `shot_000.bmp`, `shot_001.bmp` and so on in the game folder, skipping names that exist. | PNG, in the folder you run it from |
| Left **Alt** + **Q** | Anywhere | Quits at once, intro included. | Works |
| **F1** | In a run, except Typ'o'Shooter | Pauses and shows your keys; F1 again resumes. | Works |
| **Space**, keypad **+** | In a run | Opens the perk picker, whatever Level Up is bound to. | Works |
| Hold **F1** | Play Game | Times played next to each mode. | Works |
| Hold **F1** | Quests | Completed and played counts next to each quest. | Works |
| **←** / **→** | Quests | Changes the tier. | Works |
| **1**–**9**, **0** | Quests | Starts that quest of the tier, if it's unlocked. | Works |
| **Space** | Quest results | Skips the tally. | Works |
| Hold **F1** | Statistics | Adds your total playtime from the Windows registry, Tutorial excluded, when its hours differ from the profile's. | Not shown |

## Custom music

At startup the game runs `music\game_tunes.txt`, and the shipped file says
you can add your own. Each `snd_addGameTune <name>.ogg` line adds
`music\<name>.ogg` to the tunes that play at random during a run. A name
missing from `music.paq` loads from the `music` folder. The rewrite does the
same.

## Later-tier ground

Survival, Rush and Typ'o'Shooter runs, and the menu background, normally
use tier 1 ground. As you clear quests, each new ground gets 1-in-8 chances
of borrowing a quest's ground instead, checked in this order:

- quest 4.2's, once you've cleared 40 quests;
- quest 3.2's, once you've cleared 30;
- quest 2.2's, once you've cleared 20.

## Console

Press **~** (the key left of 1) to open the console, even during the intro.
Type a variable's name to see its value, or the name and a value to set it.
Tab completes names. Commands in `autoexec.txt` in the game folder run at
every launch.

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
| `cv_terrainFilter` | 1 | 2: point-filtered ground, sharp texels instead of smooth. | Works |
| `cv_uiPointFilterPanels` | 0 | 1: point-filtered menu panels. | Ignored |
| `cv_enableMousePointAndClickMovement` | 0 | 1: lists Mouse point&click in Controls. | Ignored |
| `con_monoFont` | 1 | 0: the console uses the game's small font. The shipped `autoexec.txt` sets 0. | Works |
| `cv_verbose` | 0 | 1: logs saves, spawns and terrain changes to the console. | Ignored |
| `cv_silentloads` | 1 | 0: logs every file the game loads. | Ignored |

| Command | Effect | Rewrite |
| --- | --- | --- |
| `telltimesurvived` | Prints the current run's time in whole seconds. | Works |
| `generateterrain` | Paints a new random ground. | Works |
| `setGammaRamp <x>` | Multiplies screen brightness by x. | Works |
| `snd_addGameTune <x.ogg>` | Adds a tune to the in-run music ([custom music](#custom-music)). | Works |
| `openurl <url>` | Opens the address in your browser. | Works |
| `set <var> <value>` | Sets a variable, creating it if needed. | Works |
| `echo <text>` | Prints the text. `echo off` silences all console output until `echo on`. | Works |
| `clear` | Empties the console. | Works |
| `extendconsole` / `minimizeconsole` | Makes the console taller or shorter. | Works |
| `cmdlist` / `vars` | Lists every command or variable. | Works |
| `exec <file>` | Runs a file of console lines. | Works |
| `quit` | Quits the game. | Works |

`setresourcepaq`, `loadtexture` and `sndfreqadjustment` also exist. None of
them changes anything you'd see.

## Dead ends

- The executable holds hints that never reach the screen: "Inside
  AlienZooKeeper" combinations such as *CyanYellowRedYellow*, "few secret
  weapons hidden inside the game", and "Brave little haxx0r aren't you?".
  They sit in startup code that never runs.
- The credits write *Greeting to:*, *Chaos^*, *Matricks* and *Muzzy* onto one
  line, then blank it, so the greetings never show.
- On September 12, November 8 and December 18 the game loads a balloon
  image at startup, then never draws it.
- The end note after quest 5.10 is out of date. On normal it calls
  Typ'o'Shooter a reward for finishing, and on hardcore it says you've just
  unlocked the Splitter Gun. Both actually unlock after 4.10.
- Typing `reload` in Typ'o'Shooter plays the reload sound and does nothing
  else.
- If the game can't save to the registry when you quit, its console log
  says "Kameli was NOT hairy."

Source notes: [easter eggs](../../re/static/secrets/easter-eggs.md),
[console](../../re/static/systems/console.md).
