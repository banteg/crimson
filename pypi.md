# Crimsonland

A faithful reimplementation of [Crimsonland](https://en.wikipedia.org/wiki/Crimsonland) 1.9.93 (2003, GOG
"Crimsonland Classic") in Python and raylib. Survival, Rush, all five quest tiers, Tutorial, Typ-o-Shooter, local
co-op and the secrets are here, and they play like the original down to its timings, random rolls and rounding.

The original game assets are distributed with permission from 10tons, and the game downloads them on
first launch.

## Play

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```bash
uvx crimsonland@latest
```

Or install it with `uv tool install crimsonland` and run `crimson`, as in the examples below.

Python 3.13 or newer runs on Windows, macOS and Linux. On Linux the game runs natively on Wayland, but still needs
`libX11` installed.

## Better than the original

The port plays like the 2003 game, and adds what a modern release needs:

- **Runs anywhere.** Windows, macOS and Linux (Wayland included) instead of Direct3D 8 on Windows, at any resolution, with borderless fullscreen that keeps the aspect ratio.
- **Modern controllers.** PlayStation, Xbox and Switch Pro controllers are recognized on connect and switch a player to twin-stick controls, with reload on the shoulder like the 2014 remake. Every menu, list and slider works from the controller, with the focus always visible, and each co-op player can use their own controller.
- **Original bugs fixed, and kept on request.** [The original's gameplay bugs](https://crimson.banteg.xyz/rewrite/original-bugs/) are fixed by default, each traced to the decompiled code: Greater Regeneration did nothing, Bandage multiplied health instead of healing, some bonuses never dropped while you held certain weapons, and several co-op perks only worked for player 1. `--preserve-bugs` restores every one of them, exactly as the original behaves. The original's text stays as written, typos like "Fire Caugh" and "Plague Sphreader Gun" included.
- **RTX lighting.** An optional look, behind the RTX lighting box in Options: muzzle flashes, beams, plasma and explosions light the wet ground, the creatures and you, and cast soft shadows through fluid smoke. On macOS and Linux Wayland, HDR displays show highlights past white.
- **Replays.** Every run is recorded and can be played back, verified tick by tick, or rendered to 60 fps video.
- **Sharper art.** The original shipped its textures as JPEG-compressed JAZ files. The game uses the uncompressed source art from 10tons instead, free of JPEG artifacts, wherever it matches what shipped.

## Controls

Player 1 starts on the original's mouse and keyboard controls: WASD to move, the mouse to aim and fire. Everything is
rebindable in Options → Controls.

Connect a PlayStation, Xbox or Switch Pro controller, then press any button on it to switch that player to twin-stick
controls:

| Control | Action |
| --- | --- |
| Left stick | move |
| Right stick | aim |
| R2 / RT | fire |
| L1 / LB | reload |
| Triangle / Y | pick a perk |
| Start | pause |
| D-pad, Cross / A, Circle / B | menus |

In local co-op, player 2 uses the second controller, and so on. Menus work with the keyboard too: Tab and Shift+Tab
move, Enter picks, Escape goes back.

| Key | Action |
| --- | --- |
| F1 | pause and show the key help |
| F12 | save a screenshot |
| Alt+Enter | toggle fullscreen |
| Alt+Q | quit |
| ` (backtick) | console |

## Options

```bash
crimson --width 1280 --height 960   # game resolution (1024x768 is native)
crimson --fullscreen                # or --windowed; both are saved
crimson --seed 1234                 # a deterministic run
crimson --preserve-bugs             # keep the original's known bugs
crimson --build 1.9.8               # play by version 1.9.8's rules, its box in the Play Game menu ticked
crimson --rtx                       # RTX lighting for this launch
```

Saves, settings, high scores and replays go to your per-user data directory. Set `CRIMSON_RUNTIME_DIR` or pass
`--base-dir` to keep them elsewhere.

## Replays

Every run is recorded. A replay can be played back, rendered to video, or re-simulated to verify its score:

```bash
crimson replay list
crimson replay play <file>
crimson replay verify <file>
crimson replay render <file>    # needs ffmpeg
```

## Leaderboard

Tick Ranked in the Play Game menu to play Survival or a quest for [crimson.land](https://crimson.land). The server
replays every run before its score counts, and the game uploads finished runs by itself, so playing offline is fine.
There is no sign-up: the game makes a key on its first launch, and the `identity` commands manage it:

```bash
crimson identity show             # your key and the fingerprint the boards show
crimson identity export <file>    # copy your key, to play as you on another machine
crimson identity import <file>    # sign as an exported key (--replace overwrites this one)
crimson identity profile          # open your profile on crimson.land, signed in
```

## Unlock campaign progress

Close the game, then unlock all 50 normal and hardcore quests and their progression rewards:

```bash
crimson save unlock
crimson save unlock --base-dir /path/to/runtime
```

This requires an existing, valid `game.cfg`. Before changing it, the command writes an exact backup
beside it as `game.cfg.<unique-id>.bak` and prints its path. Counters, statistics and high scores stay
unchanged. An already fully unlocked save is left untouched, without another backup.
To restore progress, close the game and copy the backup over `game.cfg`.

## Custom quests

Quest authoring uses the optional `quests` extra. From a repository checkout,
`uv run crimson quest ...` includes it by default. Playing compiled-quest replays needs no extra.

Write a quest in the [quest language](https://crimson.banteg.xyz/formats/quest-dsl/), play it, and publish it with a
completed ranked run to give it a page and leaderboard on [crimson.land/custom](https://crimson.land/custom):

```bash
uvx --from 'crimsonland[quests]' crimson quest build <file>      # check a recipe and print its digest and entry budget
uvx --from 'crimsonland[quests]' crimson quest play <file>       # play it; every attempt saves a replay
uvx --from 'crimsonland[quests]' crimson quest publish <file>    # upload it with your newest clear
```

`quest play --build 1.9.8` plays the quest by version 1.9.8's rules.

[crimson.land/custom/llm.txt](https://crimson.land/custom/llm.txt) is the whole language in one file, for writing
quests with an LLM.

## Tools

```bash
crimson quests <level>          # print a stock quest's spawn script
crimson extract <game> <dst>    # extract the game's PAQ archives, with JAZ textures as PNG
```

## More

- [Changelog](https://github.com/banteg/crimson/blob/master/CHANGELOG.md)
- [How it was made](https://banteg.xyz/posts/crimsonland/): reverse engineering, asset formats and AI-assisted
  decompilation
- [Docs](https://crimson.banteg.xyz/): game mechanics, perks, weapons and file formats
- [Source](https://github.com/banteg/crimson): the port, plus a matching decompilation of the original
- [Telegram group](https://t.me/+pG-Ow90lt28zMWFi): chat, bug reports and runs

This is an independent preservation and research project. The original Crimsonland Classic assets are distributed
with permission from 10tons; the game code and the reimplementation are independent.
