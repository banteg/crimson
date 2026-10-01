# Crimsonland

A faithful reimplementation of [Crimsonland](https://en.wikipedia.org/wiki/Crimsonland) 1.9.93 (2003, GOG
"Crimsonland Classic") in Python and raylib. Survival, Rush, all five quest tiers, Tutorial, Typ-o-Shooter, local
co-op and the secrets are here, and they play like the original down to its timings, random rolls and rounding.

The original game assets are distributed with permission from the original developer, and the game downloads them on
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
- **Original bugs fixed, and kept on request.** [27 gameplay bugs](https://crimson.banteg.xyz/rewrite/original-bugs/) are fixed by default, each traced to the decompiled code: Greater Regeneration did nothing, Bandage multiplied health instead of healing, some bonuses never dropped while you held certain weapons, and several co-op perks only worked for player 1. `--preserve-bugs` restores every one of them, exactly as the original behaves. The original's text stays as written, typos like "Fire Caugh" and "Plague Sphreader Gun" included.
- **Replays.** Every run is recorded and can be played back, verified tick by tick, or rendered to 60 fps video.
- **Sharper art.** Textures come from the original uncompressed source art wherever it matches what shipped.

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

## More

- [Changelog](https://github.com/banteg/crimson/blob/master/CHANGELOG.md)
- [How it was made](https://banteg.xyz/posts/crimsonland/): reverse engineering, asset formats and AI-assisted
  decompilation
- [Docs](https://crimson.banteg.xyz/): game mechanics, perks, weapons and file formats
- [Source](https://github.com/banteg/crimson): the port, plus a matching decompilation of the original
- [Telegram group](https://t.me/+pG-Ow90lt28zMWFi): chat, bug reports and runs

This is an independent preservation and research project. The original Crimsonland Classic assets are distributed
with permission from the original developer; the game code and the reimplementation are independent.
