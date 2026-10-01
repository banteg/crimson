# Crimsonland, rebuilt

[![1.9.93](https://decomp.dev/banteg/crimson.svg?mode=shield&measure=code&category=game&label=1.9.93)](https://decomp.dev/banteg/crimson?category=game)
[![1.9.8](https://decomp.dev/banteg/crimson/1.9.8.svg?mode=shield&measure=code&category=game&label=1.9.8)](https://decomp.dev/banteg/crimson/1.9.8?category=game)
[![1.4.0](https://decomp.dev/banteg/crimson/1.4.0.svg?mode=shield&measure=code&category=game&label=1.4.0)](https://decomp.dev/banteg/crimson/1.4.0?category=game)
[![1.3.0](https://decomp.dev/banteg/crimson/1.3.0.svg?mode=shield&measure=code&category=game&label=1.3.0)](https://decomp.dev/banteg/crimson/1.3.0?category=game)
[![1.0.2](https://decomp.dev/banteg/crimson/1.0.2.svg?mode=shield&measure=code&category=game&label=1.0.2)](https://decomp.dev/banteg/crimson/1.0.2?category=game)

[Crimsonland](https://en.wikipedia.org/wiki/Crimsonland) 1.9.93 (2003, GOG "Crimsonland Classic"), rebuilt twice:

- **A playable reimplementation** in Python and raylib that matches the original's timings, random rolls, float32 rounding, UI layout and quirks, checked tick by tick against the original code.
- **A matching decompilation**: C/C++ source that Visual C++ 6 compiles back into the original `crimsonland.exe` and `grim.dll`, instruction for instruction.

[The full story](https://banteg.xyz/posts/crimsonland/) · [Docs](https://crimson.banteg.xyz/) · [Changelog](CHANGELOG.md) · [Telegram group](https://t.me/+pG-Ow90lt28zMWFi)

## Play

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```bash
uvx crimsonland@latest

# or run from source
gh repo clone banteg/crimson && cd crimson
uv run crimson
```

The original Crimsonland Classic assets are distributed with permission from the original developer, and the game downloads them into its runtime directory on first launch. Saves, config, high scores and replays live in your per-user data directory; set `CRIMSON_RUNTIME_DIR` or pass `--base-dir` to keep them elsewhere.

`--width`/`--height` set the game resolution (1024x768 is native, 1024x1024 shows the whole arena) and `--fullscreen`/`--windowed` the window mode; both are saved. Fullscreen scales the game to fit the screen, and Alt+Enter toggles it. On Linux the game runs natively on Wayland but still links `libX11`.

### Controllers

Connect a PlayStation, Switch Pro or Xbox controller and press any button on it: a player still on the default controls switches to twin-stick controls. Controls you customized stay as you set them.

| Control | Action |
| --- | --- |
| Left stick | move |
| Right stick | aim |
| R2 / RT | fire |
| L1 / LB | reload |
| Triangle / Y | pick a perk |
| Start | pause |
| D-pad, Cross / A, Circle / B | menus and the perk list |

Buttons are named by position, so on a Switch Pro controller "Cross / A" is the bottom face button. In local co-op, player 2 uses the second controller, and so on. Options → Controls edits everything; its Reset button restores the controller layout, or mouse and keyboard when no controller is connected. `crimson view gamepad` shows what the game reads from each controller.

### Replays and tools

Every run is recorded. The `crimson` CLI (alias `crimsonland`) plays them back and checks them:

```
crimson replay list                       list your replays
crimson replay play <file>                play back a replay
crimson replay verify <file>              re-simulate a replay and check its recorded result
crimson replay render <file>              render a replay to 60 fps video with ffmpeg
crimson extract <src> <dst>               extract PAQ archives, with JAZ textures as PNG
crimson quests <level>                    print a quest's spawn script
```

`--seed N` starts a deterministic run, and `--preserve-bugs` keeps the original's known bugs.

## Better than the original

The port plays like the 2003 game, and adds what a modern release needs:

- **Runs anywhere.** Windows, macOS and Linux (Wayland included) instead of Direct3D 8 on Windows, at any resolution, with borderless fullscreen that keeps the aspect ratio.
- **Modern controllers.** PlayStation, Xbox and Switch Pro controllers are recognized on connect and switch a player to twin-stick controls, with reload on the shoulder like the 2014 remake. Every menu, list and slider works from the controller, with the focus always visible, and each co-op player can use their own controller.
- **Original bugs fixed, and kept on request.** [27 gameplay bugs](https://crimson.banteg.xyz/rewrite/original-bugs/) are fixed by default, each traced to the decompiled code: Greater Regeneration did nothing, Bandage multiplied health instead of healing, some bonuses never dropped while you held certain weapons, and several co-op perks only worked for player 1. `--preserve-bugs` restores every one of them, exactly as the original behaves. The original's text stays as written, typos like "Fire Caugh" and "Plague Sphreader Gun" included.
- **Replays.** Every run is recorded and can be played back, verified tick by tick, or rendered to 60 fps video.
- **Sharper art.** Textures come from the original uncompressed source art wherever it matches what shipped.

## Status

The rewrite is the full game: Survival, Rush, Quests (5 tiers), Tutorial, Typ-o-Shooter and local co-op, with every weapon, creature, perk and bonus, the music, sound and secrets. The simulation is deterministic, so every recorded run can be verified headlessly.

The [Crimson core](crimson-core/README.md) is the direction for a shared game and verifier: the recovered C/C++ compiled to one WASM module for desktop, web and Workers. The [Zig port](docs/rewrite/zig-verifier.md) is frozen; its verifier stays until the replacement passes complete replay and bot-run gates.

## Decompilation

The [matching decompilation](decomp/README.md) of 1.9.93 is complete: all 858 game and engine functions (360,094 bytes of code) come from recovered source, with every reference checked. Bundled third-party libraries (D3DX8, the MSVC runtime, the image and audio codecs) keep their upstream provenance and are not counted.

The same source tree is set up to build other releases, each with its own compiler profile and `CL_BUILD` define. [decomp.dev](https://decomp.dev/banteg/crimson) tracks these builds, each from its own evidence:

| Build | Released | Edition | Progress |
| --- | --- | --- | --- |
| 1.9.93 | 2011 | GOG Crimsonland Classic, the canonical build | [complete](https://decomp.dev/banteg/crimson?category=game) |
| 1.9.8 | 2003 | shareware | [measured](https://decomp.dev/banteg/crimson/1.9.8?category=game) from the 1.9 sources |
| 1.4.0, 1.3.0, 1.0.2 | 2002 | freeware | [1.4.0](https://decomp.dev/banteg/crimson/1.4.0?category=game), [1.3.0](https://decomp.dev/banteg/crimson/1.3.0?category=game), [1.0.2](https://decomp.dev/banteg/crimson/1.0.2?category=game) |

Builds 1.9.1, 1.9.9 and 1.9.92 are pinned and mapped in [builds.json](decomp/builds.json) but not reported yet.

## Developing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the project layout, the reverse-engineering and parity workflow, and the checks to run.

## Legal

This project is an independent reverse engineering and reimplementation effort for preservation, research, and compatibility. Original Crimsonland Classic assets are distributed with permission from the original developer; the game code and reimplementation remain independent.
