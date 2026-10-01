# Crimsonland, rebuilt

[![1.9.93](https://decomp.dev/banteg/crimson.svg?mode=shield&measure=code&category=game&label=1.9.93)](https://decomp.dev/banteg/crimson?category=game)
[![1.9.8](https://decomp.dev/banteg/crimson/1.9.8.svg?mode=shield&measure=code&category=game&label=1.9.8)](https://decomp.dev/banteg/crimson/1.9.8?category=game)
[![1.4.0](https://decomp.dev/banteg/crimson/1.4.0.svg?mode=shield&measure=code&category=game&label=1.4.0)](https://decomp.dev/banteg/crimson/1.4.0?category=game)
[![1.3.0](https://decomp.dev/banteg/crimson/1.3.0.svg?mode=shield&measure=code&category=game&label=1.3.0)](https://decomp.dev/banteg/crimson/1.3.0?category=game)
[![1.0.2](https://decomp.dev/banteg/crimson/1.0.2.svg?mode=shield&measure=code&category=game&label=1.0.2)](https://decomp.dev/banteg/crimson/1.0.2?category=game)

[Crimsonland](https://en.wikipedia.org/wiki/Crimsonland) 1.9.93 (2003, GOG "Crimsonland Classic"), rebuilt twice:

- **A playable reimplementation** in Python and raylib that matches the original's timings, random rolls, float32 rounding, UI layout and quirks, checked tick by tick against the original code.
- **A matching decompilation**: C/C++ source that Visual C++ 6 compiles back into the original `crimsonland.exe` and `grim.dll`, instruction for instruction.

**[Read the full story](https://banteg.xyz/posts/crimsonland/)** — reverse engineering workflow, custom asset formats, AI-assisted decompilation, and game preservation philosophy.

**[Browse the docs](https://crimson.banteg.xyz/)** — 100+ pages of analysis, struct layouts, format specs, and parity tracking.

**[Read the changelog](CHANGELOG.md)** — what changed in each release, for players and under the hood.

**[Join the Telegram group](https://t.me/+pG-Ow90lt28zMWFi)** — chat about the project, report bugs, share runs.

## Current state

The rewrite is a playable full game: boot, menus, Survival, Rush, Quests (5 tiers), Tutorial, Typ-o-Shooter and local co-op, with all weapons, creatures, perks and bonuses, terrain, sprites and decals, music, sound and the secrets. Mouse and keyboard, gamepads, and fullscreen at any resolution are supported. The simulation is fully deterministic: every run is recorded as a replay that can be verified headlessly.

Python remains the fast iteration platform. The [recovered-core spike](tools/recovered_sim/README.md) is the direction for a shared game and verifier: compile the recovered C/C++ to one WASM module for desktop, web and Workers. New development on the [Zig port](docs/rewrite/zig-verifier.md) is deferred; its existing verifier remains available until the replacement passes complete replay and bot-run gates. See the [follow-up plan](tools/recovered_sim/FOLLOWUP.md) and [coverage limits](docs/rewrite/status.md).

### Decompilation

The [matching decompilation](decomp/README.md) of 1.9.93 is complete: all 858 game and engine functions (360,094 bytes of code) come from recovered source, with every reference checked. Bundled third-party libraries (D3DX8, the MSVC runtime, the image and audio codecs) keep their upstream provenance and are not counted.

The same source tree is set up to build other releases, each with its own compiler profile and `CL_BUILD` define. [decomp.dev](https://decomp.dev/banteg/crimson) tracks these builds, each from its own evidence:

| Build | Released | Edition | Progress |
| --- | --- | --- | --- |
| 1.9.93 | 2011 | GOG Crimsonland Classic, the canonical build | [complete](https://decomp.dev/banteg/crimson?category=game) |
| 1.9.8 | 2003 | shareware | [measured](https://decomp.dev/banteg/crimson/1.9.8?category=game) from the 1.9 sources |
| 1.4.0, 1.3.0, 1.0.2 | 2002 | freeware | [1.4.0](https://decomp.dev/banteg/crimson/1.4.0?category=game), [1.3.0](https://decomp.dev/banteg/crimson/1.3.0?category=game), [1.0.2](https://decomp.dev/banteg/crimson/1.0.2?category=game) |

Builds 1.9.1, 1.9.9 and 1.9.92 are pinned and mapped in [builds.json](decomp/builds.json) but not reported yet.

## Quick start

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```bash
uvx crimsonland@latest

# or run from source
gh repo clone banteg/crimson && cd crimson
uv run crimson
```

**Display:** `--width`/`--height` set the game resolution (1024x768 is native, 1024x1024 shows the whole arena) and `--fullscreen`/`--windowed` the window mode; both are saved to `crimson.cfg`. Fullscreen scales the game to fit the screen, and Alt+Enter toggles it in game.

**Wayland on Linux:** the raylib wheels run natively on Wayland, but still link `libX11`, so keep it installed.

### Runtime files

By default, saves, config, logs, and replays live in your per-user data directory. To keep everything local to the checkout:

```bash
export CRIMSON_RUNTIME_DIR="$PWD/artifacts/runtime"
uv run crimson
```

### Controllers

Connect a PlayStation, Switch Pro or Xbox controller. Controller bindings still at their original defaults move to the layout below right away. If that player's controls are all still the defaults, pressing any button on the controller switches them to twin-stick controls. Changes are saved:

| Control | Action |
| --- | --- |
| Left stick | move |
| Right stick | aim |
| R2 / RT | fire |
| L1 / LB | reload |
| Triangle / Y | pick a perk |
| Start | pause |
| D-pad, Cross / A, Circle / B | menus and the perk list |

Buttons are named by position, so on a Switch Pro controller "Cross / A" is the bottom face button. In local co-op, player 2 uses the second controller, and so on. Everything stays editable in Options → Controls. Its Reset button restores the selected player's controls: to this controller layout when their controller is connected, otherwise to mouse and keyboard. If you already changed some controls, those stay as you set them; only controls still at their original defaults are moved to the controller.

`crimson view gamepad` shows what the game reads from each connected controller, and the in-game console command `gamepads` prints the same.

## Assets

The original Crimsonland Classic assets are distributed for this project with permission from the original developer. Missing PAQ archives (`crimson.paq`, `music.paq`, `sfx.paq`) are downloaded into the runtime directory on first launch, so `uvx crimsonland@latest` works out of the box.

The project also has access to the original uncompressed source art. The current asset pack is a selective hybrid: it uses higher-quality uncompressed textures where they match the shipped runtime art, keeps the original PAQ assets where they are the better match, and stitches a few sprite sheets from both sources.

Point to them explicitly if needed:

```bash
uv run crimson --assets-dir path/to/game_dir
```

Extract PAQs into a filesystem tree for inspection. JAZ textures are automatically converted to PNG with alpha:

```bash
uv run crimson extract path/to/game_dir artifacts/assets
```

## CLI

Everything is exposed via the `crimson` CLI (alias: `crimsonland`):

```
crimson                                   run the game (default)
crimson view <name>                       debug views and sandboxes
crimson quests <level>                    print a quest's spawn script
crimson config                            inspect crimson.cfg
crimson extract <src> <dst>               extract PAQ archives
crimson spawn-plan <template>             spawn one creature template and print the pool
crimson replay list                       list replays in the runtime replays dir
crimson replay play <file>                play back a replay
crimson replay verify <file>              re-simulate a replay and check its recorded result
crimson replay info <file>                timeline of a replay's gameplay events
crimson replay render <file>              render a replay to 60 fps video with ffmpeg
crimson replay benchmark <file>           benchmark replay throughput, with optional profiling
crimson replay verify-checkpoints <file>  compare a replay against its checkpoint sidecar
crimson replay diff-checkpoints <a> <b>   find where two checkpoint sidecars diverge
```

Useful flags: `--seed N` (deterministic runs), `--preserve-bugs` (native quirks for parity work), `--no-intro` (skip logos), `--base-dir PATH` / `CRIMSON_RUNTIME_DIR` (runtime file location), `--assets-dir PATH` (PAQ / extracted asset location).

## Project layout

```
src/
  crimson/          game logic — modes, weapons, perks, creatures, UI, replay
  grim/             engine layer — raylib wrapper, PAQ/JAZ decoders, audio, fonts
crimson-zig/        Zig port (frozen): replay verifier, desktop runtime, WASM
crimson-re/         reverse-engineering tools (decomp matching, native link, replay traces);
                    not shipped with the game, adds `crimson match|native|dbg` in the dev environment
analysis/
  ghidra/           name/type maps (source of truth) and structured snapshots
  binary_ninja/     preferred live analysis databases
  ida/              structured function/import/string snapshots
  frida/            runtime trace summaries from past Frida sessions
docs/               100+ pages: formats, structs, algorithms, parity tracking
scripts/            analysis and utility tools
tests/              gameplay, perks, physics, replay, and parity regression tests
```

## Reverse engineering

**Static analysis** is the source of truth. Names and types live in
[`analysis/ghidra/maps/`](analysis/ghidra/maps/); consult current function views
in Binary Ninja, IDA, then Ghidra using the shared address-keyed workflow in
[`analysis/README.md`](analysis/README.md).

**Differential testing** is the runtime ground truth: it runs original functions under a Unicorn [native execution oracle](docs/verification/differential-testing/native-oracle.md) and checks port code against them bit for bit. Recorded traces compare canonical input, state, entity, timing and RNG channels between runs; compact checkpoints help localize differences, and complete session digests cover same-build port regressions.

See [docs/contributor/project-tracking/provenance.md](docs/contributor/project-tracking/provenance.md) for exact binary hashes of the target build.

## Development

```bash
uv run pytest              # test suite
uv run ruff check .        # lint
uv run ty check src tests  # type check
ast-grep scan              # ast-grep code scan
ast-grep test              # ast-grep rule tests
just check                 # all of the above
```

### Docs

Docs are authored in `docs/` and built as a static site with [zensical](https://github.com/banteg/zensical):

```bash
uv tool install zensical
zensical serve
```

## Parity workflow

1. Recover structure and intent from static analysis (`analysis/ghidra/maps/` as source-of-truth maps).
2. Validate ambiguous behavior against the original code under the native execution oracle.
3. Port behavior into `src/` with deterministic simulation contracts.
4. Verify against recorded replays and their per-tick checkpoints with headless tools.

For deterministic gameplay code, float behavior is part of the contract.  
See [`docs/rewrite/float-parity-policy.md`](docs/rewrite/float-parity-policy.md).

## Contributing

- Keep changes small and reviewable — one subsystem at a time.
- Prefer *measured parity* (captures, logs, deterministic tests) over "looks right".
- Preserve native float32 math behavior in deterministic simulation paths. See [float parity policy](docs/rewrite/float-parity-policy.md).
- Run `just check` before committing.

## Tech stack

Python 3.13+ · raylib (pyray) · Construct · msgspec · Typer · Ghidra · Binary Ninja · Unicorn · pytest · uv

## Legal

This project is an independent reverse engineering and reimplementation effort for preservation, research, and compatibility. Original Crimsonland Classic assets are distributed with permission from the original developer; the game code and reimplementation remain independent.
