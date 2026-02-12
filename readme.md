# Crimsonland 1.9.93 — reverse engineering + rewrite

A high-fidelity reimplementation of [Crimsonland](https://en.wikipedia.org/wiki/Crimsonland) v1.9.93 (2003, GOG "Crimsonland Classic") in Python + raylib, paired with deep reverse engineering of the original Windows binary.

The aim of the project is **behavioral parity**: timings, RNG sequences, float32 math, UI layout quirks, asset decoding, and gameplay rules should match the original as closely as practical.

We go great lengths to achieve this goal, including a headless differential testing harness to verify runs recorded in the original game versus our reimplementation.

**[Read the full story](https://banteg.xyz/posts/crimsonland/)** — reverse engineering workflow, custom asset formats, AI-assisted decompilation, and game preservation philosophy.

**[Browse the docs](https://crimson.banteg.xyz/)** — 100+ pages of analysis, struct layouts, format specs, and parity tracking.

## Current state

The rewrite is a playable full game: boot, menus, Survival, Rush, Quests (5 tiers), Tutorial, and Typ-o-Shooter, with full weapon/creature/perk content, terrain/sprite/decal rendering, music, gameplay SFX, and even secrets. The simulation is fully deterministic, supporting seeded runs and headless verifiable replays.

## Quick start

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```bash
uvx crimsonland@latest

# or run from source
gh repo clone banteg/crimson && cd crimson
uv run crimson
```

**Wayland on Linux:** current PyPI raylib wheels are X11-oriented on x86_64, so you may need `xwayland` + `libX11`. See [electronstudio/raylib-python-cffi#199](https://github.com/electronstudio/raylib-python-cffi/pull/199).

### Runtime files

By default, saves, config, logs, and replays live in your per-user data directory. To keep everything local to the checkout:

```bash
export CRIMSON_RUNTIME_DIR="$PWD/artifacts/runtime"
uv run crimson
```

## Assets

The rewrite can load the assets from original PAQ archives (`crimson.paq` et al). No original assets or binaries are included in this repository.

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
crimson                           run the game (default)
crimson view <name>               debug views / sandboxes
crimson quests <level>            print quest spawn script
crimson config                    inspect crimson.cfg
crimson extract <src> <dst>       extract PAQ archives
crimson replay play <file>        play back a recorded demo
crimson replay verify <file>      headlessly verify score from a replay
crimson oracle [--seed N]         headless simulation for differential testing
```

Useful flags: `--seed N` (deterministic runs), `--demo` (shareware teaser), `--no-intro` (skip logos), `--base-dir PATH` / `CRIMSON_RUNTIME_DIR` (runtime file location), `--assets-dir PATH` (PAQ / extracted asset location).

## Project layout

```
src/
  crimson/          game logic — modes, weapons, perks, creatures, UI, replay
  grim/             engine layer — raylib wrapper, PAQ/JAZ decoders, audio, fonts
analysis/
  ghidra/           name/type maps (source of truth) and raw decompile exports
  frida/            runtime capture evidence (state snapshots, RNG traces)
  windbg/           debugger session logs
docs/               100+ pages: formats, structs, algorithms, parity tracking
scripts/            40+ analysis and utility tools
tests/              200+ tests: gameplay, perks, physics, replay, parity
```

## Reverse engineering

**Static analysis** is the source of truth. Names and types live in [`analysis/ghidra/maps/`](analysis/ghidra/maps/); raw decompiles in [`analysis/ghidra/raw/`](analysis/ghidra/raw/) are regenerated output.

**Runtime tooling** (Frida, WinDbg) validates ambiguous behavior and captures ground truth. Evidence summaries live under [`analysis/frida/`](analysis/frida/).

**Differential testing** captures original execution via Frida, replays the same inputs through the rewrite's headless oracle, and compares state checkpoints field-by-field.

See [docs/contributor/project-tracking/provenance.md](docs/contributor/project-tracking/provenance.md) for exact binary hashes of the target build.

## Development

```bash
uv run pytest              # test suite
uv run ruff check .        # lint
uv run ty check src        # type check
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
2. Validate ambiguous behavior with runtime evidence (Frida/WinDbg captures under `analysis/frida/`).
3. Port behavior into `src/` with deterministic simulation contracts.
4. Verify against captures/replays with headless differential tools.

For deterministic gameplay code, float behavior is part of the contract.  
See [`docs/rewrite/float-parity-policy.md`](docs/rewrite/float-parity-policy.md).

## Contributing

- Keep changes small and reviewable — one subsystem at a time.
- Prefer *measured parity* (captures, logs, deterministic tests) over "looks right".
- Preserve native float32 math behavior in deterministic simulation paths. See [float parity policy](docs/rewrite/float-parity-policy.md).
- Run `just check` before committing.

## Tech stack

Python 3.13+ · raylib (pyray) · Construct · msgspec · Typer · Ghidra · Frida · WinDbg · pytest · uv

## Legal

This project is an independent reverse engineering and reimplementation effort for preservation, research, and compatibility. No original assets or binaries are included. Use your own legally obtained copy.
