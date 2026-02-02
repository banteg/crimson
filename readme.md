# Crimsonland 1.9.93 decompilation + rewrite

This repository is a **reverse engineering + high‑fidelity reimplementation** of **Crimsonland 1.9.93 (2003)**.

- **Target build:** `v1.9.93` (GOG "Crimsonland Classic") — see [docs/provenance.md](docs/provenance.md) for exact hashes.
- **Rewrite:** a runnable reference implementation in **Python + raylib** under `src/`.
- **Analysis:** decompiles, name/type maps, and runtime evidence under `analysis/`.
- **Docs:** long-form notes and parity tracking under `docs/` (start at [docs/index.md](docs/index.md)).

The north star is **behavioral parity** with the original Windows build: timings, RNG, UI/layout quirks, asset decoding, and gameplay rules should match as closely as practical.

**[Read the full story](https://banteg.xyz/posts/crimsonland/)** of how this project came together: reverse engineering workflow, custom asset formats, AI-assisted decompilation, and game preservation philosophy.

---

## Quick start

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager.

### Run the latest packaged build

If you just want to play the rewrite:

```bash
uvx crimsonland@latest
```

### Run from a checkout

```bash
gh repo clone banteg/crimson
cd crimson
uv run crimson
```

### Keep runtime files local to the repo

By default, runtime files (e.g. `crimson.cfg`, `game.cfg`, highscores, logs, downloaded PAQs) live in your per-user data dir.
To keep everything under this checkout:

```bash
export CRIMSON_RUNTIME_DIR="$PWD/artifacts/runtime"
mkdir -p artifacts/runtime
uv run crimson
```

---

## Assets + binaries

There are two separate “inputs” to this repo:

1. **Runtime assets for the rewrite** (PAQ archives)
2. **Original Windows binaries for reverse engineering** (`crimsonland.exe`, `grim.dll`, …)

We keep them out of git and expect a local layout like:

```text
game_bins/
  crimsonland/
    1.9.93-gog/
      crimsonland.exe
      grim.dll
      crimson.paq
      music.paq
      sfx.paq
artifacts/
  runtime/        # optional: where you run the rewrite (cfg/status/paqs)
  assets/         # optional: extracted PAQs for inspection/tools
```

### Running the rewrite

The rewrite loads the assets from original archives:

- `crimson.paq`
- `music.paq`
- `sfx.paq`

### Extracted assets

For inspection/diffs/tools, you can extract PAQs into a filesystem tree:

```bash
uv run crimson extract crimsonland_1.9.93 artifacts/assets
```

Same as the original, many loaders can work from either:

- **PAQ-backed assets** (preferred when available), or
- the **extracted filesystem layout** under `artifacts/assets/`.

---

## CLI cheat sheet

Everything is exposed via the `crimson` CLI (alias: `crimsonland`):

```bash
uv run crimson               # run the game (default command)
uv run crimson view ui       # debug views / sandboxes
uv run crimson quests 1.1    # print quest spawn script
uv run crimson config        # inspect crimson.cfg
uv run crimson extract <game_dir> artifacts/assets
```

Useful flags:

- `--base-dir PATH` / `CRIMSON_RUNTIME_DIR=...` — where saves/config/logs live
- `--assets-dir PATH` — where `.paq` archives (or extracted assets) are loaded from
- `--seed N` — deterministic runs for parity testing
- `--demo` — enable shareware/demo paths
- `--no-intro` — skip logos/intro music

---

## Docs

Docs are authored in `docs/` and built as a static site at https://crimson.banteg.xyz/

For development, it's useful to have a live local build:

```
uv tool install zensical
zensical serve
```

---

## Development

### Tests

```bash
uv run pytest
```

### Lint / checks

```bash
uv run lint-imports
uv run python scripts/check_asset_loader_usage.py
```

### `justfile` shortcuts

If you have `just` installed:

```bash
just --list
just test
just docs-build
just ghidra-exe
just ghidra-grim
```

---

## Reverse engineering workflow

High level:

- **Static analysis is the source of truth.**
  - Update names/types in [analysis/ghidra/maps/](analysis/ghidra/maps/).
  - Treat [analysis/ghidra/raw/](analysis/ghidra/raw/) as generated output (regenerate; do not hand-edit).
- **Runtime tooling** (Frida / WinDbg) validates ambiguous behavior and captures ground truth.
  - Evidence summaries live under [analysis/frida/](analysis/frida/).

---

## Contributing notes

- Keep changes small and reviewable (one subsystem/feature at a time).
- Prefer *measured parity* (captures/logs/deterministic tests) over “looks right”.
- When porting float constants from decompilation, prefer the intended value
  (e.g. `0.6` instead of `0.6000000238418579` when it’s clearly a float32 artifact).

---

## Legal

This project is an independent reverse engineering and reimplementation effort for preservation, research, and compatibility.

No original assets or binaries are included. Use your own legally obtained copy.
