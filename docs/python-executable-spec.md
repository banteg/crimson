# Python executable spec

**Status:** Draft

This page defines the CLI entry points and stable command contracts for the
Python tooling in this repo. The goal is to keep automation consistent even as
internals evolve.

## Entry points

Both entry points are defined in `pyproject.toml` and resolve to the same
implementation.

| Script | Target | Purpose |
| --- | --- | --- |
| `crimson` | `crimson.cli:main` | Primary CLI for tools and analysis helpers. |
| `paq` | `crimson.cli:main` | Legacy alias for extraction workflows. |

## Invocation

Use `uv` for all Python execution:

```bash
uv run crimson --help
uv run paq extract game_bins/crimsonland/1.9.93-gog artifacts/assets
```

## Command contracts

### `crimson extract`

```
crimson extract <game_dir> <assets_dir>
```

- Extracts all `.paq` archives under `game_dir` into `assets_dir`.
- Converts `.jaz` and `.tga` assets to PNG (see `docs/pipeline.md`).
- Exits with code `1` if the game directory is missing or no `.paq` files exist.

### `crimson font`

```
crimson font [--assets-dir PATH] [--out-path PATH] [--text TEXT] [--text-file PATH] [--scale FLOAT]
```

- Renders a sample image using the small font.
- Default `assets_dir` is `artifacts/assets`.
- Uses `--text` or `--text-file` (mutually exclusive) and falls back to the
  built-in sample if neither is supplied.

### `crimson quests`

```
crimson quests <level> [--width INT] [--height INT] [--player-count INT] [--seed INT] [--sort]
```

- Prints resolved quest spawn entries for a level like `1.1` or `2.7`.
- `--seed` controls randomized quests; omit it for non-deterministic output.
- `--sort` orders output by trigger time for easier diffing.

Output format is stable for tooling:

```
Quest 1.1 Land Hostile (4 entries)
01  t=  500  id=0x26 (38)  count= 1  x=  512.0  y= 1088.0  heading=  0.000
```

## Error handling

- CLI errors emit a human-readable message on stderr and exit with code `1`.
- Successful runs exit with code `0`.

## Implementation references

- CLI: `src/crimson/cli.py`
- Quest builders: `src/crimson/quests/`
