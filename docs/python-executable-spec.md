---
tags:
  - status-scoping
---

# Python executable spec
This page defines the CLI entry points and stable command contracts for the
Python tooling in this repo. The goal is to keep automation consistent even as
internals evolve.

## Entry points

Both entry points are defined in `pyproject.toml` and resolve to the same
implementation.

| Script | Target | Purpose |
| --- | --- | --- |
| `crimson` | `crimson.cli:main` | Primary CLI for tools and analysis helpers. |
| `crimsonland` | `crimson.cli:main` | Packaged alias; same commands as `crimson`. |

## Invocation

Use `uv` for all Python execution:

```bash
uv run crimson --help
uv run crimson extract game_bins/crimsonland/1.9.93-gog artifacts/assets
```

## Command contracts

### `crimson` (default)

```
crimson [OPTIONS]
```

- Running `crimson` with no subcommand launches the game flow.
- See `crimson --help` for the full option list.

### `crimson extract`

```
crimson extract <game_dir> <assets_dir>
```

- Extracts all `.paq` archives under `game_dir` into `assets_dir`.
- Converts `.jaz` and `.tga` assets to PNG (see `docs/pipeline.md`).
- Exits with code `1` if the game directory is missing or no `.paq` files exist.

### `crimson view`

```
crimson view <name> [--width INT] [--height INT] [--fps INT] [--assets-dir PATH]
```

- Runs a Raylib view by name (debug views and mode sandboxes).
- Default `assets_dir` is `artifacts/assets`.
- Exits with code `1` if the view name is unknown.

### `crimson quests`

```
crimson quests <level> [--width INT] [--height INT] [--player-count INT] [--seed INT] [--sort] [--show-plan]
```

- Prints resolved quest spawn entries for a level like `1.1` or `2.7`.
- `--seed` controls randomized quests; omit it for non-deterministic output.
- `--sort` orders output by trigger time for easier diffing.
- `--show-plan` includes the spawn-plan allocation summary (useful for parity checks).

Output format is stable for tooling:

```
Quest 1.1 Land Hostile (4 entries)
Meta: time_limit_ms=120000; start_weapon_id=1; unlock_perk_id=none; unlock_weapon_id=0x02 (2); builder_address=0x00435bd0; terrain_ids=[0x00 (0), 0x01 (1), 0x00 (0)]
01  t=  500  id=0x26 (38)  creature=alien       count= 1  x=  512.0  y= 1088.0  heading=  0.000
```

### `crimson spawn-plan`

```
crimson spawn-plan <template> [--seed TEXT] [--x FLOAT] [--y FLOAT] [--heading FLOAT] [--terrain-w FLOAT] [--terrain-h FLOAT] [--demo-mode-active] [--hardcore] [--difficulty INT] [--json]
```

- Prints a spawn plan for a single spawn template id (e.g. `0x12`), including derived creatures/spawn slots/effects.
- Use `--json` for stable machine-readable output.

### `crimson config`

```
crimson config [--path PATH] [--base-dir PATH]
```

- Prints decoded `crimson.cfg` fields and values.

## Error handling

- CLI errors emit a human-readable message on stderr and exit with code `1`.
- Successful runs exit with code `0`.

## Implementation references

- CLI: `src/crimson/cli.py`
- Quest builders: `src/crimson/quests/`
