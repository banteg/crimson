---
tags:
  - contributor
  - setup
---

# Setup

## Environment

- Python 3.13+ with [uv](https://docs.astral.sh/uv/)
- `just` task runner, ast-grep (`sg`), and the Zig toolchain required by `crimson-zig/`

## First run

```bash
uv sync --group dev
just check
just docs-build
```

## Useful commands

- `just check` — Python lint/import/type checks, docs and native-recovery checks, ast-grep scan/tests, pytest, and Zig tests/native/WASM builds
- `just docs-build` — build docs site

## Run and inspect

`crimson` and `crimsonland` both resolve to `crimson.cli:main`. With no subcommand
they launch the Python game. Use command help as the authority for options and
error behavior; subcommands have different validation and mismatch exit codes.

```bash
uv run crimson
uv run crimson --help
uv run crimson replay --help
uv run crimson view --help
uv run crimson quests 1.1 --seed 1
uv run crimson config
```

For native builds see [Zig port](../rewrite/zig-verifier.md); for archive extraction
see [extraction pipeline](../formats/pipeline.md). Tests requiring original assets
or a display may skip when those prerequisites are unavailable.
