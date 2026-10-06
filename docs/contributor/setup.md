---
tags:
  - contributor
  - setup
---

# Setup

## Environment

- Python 3.13+ with [uv](https://docs.astral.sh/uv/)
- `just` task runner and ast-grep
- for `crimson-core/`: clang++, Zig 0.17.0 (builds its math helper) and Node.js

## First run

```bash
uv sync --group dev
just check
just docs-build
```

## Useful commands

- `just check` — Python lint/type checks, docs and native-recovery checks, ast-grep scan/tests and pytest
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

For native and WASM builds of the recovered core see
[`crimson-core/README.md`](https://github.com/banteg/crimson/blob/master/crimson-core/README.md); for archive extraction
see [extraction pipeline](../formats/pipeline.md). Tests requiring original assets
or a display may skip when those prerequisites are unavailable.
