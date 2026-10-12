---
tags:
  - contributor
  - setup
---

# Setup

## Environment

- Python 3.13+ with [uv](https://docs.astral.sh/uv/)
- `just` task runner, ast-grep, and [prek](https://github.com/j178/prek) for the git hooks
  (`prek install -c prek.toml -t pre-commit -t pre-push`)
- for `crimson-core/`: clang++ (native verifier), Zig (the version `scripts/build_identity.py` pins;
  it builds the shared math helper and compiles the WASM targets) and Node.js
- for the browser and desktop clients: wabt's `wasm2c`, SDL3, libcurl, and Emscripten for the
  browser build; see the [port notes](https://github.com/banteg/crimson/blob/master/crimson-core/PORT.md)

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
they launch the Python game. On first launch it downloads `crimson.paq`, `sfx.paq`
and `music.paq` from the project's asset host into its data folder
(`CRIMSON_RUNTIME_DIR`, else the platform's per-user data directory); the desktop
client shares that folder. Use command help as the authority for options and
error behavior; subcommands have different validation and mismatch exit codes.

Python, desktop and browser launches also upgrade recognized earlier Frankenasset
packs by SHA-256. They verify the new pack before replacing the old file; original
release and custom packs are preserved. Artwork versions are recorded in
`src/crimson/assets_version.json`.

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
