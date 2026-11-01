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
- for `crimson-core/`: clang++ (native verifier), [wasi-sdk](https://github.com/WebAssembly/wasi-sdk)
  (the version `scripts/build_identity.py` pins, at `WASI_SDK_PATH`, the main checkout's `artifacts/wasi-sdk`
  (shared by its worktrees) or `/opt/wasi-sdk`; it compiles the
  WASM targets), Ninja (the `build` dependency group, which the dev group includes) and Node.js
- for the browser and desktop clients: wabt's `wasm2c`, SDL3, libcurl, and Emscripten for the
  browser build; see the [port notes](https://github.com/banteg/crimson/blob/master/crimson-core/PORT.md)

## First run

```bash
uv sync --group dev
just setup-test-data
just check
just docs-build
```

The setup command installs the same hash-verified artwork and original binaries as CI. Rerunning it reuses files that already match. For the browser end-to-end checks, `uv run python scripts/setup_test_data.py --only packs` also fetches the music and sound archives.

## Useful commands

- `just run [game directory]` — build and launch the native desktop client
- `just build [--package]` — build the native client, optionally packaging it for distribution
- `just check` — Python lint/type checks, docs and native-recovery checks, ast-grep scan/tests and pytest
- `just docs-build` — build docs site

## Run and inspect

`crimson` and `crimsonland` both resolve to `crimson.cli:main`. With no subcommand
they launch the Python game. On first launch it downloads `crimson.paq`, `sfx.paq`
and `music.paq` from the project's asset host into its data folder
(`CRIMSON_RUNTIME_DIR`, else the platform's per-user data directory); the desktop
client shares that folder. Use command help as the authority for options and
error behavior; subcommands have different validation and mismatch exit codes.

All three clients verify every distributed pack against the SHA-256 pins in
`src/crimson/assets_version.json`. On the next launch, a damaged archive is
backed up and downloaded again. Valid custom packs keep their contents and names.
Only the identified earlier music pack is migrated.

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
