# crimson-rust

Phase-1 Rust replay verifier workspace.

## Crates

- `crimson-rust-core`: replay decode/bootstrap/verify API.
- `crimson-rust`: native CLI binary.
- `crimson-rust-wasm`: wasm wrapper over the same core verifier API.

## CLI

```bash
cargo run --manifest-path crimson-rust/Cargo.toml -p crimson-rust -- \
  verify <replay.crd> --format json
```

Options:

- `--submitted-score N`
- `--score-metric auto|score_xp|elapsed_ms`
- `--base-dir PATH` (also accepts `--runtime-dir`)

Exit code `3` is used for score-claim mismatch.

## Current Phase-1 Scope

- Survival only (`game_mode_id=1`)
- Single player only (`player_count=1`)
- `preserve_bugs=false` only
- Locked to the acceptance replay hash:
  `1cb9ec12b25b0a5b3529689751ef1f5a5707cbd90b5657e0e74837e55a1bf790`
