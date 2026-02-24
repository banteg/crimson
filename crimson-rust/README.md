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

## Current Backend

- Replay decode/bootstrap/guards and replay tick loop are implemented in Rust.
- No Python delegation is used in `crimson-rust-core`; this is an isolated
  Rust-native verifier path intended for parity comparison against Python.
- Gameplay parity is still in progress: the current simulation models input,
  timing, replay events, and a minimal firing/reload subset while creature,
  projectile, bonus, and perk-effect runtime is being ported.
