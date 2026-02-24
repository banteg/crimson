# crimson-zig

Standalone Zig replay verifier workspace.

## Scope (current)

- Native CLI surface: `crimson-zig replay verify ...`
- JSON output contract: mirrors `crimson replay verify --format json`
- WASM target: `wasm32-freestanding` export ABI for Worker-style hosts

## Current backend behavior

- Native CLI currently verifies **latest-ruleset single-player survival** replays using:
  - replay msgpack+gzip decoding in Zig (header/inputs/events),
  - canonical terrain bootstrap RNG validation,
  - checkpoint sidecar (`.crd.chk`) for score/kills/rng,
  - survival highscore table (`scores5/survival.hi`) for shots/weapon stats.
- CLI hard-fails for unported paths (unsupported options, non-survival mode, non-latest ruleset, missing sidecar/highscore matches).
- WASM exports keep ABI shape but currently hard-fail verification with a `not yet ported` error.

This gives immediate CLI/ABI parity scaffolding while deeper gameplay porting proceeds.

## Build

```bash
zig build
zig build run -- replay verify survival_20260224_041009_score76661.crd --format json
zig build test
zig build wasm
```

## Smoke and Gates

```bash
./scripts/smoke_native.sh survival_20260224_041009_score76661.crd
./scripts/smoke_wasm.sh
./scripts/reference_acceptance.sh survival_20260224_041009_score76661.crd
./scripts/perf_gate.sh survival_20260224_041009_score76661.crd 5
```

`perf_gate.sh` enforces the target `>=3x` speedup vs Python for the reference
replay verification path.

## WASM exports

- `crimson_alloc(size) -> ptr`
- `crimson_free(ptr, size) -> void`
- `crimson_verify_replay_json(replay_ptr, replay_len, opts_ptr, opts_len, out_ptr, out_len) -> i32`
- `crimson_last_error_json(out_ptr, out_len) -> i32`
