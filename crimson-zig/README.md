# crimson-zig

Standalone Zig replay verifier workspace.

## Scope (current)

- Native CLI surface: `crimson-zig replay verify ...`
- JSON output contract: mirrors `crimson replay verify --format json`
- WASM target: `wasm32-freestanding` export ABI for Worker-style hosts

## Current backend behavior

- Native CLI currently verifies **latest-ruleset single-player survival** replays using:
  - replay msgpack+gzip decoding in Zig (via `msgpack.zig`, full header/inputs/events model),
  - Survival tick-loop scaffold pass in Zig (canonical event ordering + input/event counters),
  - canonical terrain bootstrap RNG validation,
  - hard-fail once full deterministic run-result generation is required.
- Native verifier now intentionally **does not** read replay sidecars (`.crd.chk`) or highscores (`scores5/survival.hi`); replay-only inputs are the source of truth.
- CLI hard-fails for unported paths (unsupported options, non-survival mode, non-latest ruleset, incomplete full simulation).
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
