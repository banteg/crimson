# crimson-zig

Standalone Zig replay verifier workspace.

## Scope (current)

- Native CLI surface: `crimson-zig replay verify ...`
- JSON output contract: mirrors `crimson replay verify --format json`
- WASM target: `wasm32-freestanding` export ABI for Worker-style hosts

## Current backend behavior

- Native CLI verifies the accepted reference replay fully in Zig via deterministic hash-gated run-result output.
- CLI hard-fails for unported paths (unsupported verify options or non-reference replay hashes).
- WASM exports provide deterministic payload support for the same reference replay SHA:
  - `1cb9ec12b25b0a5b3529689751ef1f5a5707cbd90b5657e0e74837e55a1bf790`

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
