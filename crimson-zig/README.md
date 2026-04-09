# crimson-zig

Standalone Zig workspace for the native Crimson port.

## Scope (current)

- Direction: full native port of Crimson runtime and supporting codecs/tooling.
- Current primary shipped CLI surface: `crimson-zig replay verify ...`
- Current JSON output contract: mirrors `crimson replay verify --format json`
- Current WASM target: `wasm32-freestanding` export ABI for Worker-style hosts

## Format codecs (library-only)

The `crimson_zig.formats` module now includes deterministic byte-level codecs for:

- `formats.paq`: PAQ archive decode/encode (`paq\\0`, sequential entries).
- `formats.jaz`: JAZ parse + zlib inflate + payload split (`jpeg_bytes` + `alpha_rle_bytes`).
- `formats.crimson_cfg`: fixed-size `crimson.cfg` decode/encode (`0x480` bytes).
- `formats.game_cfg`: `game.cfg` blob/file encode/decode, checksum, and status-struct parse/build.

This wave is intentionally codec-only:

- no new CLI commands yet,
- no `ensure_*`/repair helpers,
- no JPEG-to-RGBA expansion yet (JAZ returns split payload components).

## Current native state

- `crimson-zig` is no longer verifier-only in project direction.
  - Replay verification is the most complete user-facing entrypoint today.
  - Runtime, codecs, and window/bootstrap targets are being ported as pieces of a full native implementation.
- Native CLI currently verifies **1-4 player survival/rush/quest** replays, including preserve-bugs compatibility mode, using:
  - replay msgpack+gzip decoding in Zig (via `msgpack.zig`, full header/inputs/events model),
  - native deterministic simulation pass in Zig (canonical event ordering + input/event counters),
  - canonical terrain bootstrap RNG validation,
  - full deterministic run-result generation on supported native paths.
- Native verifier now intentionally **does not** read replay sidecars (`.crd.chk`) or highscores (`scores5/survival.hi`); replay-only inputs are the source of truth.
- CLI still hard-fails for unsupported or unported native paths instead of falling back.
- WASM exports keep ABI shape but currently hard-fail verification with a `not yet ported` error.

The verifier remains a useful parity harness, but it is now a consumer of the broader Zig port rather than the whole point of the workspace.

## Build

```bash
zig build
zig build run -- replay verify survival_20260224_041009_score76661.crd --format json
zig build run-window
zig build web-window
zig build test
zig build wasm
```

## Raylib bootstrap

- `zig build run-window` opens an empty placeholder window using `raylib-zig`.
- `zig build window` compiles that target without running it.
- `zig build web-window` builds an HTML+WASM placeholder window for browser use.
- `zig build run-web-window` serves the web build through `emrun` (`--no_browser`).
- This keeps the existing CLI entrypoint (`zig build run -- ...`) unchanged while
  we incrementally move rendering/runtime work into Zig.
- `zig build wasm` remains the verifier ABI module (`wasm32-freestanding`) and is
  intentionally separate from the raylib web target (`wasm32-emscripten`).

## WASM exports

- `crimson_alloc(size) -> ptr`
- `crimson_free(ptr, size) -> void`
- `crimson_verify_replay_json(replay_ptr, replay_len, opts_ptr, opts_len, out_ptr, out_len) -> i32`
- `crimson_last_error_json(out_ptr, out_len) -> i32`
