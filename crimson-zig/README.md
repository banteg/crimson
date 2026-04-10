# crimson-zig

Standalone Zig workspace for the native Crimson port.

## Scope (current)

- Direction: full native port of Crimson runtime and supporting codecs/tooling.
- Current most mature CLI surfaces: `crimson-zig replay verify ...` and `crimson-zig replay info ...`
- Current JSON contracts mirror the Python replay CLI for verify/info payloads.
- Current native targets include headless replay tooling, runtime modules, codec libraries,
  a raylib bootstrap window target, and a freestanding WASM ABI target.
- Shared runtime/session seams now live under `src/runtime/session.zig` and
  `src/runtime/session_builders.zig`, so replay tooling sits on top of the same
  deterministic session shell we intend to use for broader native surfaces.

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

- `crimson-zig` is the native-port workspace, not a replay-verifier workspace.
  - Replay verification/info are the most complete user-facing entrypoints today.
  - Runtime, codecs, startup/bootstrap, and window targets are being ported as parts of one native implementation.
- Replay session construction now routes through the shared deterministic session
  layer (`runtime/session*.zig`) rather than keeping the mutable loop shell under
  `runtime/replay/`.
- Native CLI currently executes **1-4 player survival/rush/quest** replay paths, including preserve-bugs compatibility mode, using:
  - replay msgpack+gzip decoding in Zig (via `msgpack.zig`, full header/inputs/events model),
  - native deterministic simulation pass in Zig (canonical event ordering + input/event counters),
  - canonical terrain bootstrap RNG validation,
  - full deterministic run-result generation on supported native paths.
- Replay-side validation remains a primary parity harness, but it is now a consumer of shared runtime code rather than the whole point of the workspace.
- Native CLI still hard-fails for unsupported or unported native paths instead of falling back.
- WASM exports keep ABI shape for future native web/worker integration, but the
  freestanding verify path is still stubbed.

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
- These targets exist as early native application/bootstrap surfaces for the full
  Zig port, while `zig build run -- ...` continues to expose the replay tooling.
- `zig build wasm` remains the freestanding ABI module (`wasm32-freestanding`) and
  is intentionally separate from the raylib web target (`wasm32-emscripten`).

## WASM exports

- `crimson_alloc(size) -> ptr`
- `crimson_free(ptr, size) -> void`
- `crimson_verify_replay_json(replay_ptr, replay_len, opts_ptr, opts_len, out_ptr, out_len) -> i32`
- `crimson_last_error_json(out_ptr, out_len) -> i32`
