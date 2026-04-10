# crimson-zig

Standalone Zig workspace for the native Crimson port.

## Scope (current)

- Direction: full native port of Crimson runtime and supporting codecs/tooling.
- Current most mature CLI surfaces: `crimson-zig replay verify ...` and `crimson-zig replay info ...`
- Current JSON contracts mirror the Python replay CLI for verify/info payloads.
- Current native targets include headless replay tooling, runtime modules, codec libraries,
  a raylib desktop app target, and a freestanding WASM ABI target.
- Shared runtime/session seams now live under `src/runtime/session.zig` and
  `src/runtime/session_builders.zig`, so replay tooling sits on top of the same
  deterministic session shell we intend to use for broader native surfaces.
- `runtime/session_builders.zig` now mirrors the Python `build_*_session(...)`
  split with explicit Survival/Rush/Quest builders, not just replay startup glue.

## Format codecs (library-only)

The `crimson_zig.formats` module now includes deterministic byte-level codecs for:

- `formats.paq`: PAQ archive decode/encode (`paq\\0`, sequential entries).
- `formats.jaz`: JAZ parse + zlib inflate + payload split (`jpeg_bytes` + `alpha_rle_bytes`).
- `formats.crimson_cfg`: fixed-size `crimson.cfg` decode/encode (`0x480` bytes).
- `formats.game_cfg`: `game.cfg` blob/file encode/decode, checksum, and status-struct parse/build.

This wave is intentionally codec-only:

- no new CLI commands yet,
- no `ensure_*`/repair helpers,
- core `formats.jaz` still returns split payload components, while the desktop
  raylib asset loader now expands JAZ JPEG+alpha payloads into RGBA textures.

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
- `zig build run-window` now boots a real desktop Survival slice:
  boot screen -> main menu -> live 1-player Survival run -> results.
- `zig build run-window` now looks for runtime assets using the same default
  runtime-dir policy as Python first:
  `CRIMSON_ASSETS_DIR`, then `CRIMSON_RUNTIME_DIR` / `CRIMSON_BASE_DIR`, then
  the per-user platform data dir (`platformdirs`-compatible layout), with
  `./artifacts/assets` and the current directory left as checkout-local
  fallback. It loads `.jaz`, `.tga`, `.jpg/.jpeg`, and `load/smallFnt.dat`.
- The freestanding WASM ABI now runs the same replay verification core for
  byte-input payloads, with JSON output and JSON error reporting via
  `crimson_last_error_json`.
- A staged scope of the remaining port work lives in
  [`docs/rewrite/zig-roadmap.md`](/Users/banteg/dev/banteg/crimson/docs/rewrite/zig-roadmap.md).

## Build

```bash
zig build
zig build run -- replay verify survival_20260224_041009_score76661.crd --format json
zig build run-window
zig build web-window
zig build asset-smoke
zig build test
zig build wasm
```

## Raylib bootstrap

- `zig build run-window` opens the current desktop playable slice using `raylib-zig`.
- `zig build window` compiles that target without running it.
- `zig build asset-smoke` runs a local decode smoke pass over `crimson.paq` and
  runtime-mapped texture entries, printing exact failing asset paths.
- `zig build web-window` builds an HTML+WASM placeholder window for browser use.
- `zig build run-web-window` serves the web build through `emrun` (`--no_browser`).
- The desktop target is currently a menu-to-gameplay Survival slice with a
  mixed renderer: gameplay world surfaces now use archive-backed textures when
  `crimson.paq` is available, with primitive fallback where exact sprite atlas
  mapping is still incomplete.
- `zig build wasm` remains the freestanding ABI module (`wasm32-freestanding`) and
  is intentionally separate from the raylib web target (`wasm32-emscripten`).

## WASM exports

- `crimson_alloc(size) -> ptr`
- `crimson_free(ptr, size) -> void`
- `crimson_verify_replay_json(replay_ptr, replay_len, opts_ptr, opts_len, out_ptr, out_len) -> i32`
- `crimson_last_error_json(out_ptr, out_len) -> i32`
- `crimson_verify_replay_json` returns copied JSON length on success, negative
  required output length when `out_ptr/out_len` is too small, and `-1` on
  verification/option errors.
- `opts_ptr/opts_len` currently accepts a JSON object with optional `max_ticks`.
