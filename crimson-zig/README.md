# crimson-zig

Standalone Zig workspace for the native Crimson port.

## What it is now

`crimson-zig/` is no longer a replay-verifier side project. It already contains:

- a shared deterministic runtime under `src/runtime/`,
- native replay tooling (`replay list`, `replay verify`, `replay info`,
  `replay benchmark`, checkpoint verification/diffing),
- a real raylib desktop app target,
- archive/codec support for `crimson.paq`, `music.paq`, `sfx.paq`, `crimson.cfg`, and `game.cfg`,
- a freestanding WASM replay verify/info/benchmark and checkpoint comparison ABI.

The desktop target now owns a real boot-to-menu-to-gameplay loop:

- boot/logo flow,
- root/play-game/options/statistics/pause/results shells,
- live Survival, Rush, Quests, Typ-o, and Tutorial,
- archive-backed rendering/audio,
- native config/status loading and saveback,
- high-score entry and statistics surfaces.

The strongest public tooling surface is still replay verification, but the
workspace direction is a full native port, not a verifier-only fork.

## Current gaps

The biggest remaining Zig work is no longer basic rendering or menu existence.
It is mostly closure work:

- replay/tooling breadth still lags Python,
- some product-shell flows are still thinner than Python,
- checkpoint verification tooling still lacks some Python-only diagnostics,
- WASM is still a narrow replay/runtime ABI, but exposes replay
  verify/info/benchmark JSON paths plus checkpoint text and JSON paths,
- network/LAN parity is still deferred.

For the staged remaining-work breakdown, see
[`docs/rewrite/zig-roadmap.md`](/Users/banteg/dev/banteg/crimson/docs/rewrite/zig-roadmap.md).

## Codecs and assets

`crimson_zig.formats` includes deterministic codecs for:

- `formats.paq`
- `formats.jaz`
- `formats.tga`
- `formats.crimson_cfg`
- `formats.game_cfg`

The desktop asset layer in
[`src/window_assets.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_assets.zig)
now loads:

- `.jaz`
- `.tga`
- `.jpg` / `.jpeg`
- `load/smallFnt.dat`

Runtime assets are resolved with the same priority as the Python port:

1. `CRIMSON_ASSETS_DIR`
2. `CRIMSON_RUNTIME_DIR`
3. `CRIMSON_BASE_DIR`
4. the platformdirs-compatible runtime dir
5. checkout-local fallbacks such as `./artifacts/assets`

The same runtime-dir policy is used for `crimson.cfg`, `game.cfg`,
`music.paq`, `sfx.paq`, and `music/game_tunes.txt`.

## Build and run

```bash
cd crimson-zig
zig build
zig build test
zig build window
zig build run-window
zig build wasm
zig build asset-smoke
zig build run -- replay verify <replay.crd> --format json
zig build run -- replay info <replay.crd> --format json
zig build run -- replay list --base-dir .
zig build run -- replay verify-checkpoints <replay.crd> --format json
zig build run -- replay diff-checkpoints <expected.chk> <actual.chk> --format json
zig build run -- replay benchmark <replay.crd> --runs 5
zig build asset-smoke -- /path/to/assets --json
zig build run -- relay serve --bind 127.0.0.1 --port 31993
```

Useful targets:

- `zig build window`
  Builds the native raylib app without launching it.
- `zig build run-window`
  Launches the desktop app.
- `zig build asset-smoke`
  Runs a local decode smoke pass over archive-backed assets and reports exact
  failing entries. Pass `--json` or `--format json` for scriptable output.
- `zig build wasm`
  Builds the freestanding replay/runtime ABI target.
- `zig build web-window`
  Builds the emscripten/raylib browser target.
- `zig build run -- relay serve`
  Runs the native UDP relay server through the main CLI. The dedicated
  `zig build relay-serve` step remains available for relay-only runs.

## Desktop shell status

The native desktop target is implemented in
[`src/window_main.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_main.zig)
with supporting modules for boot, menus, pause, statistics, options, cursors,
HUD, world rendering, terrain FX, projectiles, perk menus, and audio.

Current notable behaviors:

- window size is read from `crimson.cfg`,
- `--demo` enables the shareware shell and `--no-intro` skips directly to the
  root menu,
- the OS cursor is hidden and replaced by native menu/aim cursors,
- world rendering uses archive-backed terrain/sprites/effects,
- gameplay audio and product-shell audio are routed through native Zig audio
  modules,
- `game.cfg` is updated for play counters, quest counters, unlock indices,
  weapon usage, and playtime,
- replay/runtime RNG tracing now uses static caller tags instead of the old
  untagged verifier behavior.

## Replay tooling

The native CLI currently exposes:

- `crimson-zig replay verify <replay.crd>`
- `crimson-zig replay info <replay.crd>`
- `crimson-zig replay list`
- `crimson-zig replay verify-checkpoints <replay.crd>`
- `crimson-zig replay benchmark <replay.crd>` (headless mode only)
- `crimson-zig replay diff-checkpoints <expected.chk> <actual.chk>`
- `crimson-zig relay serve`

Supported native replay/runtime modes today:

- Survival
- Rush
- Quests
- Typ-o
- Tutorial

The native verifier/info stack now:

- decodes `.crd` payloads in Zig,
- runs the shared deterministic runtime,
- supports RNG tracing via `replay verify --trace-rng` and
  `replay benchmark --trace-rng`,
- emits Python-readable trace payloads,
- reports invalid spawn-template / quest-table inputs as invalid replay/session
  data rather than vague “unsupported path” failures.

## WASM exports

Current freestanding exports:

- `crimson_alloc(size) -> ptr`
- `crimson_free(ptr, size) -> void`
- `crimson_verify_replay_json(replay_ptr, replay_len, opts_ptr, opts_len, out_ptr, out_len) -> i32`
- `crimson_info_replay_json(replay_ptr, replay_len, opts_ptr, opts_len, out_ptr, out_len) -> i32`
- `crimson_benchmark_replay_json(replay_ptr, replay_len, opts_ptr, opts_len, out_ptr, out_len) -> i32`
- `crimson_diff_checkpoints_text(expected_ptr, expected_len, actual_ptr, actual_len, out_ptr, out_len) -> i32`
- `crimson_diff_checkpoints_json(expected_ptr, expected_len, actual_ptr, actual_len, out_ptr, out_len) -> i32`
- `crimson_verify_checkpoints_text(replay_ptr, replay_len, checkpoints_ptr, checkpoints_len, opts_ptr, opts_len, out_ptr, out_len) -> i32`
- `crimson_verify_checkpoints_json(replay_ptr, replay_len, checkpoints_ptr, checkpoints_len, opts_ptr, opts_len, out_ptr, out_len) -> i32`
- `crimson_last_error_json(out_ptr, out_len) -> i32`

The replay verify/info and checkpoint verify exports accept an optional JSON
options object with `max_ticks`. The replay benchmark export accepts
`max_ticks`, `runs`, `warmup_runs`, and `trace_rng`; freestanding WASM has no
host clock, so callers that need wall-time measurements should time the export
externally.
