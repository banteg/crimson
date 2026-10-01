---
tags:
  - rewrite
  - parity
  - zig
---

# Zig port

`crimson-zig/` contains the native desktop game, deterministic runtime, replay and
debug tooling, and a freestanding WASM interface. Live play and replay share
`crimson-zig/src/runtime/session.zig` and
`crimson-zig/src/runtime/session_builders.zig`; the desktop loop drives this core
through `crimson-zig/src/runtime/live_runner.zig`.

## Development status

New Zig simulation, parity and product work is deferred. Do not mirror further
Python or recovered-core changes into Zig, including the shared UI timeline,
Typ-o follow-ups and phantom spawn-slot work. The existing verifier remains
available while the recovered C/C++ becomes the shared game/verifier WASM core;
Python remains the fast iteration platform.

The retirement criterion is complete replay-fixture and fixed bot-sweep agreement
with Python's full `RunResult` under each supported bug policy, including the
controllers, settings and players exercised by that corpus. Unsupported cases
are gaps, not passes. Then switch verification to the recovered core; retain a
frozen legacy artifact only where existing replay versions still need it.
The staged parity and deployment gates are in `crimson-core/ROADMAP.md`.

## Build and run

```bash
just zig-build
crimson-zig/zig-out/bin/crimson-zig-window
crimson-zig/zig-out/bin/crimson-zig --help
```

The desktop shell implements boot, menu, gameplay, pause, results, high scores,
statistics and options/controls. Survival, Rush, Quests, Typ-o and Tutorial can
be launched from the shell or direct-start flags. Inspect
`crimson-zig-window --help` for current launch options.

The default build also installs archive smoke/extraction tools. Rendering and
audio use original archive resources; config and status codecs read the native
file formats. Custom network play is [deferred](netplay.md).

## Tooling surfaces

The native command authority is `crimson-zig/src/cli.zig`.

| Surface | Commands or exports |
| --- | --- |
| Replay | `list`, `verify`, `info`, `benchmark`, `verify-checkpoints`, `diff-checkpoints` |
| CDT debugging | `record`, `diff`, `bisect`, `focus`, `health`, `tick`, `entity`, `query`, `verify` |
| Native data inspection | `config`, `status`, `quests`, `spawn-plan` |
| Asset tools | `crimson-zig-asset-smoke`, `crimson-zig-asset-extract` |
| WASM | Replay verify/info/benchmark and checkpoint diff/verify byte-input APIs in `crimson-zig/src/wasm_exports.zig` |

Replay and debug commands expose structured output. Native benchmarking supports
coarse profiling; Python retains render benchmarking, cProfile export and MP4
replay rendering. The WASM target exposes headless replay services, not the
desktop shell. See [trace contracts](trace-format-alignment.md) for the shared
Python/Zig artifact boundary.

## Validation boundaries

- `tests/replay/cli/test_zig_corpus.py` exercises a generated current-format
  corpus covering all five modes, multiplayer and invalid inputs.
- `tests/debug/test_zig_dbg_cli.py` covers native trace diagnostics.
- `tests/grim/test_zig_window_cli.py` verifies installation and non-rendering
  startup for the five modes.
- `just check-zig` runs Zig tests, the native ReleaseFast build, and the WASM build.

These gates establish their tested behavior. They do not establish complete
native replay parity or a visually verified boot-to-results walkthrough.
Product-shell, visual and audio differences need concrete capture or
walkthrough evidence before being declared closed. Keep individual investigation
results with their artifacts as described in the [evidence policy](../verification/evidence-ledger/index.md).
