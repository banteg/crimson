---
tags:
  - rewrite
  - parity
  - zig
---

# Zig native port status (`crimson-zig/`)

Last reviewed: **2026-05-02**

Scope target: a full native Zig port of Crimson systems, content, codecs,
runtime, and product shell.

For the broader remaining-work breakdown, see
[`zig-roadmap.md`](zig-roadmap.md).

## Current status

The Zig tree is no longer best described as “the verifier port”.

What exists today:

- shared deterministic runtime/session ownership under
  `crimson-zig/src/runtime/`,
- native replay list/verification/info/benchmark/checkpoint tooling,
- native debug contract verification and CDT trace export tooling,
- native `crimson.cfg` and `game.cfg` inspection tooling,
- native quest spawn-table dump tooling,
- native UDP relay serve CLI,
- native `net host/join --format json` session construction,
- native rollback live-session launch and an in-process rollback smoke command,
- native Play Game network entry shell,
- a real raylib desktop app target,
- archive/config/status codecs,
- archive-backed rendering/audio,
- live native gameplay for Survival, Rush, Quests, Typ-o, and Tutorial,
- a freestanding WASM replay verify/info plus checkpoint diff/verify text and
  JSON ABI.

Replay tooling is still the most mature headless/public surface, but it now
consumes the same shared runtime used by the native desktop application.

## Ported in Zig

- `.crd` replay ingestion and native simulation in Zig
- shared deterministic session builders
- native replay `list`, `verify`, `info`, `benchmark`, `verify-checkpoints`,
  and `diff-checkpoints`
- CDT/debug trace plumbing
- typed RNG caller tagging for verifier/runtime draws
- native config/status ownership for `crimson.cfg` and `game.cfg`, including
  CLI inspection for both files
- native spawn-template runtime summary tooling via `spawn-plan`
- installed native asset smoke tool for `crimson.paq` archive/image decode
  validation
- installed native desktop `crimson-zig-window` binary for the playable product
  shell
- real boot/menu/gameplay/pause/results/final-quest end-note/statistics/options
  shell
- demo Play Game / Quest menu gating applies the native shareware quest unlock
  index cap while still using the full saved progress in full builds
- archive-backed world/UI asset loading
- archive-backed audio loading and gameplay/menu audio routing
- transient world FX, terrain baking, sprite/atlas rendering, and HUD/cursor
  presentation

## Supported native replay/runtime modes

Current supported native replay/runtime modes:

- Survival
- Rush
- Quests
- Typ-o
- Tutorial

Current supported replay-tooling behavior:

- preserve-bugs compatibility mode
- replay directory listing via `replay list`, including `--format json` and
  `--json-out`
- checkpoint verification via `replay verify-checkpoints`, including
  `--format json` and `--json-out`
- checkpoint diffing via `replay diff-checkpoints`, including `--format json`
  and `--json-out`
- replay RNG tracing via `replay verify --trace-rng` and
  `replay benchmark --trace-rng`
- freestanding WASM replay verification and replay info JSON exports, with
  replay info options for max ticks, player filtering, and verbose event output
- freestanding WASM checkpoint diff/verify text and JSON exports
- headless replay throughput timing and native coarse profiling via
  `replay benchmark`, including native JSON profile summary export with
  `--profile --profile-out`; render benchmark mode and cProfile `.pstats`
  export remain Python-only
- native CDT trace export via `dbg record <replay.crd> --out <trace.cdt>`
- native CDT trace health inspection via
  `dbg health <trace.cdt> --format json`, including tick-window filters and
  `--json-out`
- native one-tick CDT summaries via `dbg tick <trace.cdt> <tick> --json`,
  including `--json-out`
- native CDT entity-history summaries via
  `dbg entity <trace.cdt> <entity_uid> --json`, including tick-range filters and
  `--json-out`
- native debug schema contract reporting via `dbg verify`
- native `crimson.cfg` human/JSON inspection via `config`
- native `game.cfg` checksum-verified human/JSON inspection via `status`
- native runtime asset archive/image validation via `crimson-zig-asset-smoke`
- current Python-readable trace export contracts
- quest spawn-table JSON dumps via `quests <level> --format json --seed <seed>`
  and human allocation summaries via `quests <level> --show-plan`
- spawn-template runtime summaries via `spawn-plan <template_id> --json`,
  including optional non-demo burst-effect counts
- native UDP relay serving via `relay serve`
- native rollback session construction via `net host/join --format json` with
  `runtime_supported=true`
- in-process rollback smoke validation via `net smoke-rollback --format json`
  and `net smoke-rollback --impair delay-first-guest-input --format json`
  and `net smoke-rollback --impair reorder-first-guest-input --format json`
  and `net smoke-rollback --impair drop-first-guest-input --format json`
  and `net smoke-rollback --impair force-guest-resync --format json`
  and `net smoke-rollback --impair guest-reconnect --format json`
  and `net smoke-rollback --impair guest-reconnect-resync --format json`
  and `net smoke-rollback --impair guest-double-reconnect --format json`
  and `net smoke-rollback --impair guest-double-reconnect-resync --format json`
  and `net smoke-rollback --impair jitter-burst --format json`
  and `net smoke-rollback --impair bidirectional-jitter-burst --format json`
  and
  `net smoke-rollback --impair guest-reconnect-bidirectional-jitter-burst --format json`
- invalid spawn-template / quest-table inputs reported as invalid replay/session
  data rather than stale “unsupported path” wording

## Current native architecture

Important architectural state:

- replay tooling no longer owns a separate simulation fork,
- deterministic runtime is shared between replay and live desktop execution,
- session construction is mode-oriented through
  `runtime/session_builders.zig`,
- live gameplay is driven through the same runtime core by
  `runtime/live_runner.zig`.

This is the main reason the older “verifier-only” framing is now wrong.

## Remaining gaps

The important remaining gaps are now:

- replay/verifier breadth still lags Python,
- some product-shell flows are still thinner than Python, though quest results
  now include completion reward names from the native unlock tables,
- demo/trial shell behavior exists and now honors the demo quest cap in the
  product menus, but still needs polish alongside the surrounding product shell,
- WASM still exposes a narrow replay/runtime surface, but now has replay
  verify/info JSON byte-input exports, replay info filter/verbose options, plus
  checkpoint diff/verify text and JSON exports,
- network/LAN parity still needs broader stress and lobby coverage; Zig can now
  construct rollback sessions, launch live rollback runners, smoke-test a
  host/guest relay exchange, force delayed/reordered/dropped-input rollback
  correction, absorb a repeated jitter burst without resync, complete a
  guest-requested resync snapshot, and self-reconnect a guest through its relay
  token before advancing more input, absorb bidirectional jitter after a
  reconnect, drive a longer reconnect-then-resync smoke path, and recover from
  a double-reconnect-then-resync sequence, but broader reconnect/resync stress
  and product-lobby polish remain.

The biggest remaining technical risk is not basic gameplay ownership. It is
closing the remaining replay/tooling and product-shell breadth gaps cleanly.
