---
tags:
  - rewrite
  - parity
  - zig
---

# Zig native port status (`crimson-zig/`)

Last reviewed: **2026-04-12**

Scope target: a full native Zig port of Crimson systems, content, codecs,
runtime, and product shell.

For the broader remaining-work breakdown, see
[`zig-roadmap.md`](zig-roadmap.md).

## Current status

The Zig tree is no longer best described as “the verifier port”.

What exists today:

- shared deterministic runtime/session ownership under
  `crimson-zig/src/runtime/`,
- native replay list/verification/info tooling,
- a real raylib desktop app target,
- archive/config/status codecs,
- archive-backed rendering/audio,
- live native gameplay for Survival, Rush, Quests, Typ-o, and Tutorial,
- a freestanding WASM replay-verification ABI.

Replay tooling is still the most mature headless/public surface, but it now
consumes the same shared runtime used by the native desktop application.

## Ported in Zig

- `.crd` replay ingestion and native simulation in Zig
- shared deterministic session builders
- native replay `list`, `verify`, and `info`
- CDT/debug trace plumbing
- typed RNG caller tagging for verifier/runtime draws
- native config/status ownership for `crimson.cfg` and `game.cfg`
- real boot/menu/gameplay/pause/results/final-quest end-note/statistics/options
  shell
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
- replay directory listing via `replay list`
- replay RNG tracing via `--trace-rng`
- current Python-readable trace export contracts
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
- some product-shell flows are still thinner than Python,
- demo/trial shell behavior exists, but still needs polish alongside the
  surrounding product shell,
- WASM still exposes a narrow replay/runtime surface,
- network/LAN parity is still deferred.

The biggest remaining technical risk is not basic gameplay ownership. It is
closing the remaining replay/tooling and product-shell breadth gaps cleanly.
