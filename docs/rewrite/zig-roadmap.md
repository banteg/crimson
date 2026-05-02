---
tags:
  - rewrite
  - parity
  - zig
---

# Zig port roadmap (`crimson-zig/`)

Last reviewed: **2026-05-02**

This page now tracks the remaining work after the Zig port crossed the
“desktop playable slice” threshold. The current tree already contains a real
native app, shared deterministic runtime, replay tooling, asset/audio loading,
and substantial shell/product behavior. The remaining work is mostly closure,
breadth, and product parity.

## Current baseline

Today `crimson-zig/` already has:

- shared deterministic runtime/session ownership in
  [`crimson-zig/src/runtime/session.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/session.zig)
  and
  [`crimson-zig/src/runtime/session_builders.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/session_builders.zig),
- native replay tooling in
  [`crimson-zig/src/verify_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/verify_native.zig)
  and
  [`crimson-zig/src/replay_info_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/replay_info_native.zig),
- native quest spawn-table dumps, including optional spawn-plan summaries,
  through
  [`crimson-zig/src/quest_spawn_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/quest_spawn_native.zig),
- native spawn-template materialization summaries through
  [`crimson-zig/src/spawn_plan_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/spawn_plan_native.zig),
  including runtime burst-effect counts when demo mode is disabled,
- a real raylib desktop application in
  [`crimson-zig/src/window_main.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_main.zig),
- archive/config/status codecs under
  [`crimson-zig/src/formats/`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/formats),
- native audio modules under
  [`crimson-zig/src/audio/`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/audio),
- native rollback session construction and live smoke validation in
  [`crimson-zig/src/net_session_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/net_session_native.zig)
  and
  [`crimson-zig/src/net_rollback_smoke_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/net_rollback_smoke_native.zig),
  including delayed, reordered, and dropped guest-input smoke cases that force
  prediction correction without resync, plus a guest-requested resync smoke
  case that applies a host snapshot stream, repeated and bidirectional
  jitter-burst smoke cases, a relay-token guest self-reconnect smoke case with
  post-reconnect input continuity, a double guest reconnect smoke case, a
  post-reconnect bidirectional jitter smoke case, a longer reconnect-then-resync
  smoke case, and a double-reconnect-then-resync stress case,
- a freestanding WASM replay verify/info/benchmark plus checkpoint diff/verify
  text and JSON ABI in
  [`crimson-zig/src/wasm_exports.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/wasm_exports.zig).
  The replay info export now accepts max-tick, player-index, and verbose event
  options.

Current live/native gameplay coverage:

- Survival
- Rush
- Quests
- Typ-o
- Tutorial

The earlier “missing the game” framing is obsolete. The remaining roadmap is
about finishing the port cleanly.

## Remaining workstreams

### 1. Replay and verifier breadth

This is still the most important technical gap after the desktop shell.

Remaining work:

- widen replay envelope support in
  [`crimson-zig/src/replay_codec.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/replay_codec.zig),
  [`crimson-zig/src/runtime/replay_runner.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/replay_runner.zig),
  [`crimson-zig/src/runtime/replay_info.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/replay_info.zig),
  and
  [`crimson-zig/src/runtime/replay/events.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/replay/events.zig),
- keep burning down real remaining `Unsupported*` replay/event surfaces that are
  still justified,
- expand native tooling beyond `replay list`, `replay verify`,
  `replay info`, and `replay benchmark`,
- continue widening the WASM surface beyond byte-input replay verification,
  info, benchmark summaries, and checkpoint comparison.

Definition of done:

- native replay tooling accepts the same practical corpus/classes as Python for
  supported rulesets,
- remaining invalid-input errors are clearly invalid-input errors, not stale
  “not ported” wording,
- the Zig CLI is no longer only a replay verifier with one extra command.

### 2. Product-shell parity

The desktop app is real, but some shells are still thinner than Python.

Remaining work:

- finish remaining results/high-score/product flow parity in
  [`crimson-zig/src/window_main.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_main.zig);
  quest-completion results now include resolved weapon/perk unlock names and
  native-style completed-results keyboard shortcuts,
- keep tightening menu/statistics/options descendants in
  [`crimson-zig/src/window_menu.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_menu.zig),
  [`crimson-zig/src/window_menu_panels.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_menu_panels.zig),
  [`crimson-zig/src/window_statistics.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_statistics.zig),
  and
  [`crimson-zig/src/window_options.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_options.zig),
- keep the demo/trial overlay and purchase-shell behavior aligned with Python
  as surrounding shell flows change,
- keep removing any remaining fallback/scaffold UI logic from the desktop path.

Definition of done:

- boot -> menu -> gameplay -> pause -> results -> stats/options flows behave
  like the Python product shell,
- default Zig installs include the playable `crimson-zig-window` binary,
- the remaining differences are deliberate scope decisions, not stale
  placeholders.

### 3. Native tooling and developer surfaces

Python still has broader non-gameplay tooling than Zig.

Remaining work:

- expand Zig CLI coverage where it materially helps development:
  - replay-oriented tools beyond list/verify/info/benchmark/verify-checkpoints/diff-checkpoints,
  - useful debug/support commands where they make sense natively, including
    `crimson-zig spawn-plan` and the installed `crimson-zig-asset-smoke`
    archive/image decode validator,
- keep trace/debug surfaces aligned with current Python contracts,
- refresh developer docs when tooling behavior changes.

Definition of done:

- Zig-native tooling is useful beyond the verifier path,
- the documented command surface matches what is actually supported.

### 4. Presentation and polish follow-through

Rendering/audio are no longer placeholders, but parity polish remains.

Remaining work:

- continue tightening world/UI/details where Python is still visibly ahead,
- keep product-shell audio parity moving with shell parity,
- validate remaining mode-specific overlays and result flows,
- keep removing split-brain/fallback presentation code when runtime-owned data
  already exists.

Definition of done:

- remaining visual/audio mismatches are minor polish, not missing systems or
  duplicate architectures.

### 5. Network/LAN parity and hardening

This is no longer missing first-launch support, but it still needs hardening
and product parity.

Remaining work:

- keep the native `net host/join --format json` surface aligned with relay
  protocol defaults and runtime support flags,
- expand `net smoke-rollback` beyond the current in-process happy path and
  delayed, reordered, dropped-input, repeated-jitter, post-reconnect jitter,
  guest-resync, guest self-reconnect, and reconnect-then-resync cases into
  broader reconnect/resync stress scenarios,
- tighten desktop network lobby/status UX around live rollback sessions,
- keep legacy lockstep as an explicit fallback while rollback remains primary.

Reference Python surfaces:

- [`src/crimson/screens/panels/network_session.py`](/Users/banteg/dev/banteg/crimson/src/crimson/screens/panels/network_session.py)
- [`src/crimson/screens/panels/network_lobby.py`](/Users/banteg/dev/banteg/crimson/src/crimson/screens/panels/network_lobby.py)
- [`src/crimson/net/`](/Users/banteg/dev/banteg/crimson/src/crimson/net)

## Current priority order

If the goal is to finish the Zig port cleanly, the current order should be:

1. replay/verifier breadth and remaining justified runtime closures
2. product-shell parity, especially results and demo/trial shell
3. native tooling breadth
4. network/LAN stress hardening and product-lobby polish
5. remaining presentation/audio polish

## What is no longer a roadmap item

These were earlier concerns but are no longer the right headline risks:

- “Zig only has replay verifier architecture”
- “Zig has no real desktop game shell”
- “spawn template coverage is broadly missing”
- “quest spawn tables are mostly unported”
- “Zig network support can only emit pending session JSON”

Those areas now have real coverage in the current tree. The remaining work is
closure and parity, not first-time implementation of those foundations.
