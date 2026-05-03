---
tags:
  - rewrite
  - parity
  - zig
---

# Zig port roadmap (`crimson-zig/`)

Last reviewed: **2026-05-03**

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
- native replay/debug tooling in
  [`crimson-zig/src/verify_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/verify_native.zig)
  and
  [`crimson-zig/src/replay_info_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/replay_info_native.zig),
  plus native CDT diff, bisect, focus, health, tick, entity, and compact query
  inspection in
  [`crimson-zig/src/dbg_bisect_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/dbg_bisect_native.zig),
  [`crimson-zig/src/dbg_diff_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/dbg_diff_native.zig),
  [`crimson-zig/src/dbg_entity_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/dbg_entity_native.zig),
  [`crimson-zig/src/dbg_focus_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/dbg_focus_native.zig),
  [`crimson-zig/src/dbg_health_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/dbg_health_native.zig)
  and
  [`crimson-zig/src/dbg_query_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/dbg_query_native.zig)
  and
  [`crimson-zig/src/dbg_tick_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/dbg_tick_native.zig),
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
  post-reconnect input continuity, double and triple guest reconnect smoke cases, a
  post-reconnect bidirectional jitter smoke case, a longer reconnect-then-resync
  smoke case that accepts fresh guest input after the applied snapshot, double- and
  triple-reconnect-then-resync stress cases, and
  double- and triple-reconnect-then-bidirectional-jitter stress cases,
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

## Completion contract

The Zig port is done when all of these are true at the same time:

- the default `zig build` installs `crimson-zig-window` and the native CLI tools
  documented here,
- Survival, Rush, Quests, Typ-o, and Tutorial can all be launched from the Zig
  desktop shell and from direct launch flags without known mode-blocking gaps,
- replay verify/info/list/benchmark/checkpoint tooling accepts the same
  practical supported replay corpus as Python for current rulesets, with
  invalid inputs reported as invalid replay/input errors rather than "not
  ported" failures,
- boot -> menu -> gameplay -> pause -> results -> stats/options/control flows
  have no known placeholder-only or scaffold UI branches in the shipped desktop
  path,
- demo/trial and network lobby flows are either parity-complete or explicitly
  documented as intentional scope decisions,
- native developer tooling is broad enough to debug replay/runtime mismatches
  without dropping back to Python for every investigation,
- the completion audit maps each item above to concrete evidence: source files,
  CLI outputs, tests, and green CI runs.

Passing CI is required but not sufficient. CI only proves the current coverage;
the port is not done until the checklist above has direct artifact evidence and
there are no remaining undocumented parity gaps.

## Larger landing slices

Use these as the next PR/commit-sized units. Avoid one-test or one-helper
changes unless they unblock one of these larger slices or fix a CI regression.

### A. Replay corpus closure

Goal: prove native replay tooling handles the practical replay corpus we expect
to support.

Current evidence:

- `uv run pytest tests/replay/cli/test_zig_corpus.py` drives a generated
  current-ruleset corpus through Zig `replay verify`, `replay info`, `replay
  list`, `replay benchmark`, `replay verify-checkpoints`, and `replay
  diff-checkpoints`.
- The generated corpus names Survival, Rush, Quests, Typ-o, Tutorial,
  verbose-event, multi-player, and invalid-input cases.

Scope:

- refresh checked-in completed `.crd` fixtures under `tests/fixtures/replays/`
  or document them as intentionally legacy-only; the current files are old wire
  shapes and are not current-ruleset acceptance evidence,
- make `replay verify`, `replay info`, `replay benchmark`, and checkpoint
  commands run against that corpus in Zig,
- remove stale "not ported" wording from user-facing replay failures where the
  input is actually malformed or unsupported-by-policy.

Evidence gate:

- `uv run pytest tests/replay/cli/test_zig_corpus.py`,
- `uv run pytest tests/replay/cli/test_zig_*.py`,
- `zig build test --summary all` from `crimson-zig/`,
- at least one documented command that runs the corpus through native tooling.

### B. Product-shell walkthrough closure

Goal: make the shipped Zig window behave like the Python product shell for the
full menu/game/results loop.

Scope:

- audit and close boot, root menu, Play Game, Quests, Options, Controls,
  Statistics, Pause, Results, High Scores, demo/trial, Mods, Other Games, and
  Network Session flows as one shell batch,
- remove remaining fallback/scaffold branches from shipped paths when runtime
  data exists,
- update docs with any intentional differences.

Evidence gate:

- `uv run pytest tests/grim/test_zig_window_cli.py`,
- `zig build test --summary all` from `crimson-zig/`,
- `zig build --summary all` from `crimson-zig/`,
- a manual or automated launch smoke for representative direct launch flags:
  `--start-mode survival`, `rush`, `quests --quest-level`, `typo`, and
  `tutorial`.

### C. Native tooling parity closure

Goal: make Zig-native tools useful enough for day-to-day port debugging.

Scope:

- compare `src/crimson/cli/replay.py` and `src/crimson/cli/dbg.py` against the
  installed Zig command surface,
- add the missing high-value native commands or document why they stay Python
  only,
- ensure command help, JSON output, and docs match the implemented behavior.

Evidence gate:

- CLI parity table in this roadmap or a linked doc,
- targeted Python/Zig CLI parity tests,
- `just zig-build`, `just zig-test`, and relevant `uv run pytest tests/replay`
  or `tests/debug` targets.

### D. Network and demo hardening closure

Goal: finish the non-local product paths that can still hide launch-time gaps.

Scope:

- expand rollback smoke coverage into the remaining reconnect/resync stress
  cases that are worth keeping,
- verify host/join JSON surfaces and desktop lobby status against Python relay
  defaults,
- finish demo/trial purchase-shell behavior alongside the network shell if the
  same product-state plumbing is touched.

Evidence gate:

- native `net smoke-rollback` cases,
- `uv run pytest tests/net` coverage that compares Python contracts where
  applicable,
- `zig build test --summary all`.

### E. Final completion audit

Goal: decide whether the Zig port is actually complete.

Scope:

- build a prompt-to-artifact checklist for the completion contract above,
- cite concrete files, commands, test outputs, and CI run IDs,
- list every remaining parity difference as either fixed, intentionally scoped
  out, or still blocking.

Evidence gate:

- clean worktree,
- current master CI and Zig CI green,
- final audit committed in docs if any meaningful scope decision remains.

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
  `replay info`, `replay benchmark`, `dbg diff`, `dbg bisect`, `dbg health`,
  `dbg tick`, `dbg focus`, and `dbg entity`/`dbg query`,
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
  native-style completed-results keyboard shortcuts, and the final quest
  end-note screen uses the native 300 ms open/close timeline before launching
  Survival/Rush/Typ-o or returning to the main menu. Results/game-over panels
  now use the native open/close slide timeline, keep high-score/button hitboxes
  aligned with the moving panel, and wait for the close timeline before
  dispatching Play Again, High scores, or Main Menu actions. Result-launched
  high-score tables now return Back to the results screen instead of the
  statistics hub, and Play a game from that table clears the stacked results
  screen before opening Play Game,
- keep tightening menu/statistics/options descendants in
  [`crimson-zig/src/window_menu.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_menu.zig),
  [`crimson-zig/src/window_menu_panels.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_menu_panels.zig),
  [`crimson-zig/src/window_statistics.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_statistics.zig),
  and
  [`crimson-zig/src/window_options.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_options.zig);
  the root menu, statistics hub, statistics child panels, and options/controls
  panels now wait for the native open timeline and close before dispatching
  descendant or Back actions,
- keep tightening pause and gameplay-adjacent shells in
  [`crimson-zig/src/window_pause_menu.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_pause_menu.zig);
  the pause menu now waits for its native close timeline before dispatching
  Back, Options, or Quit actions,
- keep tightening remaining miscellaneous panels in
  [`crimson-zig/src/window_misc_panels.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_misc_panels.zig);
  Mods, Other Games, Network Session, and the live Network Lobby now use the
  shared native panel timeline before dispatching Back or Launch actions,
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
  - useful debug/support commands where they make sense natively,
- keep trace/debug surfaces aligned with current Python contracts,
- refresh developer docs when tooling behavior changes.

Definition of done:

- Zig-native tooling is useful beyond the verifier path,
- the documented command surface matches what is actually supported.

Already-native support surfaces in this workstream include `crimson-zig
spawn-plan`, the installed `crimson-zig-asset-smoke` archive/image decode
validator, and the installed `crimson-zig-asset-extract` PAQ extractor with
JAZ/TGA-to-PNG export.

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
- keep tightening desktop network lobby/status UX around live rollback sessions;
  the live lobby now opens and backs out through the native panel timeline,
- keep legacy lockstep as an explicit fallback while rollback remains primary.

Reference Python surfaces:

- [`src/crimson/screens/panels/network_session.py`](/Users/banteg/dev/banteg/crimson/src/crimson/screens/panels/network_session.py)
- [`src/crimson/screens/panels/network_lobby.py`](/Users/banteg/dev/banteg/crimson/src/crimson/screens/panels/network_lobby.py)
- [`src/crimson/net/`](/Users/banteg/dev/banteg/crimson/src/crimson/net)

## Current priority order

If the goal is to finish the Zig port cleanly, the current order should be:

1. replay corpus closure
2. product-shell walkthrough closure
3. native tooling parity closure
4. network and demo hardening closure
5. final completion audit

## What is no longer a roadmap item

These were earlier concerns but are no longer the right headline risks:

- “Zig only has replay verifier architecture”
- “Zig has no real desktop game shell”
- “spawn template coverage is broadly missing”
- “quest spawn tables are mostly unported”
- “Zig network support can only emit pending session JSON”

Those areas now have real coverage in the current tree. The remaining work is
closure and parity, not first-time implementation of those foundations.
