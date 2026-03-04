# Refactor: Remaining Work Toward Simplified End-State

## Scope

This document tracks remaining work and immediate next execution steps.
Completed stages may stay temporarily for auditability until the next cleanup pass.

Target architecture is defined by `plan.md`:
- `GameLoopView` is the only interactive runtime pump owner.
- Replay paths are local-only.
- `TickRunner` is pure/stateless (no internal clock/debt ownership).
- Input control flow is explicit (`InputStatus`: `READY`/`STALLED`/`EOS`).
- Replay uses `Journal` with `ReplayInputProvider` as a thin adapter.
- Hook-bus orchestration is removed from end-state.
- Headless verify skips apply but preserves deterministic planning RNG.
- Presentation apply is frame-driver-owned by context (`GameLoopView` for interactive gameplay; replay/headless frame drivers for replay contexts).
- World architecture collapses to `SimWorldState` + `PresentationLayer`.
- `NullSink` remains the headless sink.
- Tests are runtime-first (no test-only runtime fallback/default behavior).

---

## Stage 1: Remove Hook-Bus Orchestration

Current state uses dynamic hook dispatch inside the deterministic tick loop.
`TickRunner` calls 8 hook dispatch points per tick via `TickHookBus`, which uses
`getattr`-string-based method lookup on `TickHook: TypeAlias = object` (fully
type-erased). Replay recording, checkpoint emission, network sync, and profiling
all happen through this implicit dispatch instead of explicit frame-driver calls.

### Tasks

- [x] Remove `TickHookBus` from `TickRunner`. The runner should return `TickBatchResult` with completed tick payloads only — no side-effect dispatch.
- [x] Replace `TickHook: TypeAlias = object` with nothing. Hook objects should not exist as a concept in the runner; side effects belong to the frame driver.
- [x] Delete `getattr`-string method lookup dispatch (`_resolve_method`, `_dispatch`) from tick orchestration.
- [x] Move replay recording to explicit frame-driver dispatch: after `advance_ticks` returns, iterate `TickBatchResult.completed_results` and call `recorder.record_tick(inputs)` directly. Currently this happens inside `ReplayRecorderHook.on_pre_sim` (hooks.py:157).
- [x] Move checkpoint emission to explicit frame-driver dispatch: after batch apply, call checkpoint from completed results directly. Currently this happens inside `CheckpointHook.on_tick_end` (hooks.py:182).
- [x] Move network sync to explicit frame-driver dispatch: hash broadcast and desync detection currently happen inside `NetworkSyncHook.on_post_hash`/`on_tick_end` (hooks.py:216, 223).
- [x] Move profiling to explicit frame-driver timing: wrap `advance_ticks` + apply with `time.perf_counter_ns()` instead of scattering timing across `ProfilerHook.on_pre_sim`/`on_world_step_done`/`on_post_hash`/`on_tick_end` (hooks.py:285-304).
- [x] Delete mode-level hook wiring instance vars: `_tick_replay_hook`, `_tick_checkpoint_hook`, `_tick_network_sync_hook`, `_tick_profiler_hook`, `_tick_observer_hook`, `_tick_command_hook` (base_gameplay_mode.py:1596-1601).
- [x] Collapse `_ensure_tick_runner` from 125-line 8-tuple return to simple runner creation. It currently returns `(TickRunner, InputProvider, ReplayRecorderHook, CheckpointHook, NetworkSyncHook, ProfilerHook, ObserverHook, CommandHook)`. After hook removal, it only needs to return `(TickRunner, InputProvider)`.
- [x] Keep deterministic ordering guarantees by explicit, ordered dispatch calls in one place.

### Evidence

- `src/crimson/sim/hooks.py:40` — `TickHook: TypeAlias = object` (type-erased)
- `src/crimson/sim/hooks.py:54-61` — `_resolve_method` uses `getattr` + string names
- `src/crimson/sim/hooks.py:134-166` — `ReplayRecorderHook` (implicit recording via `on_pre_sim`)
- `src/crimson/sim/hooks.py:169-193` — `CheckpointHook` (implicit checkpoint via `on_tick_end`)
- `src/crimson/sim/hooks.py:196-270` — `NetworkSyncHook` (implicit sync via `on_post_hash`/`on_tick_end`)
- `src/crimson/sim/hooks.py:273-304` — `ProfilerHook` (timing scattered across 4 hook methods)
- `src/crimson/sim/tick_runner.py:69-74` — runner accepts and defaults `TickHookBus`
- `src/crimson/sim/tick_runner.py:140-173` — 8 hook dispatch points inside deterministic tick loop
- `src/crimson/modes/base_gameplay_mode.py:1661-1785` — `_ensure_tick_runner` 125-line 8-tuple factory
- `src/crimson/modes/base_gameplay_mode.py:1596-1601` — 6 hook instance vars in reset

### Acceptance

- [x] No `TickHookBus` or hook objects in runtime tick orchestration.
- [x] Zero `getattr`-based dispatch in runtime path.
- [x] `_ensure_tick_runner` returns at most `(TickRunner, InputProvider)`.
- [x] Replay/checkpoint/network sync behavior parity preserved.
- [x] `uv run pytest --no-cov` passes.

---

## Stage 2: Standardize Input Status + Journal Replay Contract

Current state mixes `None`-as-stall and exception-driven EOS. `pull_tick_input`
returns `list[PlayerInput] | None` (None = stall). `ReplayInputProvider` raises
`ReplayEndOfStream` for EOS. `TickRunner` catches this and re-wraps it as
`ReplayAdvanceEndOfStream`. `ReplayInputProvider.push_command` raises
`RuntimeError` — a protocol violation on a method that's part of `InputProvider`.

### Tasks

- [x] Introduce `InputStatus` enum (`READY`/`STALLED`/`EOS`) and `TickInput` dataclass with `status` + `inputs` fields.
- [x] Change `InputProvider.pull_tick_input` return type from `list[PlayerInput] | None` to `TickInput`.
- [x] Convert `LocalInputProvider` to always return `TickInput(status=READY, ...)`.
- [x] Convert `NetworkInputProvider` to return `TickInput(status=STALLED, ...)` instead of `None`.
- [x] Convert `ReplayInputProvider` to return `TickInput(status=EOS, ...)` instead of raising `ReplayEndOfStream`.
- [x] Delete `ReplayEndOfStream` and `ReplayAdvanceEndOfStream` exception classes.
- [x] Fix `ReplayInputProvider.push_command`: either split `InputProvider` into read-only and command-capable protocols, or make replay's `push_command` a silent no-op. Current `RuntimeError` raise on a protocol method is an LSP violation.
- [x] Update `TickRunner.advance_frame` (or its pure replacement) to match on `TickInput.status` instead of `None` checks (line 141) and `try/except ReplayEndOfStream` (line 180).
- [x] Update `TickBatchResult` to carry `batch_status` (`ready`/`stalled`/`eos`) instead of just `stalled: bool`.
- [x] Update all mode and replay driver callers to consume status-based results.

### Evidence

- `src/crimson/sim/input_providers.py:13` — `ReplayEndOfStream` exception class
- `src/crimson/sim/input_providers.py:34` — `pull_tick_input -> list[...] | None`
- `src/crimson/sim/input_providers.py:136-142` — `ReplayInputProvider` raises exception for EOS
- `src/crimson/sim/input_providers.py:146-147` — `push_command` raises `RuntimeError`
- `src/crimson/sim/tick_runner.py:39-44` — `TickBatchResult` has `stalled: bool` instead of `batch_status`
- `src/crimson/sim/tick_runner.py:46-60` — `ReplayAdvanceEndOfStream` re-wrap class
- `src/crimson/sim/tick_runner.py:141` — `if tick_inputs is None:` stall detection
- `src/crimson/sim/tick_runner.py:180-195` — exception-based replay EOS with re-wrap

### Acceptance

- [x] `InputStatus` enum with `READY`/`STALLED`/`EOS`.
- [x] No `None`-as-stall in provider/runner contracts.
- [x] No replay EOS exceptions in normal tick advancement.
- [x] No `RuntimeError` from protocol methods during normal operation.
- [x] `TickBatchResult.batch_status` replaces `stalled: bool`.
- [x] Input provider tests cover all three status paths.

### Execution Plan (Next Phase)

1. Contract-first types
- Add `InputStatus` and `TickInput` in `sim/input_providers.py`.
- Update `InputProvider.pull_tick_input` protocol signature to return `TickInput`.
- Keep type aliases and names stable where possible to reduce call-site churn.

2. Provider migration
- Update `LocalInputProvider` to always return `TickInput(status=READY, inputs=...)`.
- Update `NetworkInputProvider` to return `STALLED` instead of `None`.
- Update `ReplayInputProvider` to return `EOS` instead of raising `ReplayEndOfStream`.
- Make replay `push_command` contract-safe (no `RuntimeError` in normal flow).

3. Runner migration
- Replace `None`/exception flow in `TickRunner.advance_frame` with status branching.
- Remove `ReplayAdvanceEndOfStream` and propagate EOS via `TickBatchResult.batch_status`.
- Introduce `batch_status` and keep `ticks_completed`/`completed_results` semantics unchanged.

4. Caller migration
- Update `BaseGameplayMode` and `ReplayPlaybackMode` to consume `batch_status`.
- Remove all normal-path replay EOS exception handling from frame drivers.
- Preserve current deterministic ordering for command apply, record, checkpoint, sync, and apply.

5. Test migration
- Update provider and runner tests to cover `READY`, `STALLED`, and `EOS`.
- Replace exception-based replay EOS assertions with status-based assertions.
- Add targeted regressions for replay boundary (`tick_index == tick_limit`) and LAN stall behavior.

6. Validation gates
- Run focused suites first: `test_input_provider_semantics.py`, `test_tick_runner_*`, `test_replay_playback_mode_*`.
- Then run full gate: `uv run pytest --no-cov`.
- Do not start Stage 3 until Stage 2 acceptance checklist is fully checked.

---

## Stage 3: Make TickRunner Pure and Frame-Owned for Debt

`TickRunner` currently owns `FixedStepClock`, `_next_tick_index`, and
`_frame_index` as mutable state. It exposes `runner.clock` to callers (modes
read `tick_rate`, `dt_tick`, `accum`; replay reads `clock` directly). Modes call
`runner.reset_clock()`. The runner also mutates the clock accumulator internally
to restore unconsumed ticks (line 186). A 3-layer no-op call chain wraps the
advance call.

### Tasks

- [x] Remove `FixedStepClock` ownership from `TickRunner`.
- [x] Remove `self._next_tick_index` and `self._frame_index` mutable state.
- [x] Replace `advance_frame(dt, max_ticks)` with `advance_ticks(start_tick, ticks_requested, tick_dt)` returning `TickBatchResult`. Frame drivers compute candidate ticks from their own clock.
- [x] Move clock/debt ownership to frame-driver contexts: `_update_local_match` in base mode, `_advance_runner` in replay mode, and demo/debug frame drivers (temporary harness path only until Stage 6 removal).
- [x] Remove `runner.clock` property and all external reads: `_gameplay_tick_rate()` reads `runner.clock.tick_rate` (line 1575), `_gameplay_tick_dt()` reads `runner.clock.dt_tick` (line 1581-1584), replay reads `runner.clock` (line 881-888).
- [x] Delete `reset_clock()` method and its caller `_reset_gameplay_tick_runner_clock()` (line 1587-1590).
- [x] Delete 3-layer pass-through: `_invoke_tick_runner_advance` (line 1543) → `_advance_tick_runner_with_profile` (line 1550) → `_advance_tick_runner` (line 1561). Each just calls the next with zero added behavior.
- [x] Remove clock accumulator mutation inside runner: `self._clock.accum += unconsumed_ticks * self._clock.dt_tick` (line 186).

### Evidence

- `src/crimson/sim/tick_runner.py:7` — `FixedStepClock` import
- `src/crimson/sim/tick_runner.py:76-78` — clock, tick index, frame index stored as mutable state
- `src/crimson/sim/tick_runner.py:80-82` — `clock` property exposing internal state
- `src/crimson/sim/tick_runner.py:88-89` — `reset_clock()` method
- `src/crimson/sim/tick_runner.py:99` — `self._clock.advance(dt_seconds)` internal mutation
- `src/crimson/sim/tick_runner.py:186` — accumulator restoration for unconsumed ticks
- `src/crimson/modes/base_gameplay_mode.py:1543-1570` — 3-layer pass-through chain
- `src/crimson/modes/base_gameplay_mode.py:1572-1590` — mode methods that read/reset runner clock
- `src/crimson/modes/replay_playback_mode.py:881-888` — replay directly accesses `runner.clock`

### Acceptance

- [x] `TickRunner` has zero mutable state (no clock, no tick index, no frame index).
- [x] `TickRunner` API takes explicit tick range, not `dt_seconds`.
- [x] Frame drivers own their own `FixedStepClock`.
- [x] No external code reads `runner.clock`.
- [x] No pass-through call chain remains.
- [x] Determinism parity and stall/debt tests pass.

---

## Stage 4: Close Correctness Gaps and Collapse LAN Scaffolding

### Tasks

- [x] Apply rollback resync snapshots to mode/runtime state. Current code decodes the snapshot (line 1272) but calls `mark_resync_applied` (line 1300) without actually applying the decoded state to the sim world.
- [x] Fix LAN stop-under-backlog: `_on_tick_applied` can return a stop action partway through a batch, but remaining batch ticks have already been simulated by the runner. This can leave runner-simulated state ahead of finalized/checkpointed state.
- [x] Collapse LAN scaffolding methods in `BaseGameplayMode`: `_prepare_lan_frame` (line 1813), `_allow_lan_frame_pop` (line 1826), `_after_join_lan_consume` (line 1829), `_on_lan_tick_applied` (line 1842) are thin delegation wrappers that mode subclasses override. Flatten into a single explicit tick-apply path.
- [x] Keep rollback snapshot/store orchestration explicit in frame-driver code; do not introduce `StateSnapshotHook` or new hook-bus abstractions.
- [x] Delete `sandbox_step.py` — duplicate module removed, code moved to `step_world_once` in `world_tick_runner_harness.py`. Full migration of test callers to `TickRunner` + batch-apply is Stage 6 scope.
- [x] Deduplicate `SandboxWorldHost` (sandbox_step.py:15) and `WorldTickRunnerHost` (world_tick_runner_harness.py:18) — collapsed into single `WorldHost` protocol.

### Evidence

- `src/crimson/modes/base_gameplay_mode.py:1285-1300` — decode + `mark_resync_applied` without state apply
- `src/crimson/modes/base_gameplay_mode.py:2017-2055` — `_consume_lan_tick_frames` applies batch then checks stop
- `src/crimson/modes/base_gameplay_mode.py:1813-1855` — LAN scaffolding methods
- `src/crimson/sim/sandbox_step.py:15-95` — duplicate `SandboxWorldHost` + parallel stepping path
- `src/crimson/sim/world_tick_runner_harness.py:18` — duplicate `WorldTickRunnerHost`
- `tests/test_camera_shake.py`, `tests/test_bonus_pickup_fx.py`, `tests/test_game_world_audio.py` — `run_sandbox_world_step` callers
- `tests/world_runtime.py` — `SandboxWorldHost` implementor

### Acceptance

- [x] Recovery snapshots have observable state-application behavior.
- [x] Stop action under LAN backlog does not leave divergent runner/checkpoint state.
- [x] No new hook/snapshot orchestration layer is introduced in LAN paths.
- [x] Only one world host protocol exists.
- [x] `sandbox_step.py` deleted; callers migrated.
- [x] LAN scaffolding methods collapsed.

---

## Stage 5: Runtime-First Test Suite Cleanup

### Tasks

- [x] Remove `inspect.stack()`-based architecture assertion in `test_architecture_contracts.py:48`. This asserts internal call-chain shape and breaks on any refactor.
- [x] Review `test_architecture_contracts.py` broadly — decide which behavioral invariants to keep vs. which are incidental wiring checks that should be deleted.
- [x] Reduce mock-heavy tests in `test_runtime_pump_ownership.py` (line 91+) — currently simulates LAN with heavy mocking instead of runtime types.
- [x] Keep only behaviorally meaningful assertions (observable state/telemetry), not internal call-chain shape.
- [x] Fix stale ast-grep guardrail: `tools/ast-grep/rules/no-gameplay-rng-out-of-band.yml:6` references deleted `src/crimson/game_world.py`.
- [x] Align test assertions with new contracts after Stages 1-3 land (`InputStatus`, pure runner, no hook bus).

### Evidence

- `tests/test_architecture_contracts.py:48` — `inspect.stack()` frame inspection
- `tests/test_runtime_pump_ownership.py:91` — mock-heavy LAN runner simulation
- `tools/ast-grep/rules/no-gameplay-rng-out-of-band.yml:6` — references `src/crimson/game_world.py`

### Acceptance

- [x] Zero `inspect.stack` assertions in test suite.
- [x] Runtime orchestration tests use real types where possible.
- [x] Guardrail rules reference only existing files.
- [x] `uv run pytest --no-cov` passes.

---

## Stage 6: Collapse World Facades and Host Duplication

World is currently 4 peer components (`SimWorldState`, `RenderResources`,
`AudioBridge`, `TerrainRuntime`). Plan end-state is 2: `SimWorldState` +
`PresentationLayer`. Four separate files implement the identical
`WorldTickRunnerHost` / `SandboxWorldHost` protocol with near-identical
init/sync/camera patterns. Deterministic tick-apply logic is also duplicated
across gameplay mode, replay mode, and harness paths.

### Tasks

- [x] Introduce a shared `WorldRuntime` composition container (`sim`, `render`, `audio`, `terrain`) to eliminate duplicated world init/reset/open/close/sync across demo/debug/tests.
- [x] Extract one shared concrete world host lifecycle from duplicate implementations in `demo.py`, `arsenal_debug.py`, `lighting_debug.py`, and `tests/world_runtime.py`.
- [x] Collapse `RenderResources` + `AudioBridge` + `TerrainRuntime` into `PresentationLayer` with one-way dependency from presentation to sim.
- [x] Demote `TerrainRuntime` from peer component to bootstrap/helper utility. Remove it from `world/__init__.py` exports.
- [x] Remove `WorldTickRunnerHarness` — tick-stepping logic absorbed into `WorldRuntime`.
- [x] Migrate `ReplayPlaybackMode` world lifecycle to `WorldRuntime` — eliminates duplicated component fields and lifecycle methods.
- [x] Add shared deterministic batch apply helper that separates sim metadata from audio/camera side effects.
- [x] Refactor `BaseGameplayMode` stepping path to use shared batch apply; remove duplicated per-context apply loops.
- [x] Move presentation/audio apply and camera updates to frame-driver output boundary for each context (interactive gameplay, replay playback, headless verify).

### Evidence

- `src/crimson/world/__init__.py` — exports `SimWorldState` + `PresentationLayer` + `WorldRuntime`
- `src/crimson/world/runtime.py` — shared `WorldRuntime` composition container with tick-stepping
- `src/crimson/sim/batch_apply.py` — shared deterministic batch metadata helper + presentation output apply helper
- `src/crimson/world/presentation.py` — `PresentationLayer` composing render + audio + terrain
- `src/crimson/demo.py` — delegates to `WorldRuntime`
- `src/crimson/views/arsenal_debug.py` — delegates to `WorldRuntime`
- `src/crimson/views/lighting_debug.py` — delegates to `WorldRuntime`
- `tests/world_runtime.py` — delegates to `WorldRuntime`
- `src/crimson/modes/replay_playback_mode.py` — world lifecycle delegates to `WorldRuntime`; tick-stepping remains replay-specific (PlaybackDriver)
- `src/crimson/modes/base_gameplay_mode.py:2026-2099` — mode-specific batch apply loop (not yet migrated)
- `src/crimson/sim/world_tick_runner_harness.py` — `WorldHost` protocol + `step_world_once` (harness class removed)

### Acceptance

- [x] World composition end-state is `SimWorldState` + `PresentationLayer`.
- [x] `TerrainRuntime` not exported as a peer in `world/__init__.py`.
- [x] Shared deterministic batch apply path is used across gameplay/replay/debug stepping contexts.
- [x] Deterministic batch apply performs no per-tick audio/camera side effects.
- [x] Frame drivers own output-phase presentation apply in strict tick order.
- [x] Host lifecycle exists in one shared implementation, not four copies.
- [x] `WorldTickRunnerHarness` removed or fully subsumed with no unique orchestration behavior.
- [x] Replay stepping path in `ReplayPlaybackMode` uses `WorldRuntime` for lifecycle; tick-stepping remains PlaybackDriver-specific by design.
- [x] Debug views and test host use shared composition.

---

## Prioritization

1. Stage 2 (InputStatus + Journal contract)
2. Stage 3 (pure runner + frame-owned debt)
3. Stage 4 (LAN/recovery correctness + scaffold collapse)
4. Stage 5 (runtime-first tests + guardrail cleanup)
5. Stage 6 (world collapse + host dedupe)

This order minimizes risk: first remove hidden orchestration indirection, then
lock contracts, then move time/debt ownership, then finish correctness and
cleanup.
