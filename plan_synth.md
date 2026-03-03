# PRD: Main Loop Orchestration Refactor (Python Runtime)

## Document Control

- Status: Draft for implementation
- Audience: implementer of gameplay/runtime architecture
- Primary codebase scope: `src/crimson` Python runtime
- Source synthesis: `plan_codex.md`, `plan_gem.md`, `plan_claude.md`, `plan.md`

## Problem Statement

The deterministic kernel is strong, but orchestration around it is tangled. The current runtime has split ownership and duplicate control paths that make composability hard.

Concrete issues:

1. Network runtime is pumped in multiple layers.
- `GameLoopView._tick_network_runtime()` calls `runtime.update()`.
- Modes also call `runtime.update()` in LAN paths.
- Evidence: `src/crimson/game/loop_view.py`, `src/crimson/modes/survival_mode.py`, `src/crimson/modes/rush_mode.py`, `src/crimson/modes/quest_mode.py`.

2. Input ownership is split.
- Frame-latched input pipeline exists (`input_begin_frame()`), but raw raylib polling still drives mode logic.
- Evidence: `src/crimson/input_codes.py`, `src/crimson/game/loop_view.py`, mode files.

3. Deterministic stepping orchestration is duplicated.
- Base mode has `_run_deterministic_session_ticks`.
- Replay mode uses a different stepping path.
- Quest has bespoke loops.
- Evidence: `src/crimson/modes/base_gameplay_mode.py`, `src/crimson/modes/replay_playback_mode.py`, `src/crimson/modes/quest_mode.py`.

4. Presentation planning and output-side effects are fused.
- `run_deterministic_step` invokes `apply_world_presentation_step`, coupling planning and side effects.
- Evidence: `src/crimson/sim/step_pipeline.py`, `src/crimson/sim/presentation_step.py`.

5. Rendering is hardwired to raylib/global state.
- Global `rl` usage and telemetry monkeypatching block backend portability.
- Evidence: `src/grim/raylib_api.py`, `src/crimson/sim/driver/render_telemetry.py`.

6. `GameWorld` carries too many roles.
- Sim state + rendering resources + audio bridge + terrain lifecycle are bundled.
- Evidence: `src/crimson/game_world.py`.

## Goals

1. Make input source pluggable (`local`, `replay`, `network`) behind one contract.
2. Make deterministic tick orchestration single-path and mode-agnostic.
3. Keep deterministic contracts intact (RNG, hashes, replay parity).
4. Separate presentation planning from side-effectful application.
5. Make rendering destination pluggable (`window`, `video`, `headless`).
6. Remove duplicated LAN orchestration and replay parallel-universe logic.
7. Reduce mode classes to composition/configuration, not orchestration hosts.

## Non-Goals

1. No redesign of gameplay rules or deterministic world math.
2. No visual redesign of HUD/effects.
3. No netcode protocol redesign beyond boundary cleanup.
4. No immediate backend replacement for raylib; only abstraction boundary.

## Hard Invariants

1. Exactly one `RuntimePumpOwner` is responsible for `runtime.update()` in each execution context where a runtime exists.
2. `InputProvider` implementations never call `runtime.update()` directly.
3. `InputProvider` implementations may read external hardware/replay streams and pre-updated runtime queues only.
4. `TickRunner` is the only owner of fixed-step deterministic advancement.
5. Presentation planning is deterministic and side-effect free with respect to renderer/window I/O.
6. Headless/replay verify still runs presentation planning for RNG parity, but may skip output application.
7. Mode classes do not call raw net runtime methods except through adapters.

## Runtime Pump Ownership Matrix

Authoritative ownership by execution context:

| Context | Runtime Present | RuntimePumpOwner | Notes |
|---|---|---|---|
| Interactive gameplay (menu + survival/rush/quest) | Sometimes | `GameLoopView` frame loop | If runtime is active, pump once per frame in loop layer. |
| Replay playback (interactive) | Usually no | `ReplayPlaybackMode` frame driver if runtime exists, otherwise none | Default replay playback has no net runtime pump. |
| Headless replay verify/benchmark | No | none | No runtime pump unless a dedicated runtime-backed verify mode is explicitly introduced. |
| Dedicated net/headless session runner (future) | Yes | that runner's frame/tick loop | Must still satisfy one-owner invariant. |

## Closed Design Decisions

1. Runtime pump authority:
- Context-specific `FrameDriver` is authoritative (`GameLoopView` for interactive gameplay, replay/headless runner for its own context when runtime exists).

2. Input pull semantics:
- `None` means stall-only and is valid only for network provider.
- Replay EOS is explicit EOS signaling (exception or explicit result type), never `None`.
- `[]` is invalid unless `player_count == 0`.

3. Determinism artifacts:
- Canonical artifacts are per-tick `command_hash`, per-tick `state_hash` (where enabled), checkpoint hashes, and terminal summary fields.

4. Render contract minimum:
- Backend owns GPU lifecycle and draw execution.
- Sink owns destination transport lifecycle and failure policy.
- Frame pacing ownership stays in frame loop.

5. Performance gates:
- Numeric thresholds are baseline-relative and benchmark-defined under NFR performance.

## Functional Requirements

### FR-1: Input Boundary

Introduce protocol:

```python
class InputProvider(Protocol):
    def begin_frame(self, frame_ctx: FrameContext) -> None: ...
    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None: ...
    def push_command(self, command: InputCommand) -> None: ...
```

Requirements:
- `pull_tick_input(...) -> None` means "tick input not ready yet (stall)" and is only valid for network-backed providers.
- Local provider handles edge semantics consistently for multi-tick frames and must never stall.
- Replay provider returns recorded tick inputs deterministically and must never use `None` for end-of-stream.
- Network provider merges local + remote per tick and surfaces stall explicitly.

Provider semantic matrix:

| Provider | `None` allowed | End-of-stream behavior | Empty input list `[]` |
|---|---|---|---|
| `LocalInputProvider` | No | Not applicable | Invalid unless `player_count == 0` |
| `ReplayInputProvider` | No | Raise `ReplayEndOfStream` (or return explicit EOS result type) | Invalid unless replay explicitly encodes zero players |
| `NetworkInputProvider` | Yes | Not applicable | Invalid unless `player_count == 0` |

`TickRunner` must treat `None` as stall-only, never as EOS.

### FR-2: TickRunner

Create standalone runner (not inheritance mixin) that owns `FixedStepClock` and orchestrates per-tick stages.

Proposed location:
- `src/crimson/sim/tick_runner.py`

Required per-tick stage order:
1. `on_tick_begin`
2. `InputNormalize` (fetch and normalize tick input)
3. `on_pre_sim`
4. `WorldSim` (`session.step_tick(...)`)
5. `on_world_step_done`
6. `PresentationPlan` (deterministic planning only)
7. `on_pre_hash`
8. `IntegrityHash`
9. `on_post_hash`
10. `on_post_presentation`
11. `Emit` + `on_tick_end`

Stall behavior:
- If input provider returns `None`, stop advancing remaining ticks for this frame and return `stalled=True` in batch result.
- Already-completed ticks in the current frame remain committed; no rollback is implied by stall.
- Unconsumed fixed-step debt remains in the clock accumulator and is retried next frame.
- `TickBatchResult` must expose `ticks_completed`, `stalled`, and `remaining_debt_ticks` (or equivalent fields).

### FR-3: Hook Bus

Introduce hook protocol:

```python
class TickHook(Protocol):
    def on_tick_begin(self, ctx: TickContext) -> None: ...
    def on_pre_sim(self, ctx: TickContext) -> None: ...
    def on_world_step_done(self, ctx: TickContext, result: StepResult) -> None: ...
    def on_pre_hash(self, ctx: TickContext, result: TickResult) -> None: ...
    def on_post_hash(self, ctx: TickContext, hashes: TickHashes) -> None: ...
    def on_post_presentation(self, ctx: TickContext, result: TickResult) -> None: ...
    def on_tick_end(self, ctx: TickContext, result: TickResult) -> None: ...
```

Required `TickContext` minimum fields:
- `tick_index`
- `dt_seconds`
- `inputs` (normalized)
- `session_kind`
- `mode_id`
- `is_networked`
- `is_replay`

Required `TickHashes` minimum fields:
- `command_hash` (canonical deterministic command stream hash)
- `state_hash` (if enabled/available; otherwise explicit null marker)

Required hook implementations:
- ReplayRecorderHook
- CheckpointHook
- NetworkSyncHook
- ProfilerHook
- Optional telemetry/export hook

### FR-4: Presentation Split (Plan vs Apply)

Current behavior in `apply_world_presentation_step` is split into:
- `plan_world_presentation_step` (deterministic command plan)
- `apply_presentation_plan` (output side effects)

Requirements:
- Plan stage runs inside deterministic tick path.
- Apply stage runs in output/render phase and may be skipped for headless.
- Command hash and replay parity must remain stable after refactor.
- Planning stage remains part of authoritative deterministic contract for RNG consumption.

### FR-5: Render Abstraction

Introduce two seams:

1. `RenderBackend` (draw API abstraction)
2. `RenderSink` (frame destination)

Minimum sinks:
- `WindowSink`
- `VideoSink`
- `NullSink`

Requirements:
- Same render pass logic feeds window and video.
- Replay render path reuses shared draw pipeline, not a bespoke one.
- `RenderBackend` owns GPU resource lifecycle (`open`, `resize`, `close`) and draw command execution.
- `RenderSink` owns destination/transport lifecycle (`open`, `present`, `flush`, `close`).
- Frame pacing ownership is outside backend/sink (owned by frame loop / runner context).
- Sink failure policy must be explicit:
- `WindowSink`: log + continue unless unrecoverable backend failure.
- `VideoSink`: fail-fast and surface non-zero/export error.
- `NullSink`: always succeed/no-op.

### FR-6: `GameWorld` Decomposition

Split `GameWorld` responsibilities into explicit components:
- `SimWorldState`: deterministic state and step-result application data
- `RenderResources`: textures/shaders/render objects and lifecycle
- `AudioBridge`: audio routing and presentation-audio application
- `TerrainRuntime`: terrain bootstrap/runtime state transitions

Requirements:
- One-way dependency: render/audio consume sim state; sim does not depend on GPU resources.
- Keep a temporary compatibility facade if needed during migration.

### FR-7: Replay Path Unification

`ReplayPlaybackMode` must use the same `TickRunner` orchestration path as gameplay modes.

Requirements:
- Replay-specific behavior lives in provider/hook/sink adapters.
- Remove replay-specific duplicate stepping glue from mode update loop.

### FR-8: Event-Driven UI Commands

Perk selection and similar UI outcomes must enter sim via input commands.

Flow:
1. Tick result surfaces pending UI state (example: perk selection).
2. UI opens and collects choice.
3. Choice is translated to `InputCommand` (example: `PerkPickCommand`).
4. Command is pushed into provider queue.
5. Next deterministic tick consumes command as regular input.

## Non-Functional Requirements

1. Determinism
- Golden replay checkpoint/hash parity must hold across phases.

2. Performance
- Benchmark environment is \"same machine, same build, same replay fixture\" and compares median of 5 runs.
- Headless replay throughput (`uv run crimson replay benchmark <replay> --mode headless`) must be >= 95% of baseline ticks/sec.
- Render replay throughput (`uv run crimson replay benchmark <replay> --mode render`) must be >= 90% of baseline ticks/sec.
- Interactive frame pacing p95 frame time must not regress by more than +1.5 ms versus baseline capture on the same scenario.

3. Observability
- Must expose counters: `runtime_updates_per_frame`, `input_stall_count`, `ticks_advanced_per_frame`.
- Must expose stage timing: `sim_ms`, `presentation_plan_ms`, `presentation_apply_ms`.

## Concrete End Shape

### Final Runtime Shape

`FrameDriver` (context-specific frame owner)
- calls `input_provider.begin_frame(...)`
- pumps runtime exactly once if runtime exists for the current context
- calls `tick_runner.advance_frame(dt)`
- sends `PresentationPlan` + world snapshot to render backend/sink

`GameLoopView` is the `FrameDriver` for interactive gameplay contexts.
`ReplayPlaybackMode` / replay runners are frame drivers for replay contexts.

`Mode` classes
- assemble components only (session, providers, hooks, sinks)
- no custom tick loop logic
- no raw runtime/net pumping

`TickRunner`
- single deterministic orchestrator for survival/rush/quest/replay

`ReplayPlaybackMode`
- same tick runner path, replay provider + replay hooks + chosen sink

### Expected Collapses / Cleanups

The following logic must be collapsed into shared components:

1. `BaseGameplayMode._run_deterministic_session_ticks`
- collapsed into `TickRunner`

2. `_update_lan_match` in:
- `src/crimson/modes/survival_mode.py`
- `src/crimson/modes/rush_mode.py`
- `src/crimson/modes/quest_mode.py`
- collapsed into shared network provider + network hook flow

3. Mode-owned fixed clocks (`_sim_clock`, `_lan_capture_clock`)
- moved under `TickRunner`/network adapter ownership

4. Duplicate `runtime.update()` calls in modes
- removed; only context-specific `FrameDriver` owner remains

5. Replay-specific custom stepping in `ReplayPlaybackMode`
- collapsed to standard `TickRunner` + `ReplayInputProvider`

6. `GameWorld` mixed responsibilities
- split into `SimWorldState`, `RenderResources`, `AudioBridge`, `TerrainRuntime`

7. Presentation side-effect coupling
- split plan/apply; apply becomes output-layer concern

### Expected Deletions (End-State)

After migration stabilizes, these should be deleted or reduced to thin adapters:

- bespoke mode LAN loops
- bespoke replay stepping loop
- mode-local net pumping paths
- duplicated checkpoint/record wiring inside mode update methods

## Implementation Plan (PR Slices)

### PR-0: Safety Nets and Instrumentation

Changes:
- Add counters/assertions for duplicate runtime pumping and stalls.
- Add stage timing scaffolding for future hook timing.

Primary files:
- `src/crimson/game/loop_view.py`
- `src/crimson/modes/survival_mode.py`
- `src/crimson/modes/rush_mode.py`
- `src/crimson/modes/quest_mode.py`
- `src/crimson/logging.py` (or equivalent telemetry surface)

Exit criteria:
- Existing behavior unchanged.
- Counters visible in debug/telemetry logs.

### PR-1: Interfaces and Adapters (No Behavior Change)

Changes:
- Add protocols for `InputProvider`, `TickHook`, `RenderBackend`, `RenderSink`.
- Add local adapter implementations wrapping existing logic.

Primary files:
- `src/crimson/sim/tick_runner.py` (interfaces + placeholder runner)
- `src/crimson/sim/input_providers.py`
- `src/crimson/sim/hooks.py`
- `src/crimson/render/backend.py`
- `src/crimson/render/sink.py`

Exit criteria:
- Adapters compile and tests pass; old call paths still primary.

### PR-2: Single Network Owner

Changes:
- Enforce context-specific single-owner `runtime.update()` with `GameLoopView` as owner for interactive gameplay contexts.
- Remove/disable mode-local duplicate updates.

Primary files:
- `src/crimson/game/loop_view.py`
- `src/crimson/modes/survival_mode.py`
- `src/crimson/modes/rush_mode.py`
- `src/crimson/modes/quest_mode.py`

Exit criteria:
- LAN lockstep/rollback smoke tests pass.
- Assertion proves one runtime pump per frame.

### PR-3: TickRunner Extraction

Changes:
- Move shared deterministic stepping out of base mode into `TickRunner`.
- Survival/Rush/Quest delegate to runner.

Primary files:
- `src/crimson/sim/tick_runner.py`
- `src/crimson/modes/base_gameplay_mode.py`
- `src/crimson/modes/survival_mode.py`
- `src/crimson/modes/rush_mode.py`
- `src/crimson/modes/quest_mode.py`

Exit criteria:
- Survival/Rush/Quest use one orchestrator entrypoint.

### PR-4: Hook Bus Migration

Changes:
- Move replay recording/checkpoint/network hash hooks from mode update paths into hook implementations.

Primary files:
- `src/crimson/sim/hooks.py`
- `src/crimson/replay/recorder.py`
- `src/crimson/net/adapter.py`
- mode files where inline logic is removed

Exit criteria:
- Hook-based observability and recording parity with previous output.

### PR-5: Replay Path Unification

Changes:
- Introduce `ReplayInputProvider` and run replay mode through shared `TickRunner`.

Primary files:
- `src/crimson/modes/replay_playback_mode.py`
- `src/crimson/sim/driver/playback_driver.py`
- `src/crimson/sim/input_providers.py`

Exit criteria:
- Replay playback no longer maintains a custom stepping loop.

### PR-6: Presentation Plan/Apply Split

Changes:
- Split presentation planning and side-effect apply.
- Keep planning inside deterministic tick, apply in render/output layer.

Primary files:
- `src/crimson/sim/step_pipeline.py`
- `src/crimson/sim/presentation_step.py`
- `src/crimson/game_world.py`

Exit criteria:
- Golden replay parity preserved.
- Headless verify plans presentation but skips apply safely.

### PR-7: Render Backend/Sink + Video Path

Changes:
- Use `RenderBackend` and `RenderSink` in live and replay render paths.
- Move replay video output to `VideoSink`.

Primary files:
- `src/crimson/render/backend.py`
- `src/crimson/render/sink.py`
- `src/crimson/sim/driver/replay_render.py`
- `src/crimson/game/loop_view.py`

Exit criteria:
- Same draw path supports window and video destinations.

### PR-8: `GameWorld` Split and Final Cleanup

Changes:
- Extract `SimWorldState`, `RenderResources`, `AudioBridge`, `TerrainRuntime`.
- Remove temporary facades and dead orchestration paths.

Primary files:
- `src/crimson/game_world.py` (split/compat removed)
- new component modules under `src/crimson/` (or `src/crimson/world/`)

Exit criteria:
- End-state architecture achieved.
- No duplicate orchestration paths remain.

## Acceptance Criteria

### Functional

1. Local gameplay works in Survival/Rush/Quest with unchanged behavior.
2. Replay playback and replay verify are deterministic and unchanged in outcomes.
3. Lockstep and rollback sessions function with no duplicate runtime pumping.
4. Video rendering path uses shared render pipeline.

### Determinism

Canonical parity artifacts:

1. Per-tick `command_hash` (authoritative).
2. Per-tick `state_hash` where enabled (or explicit null marker where not enabled).
3. Checkpoint hash rows produced by replay/checkpoint pipeline.
4. Final replay/session terminal summary fields (tick_count, score/status tuple).

Pass criteria:

1. Golden replay checkpoints match baseline for all sampled ticks.
2. `command_hash` matches baseline for all ticks in deterministic parity fixtures.
3. `state_hash` behavior is unchanged where currently produced; if newly introduced, migration notes must document expected deltas.
4. No first-bad-tick in parity runner outputs for the gated replay fixture set.

### Observability

1. Stall counters and runtime update counters are emitted.
2. Hook stage timings are emitted.

## Test Gates

Run at minimum after each PR phase:

```bash
uv run pytest \
  tests/test_step_pipeline_parity.py \
  tests/test_presentation_step.py \
  tests/test_local_input.py \
  tests/test_quest_deterministic_session.py \
  tests/test_replay_runners_survival.py \
  tests/test_replay_runners_rush.py \
  tests/test_replay_runners_quest.py \
  tests/test_replay_playback_mode_audio.py \
  tests/test_replay_playback_mode_timing.py \
  tests/test_lan_lockstep_host.py \
  tests/test_lan_lockstep_client.py \
  tests/test_net_runtime_rollback.py \
  tests/test_rollback_core.py \
  tests/test_rollback_resync_v5.py
```

Performance gate commands (same machine baseline comparison):

```bash
uv run crimson replay benchmark <replay.crd> --mode headless
uv run crimson replay benchmark <replay.crd> --mode render
```

Determinism gate commands (artifact parity checks):

```bash
uv run crimson replay verify-checkpoints <replay.crd>
uv run crimson replay diff-checkpoints <expected> <actual>
```

Required new invariant-focused tests (add during refactor):

- `tests/test_runtime_pump_ownership.py`
- asserts exactly one runtime pump owner in each execution context.
- `tests/test_input_provider_semantics.py`
- validates local/replay/network semantics for stall (`None`), EOS, and empty-input handling.
- `tests/test_tick_runner_hook_order.py`
- validates hook order and visibility of pre/post hash data.
- `tests/test_tick_runner_stall_debt.py`
- validates mid-frame stall preserves clock debt and commits only completed ticks.
- `tests/test_render_backend_sink_contract.py`
- validates lifecycle, resize, and sink failure behavior contracts.

## Detailed Execution Checklist

Use this as the implementation punch-list. Do not start the next PR until all items in the current PR block are done.

### PR-0 Checklist: Safety Nets and Instrumentation

- [ ] Add `runtime_updates_per_frame` counter at each context `FrameDriver` owner and reset/report each frame/tick.
- [ ] Add assertion/log when runtime pump count is not exactly 1 per frame in LAN mode.
- [ ] Add `input_stall_count` and `ticks_advanced_per_frame` counters to runtime telemetry/debug output.
- [ ] Add stage timer scaffolding fields (`sim_ms`, `presentation_plan_ms`, `presentation_apply_ms`) with placeholder values.
- [ ] Add `tests/test_runtime_pump_ownership.py` covering interactive/replay/headless contexts.
- [ ] Run `uv run pytest` with the full test gate suite.

### PR-1 Checklist: Interfaces and Adapters (No Behavior Change)

- [ ] Create `src/crimson/sim/input_providers.py` with `InputProvider` protocol.
- [ ] Create `src/crimson/sim/hooks.py` with `TickHook` protocol and no-op hook bus.
- [ ] Create `src/crimson/render/backend.py` with `RenderBackend` protocol.
- [ ] Create `src/crimson/render/sink.py` with `RenderSink` protocol.
- [ ] Add adapter stubs: `LocalInputProvider`, `ReplayInputProvider` (placeholder), `NetworkInputProvider` (placeholder), `WindowSink`, `NullSink`.
- [ ] Wire zero-impact construction paths (adapters instantiated but not yet primary control path).
- [ ] Add `tests/test_input_provider_semantics.py` for stall/EOS/empty-input contracts.
- [ ] Add `tests/test_tick_runner_hook_order.py` skeleton validating stage order contracts.
- [ ] Confirm no behavior change in gameplay/replay entrypoints.
- [ ] Run full test gate suite.

### PR-2 Checklist: Single Network Owner

- [ ] Keep `runtime.update()` in `GameLoopView._tick_network_runtime()` as the only authoritative pump for interactive gameplay contexts.
- [ ] Define replay/headless runtime pump owner behavior explicitly (none by default unless runtime is configured).
- [ ] Remove direct `runtime.update()` calls from:
- [ ] `src/crimson/modes/survival_mode.py`
- [ ] `src/crimson/modes/rush_mode.py`
- [ ] `src/crimson/modes/quest_mode.py`
- [ ] Add regression assertion that mode update paths do not pump runtime.
- [ ] Validate lockstep and rollback host/client flows with tests.
- [ ] Run full test gate suite.

### PR-3 Checklist: TickRunner Extraction

- [ ] Implement `TickRunner` in `src/crimson/sim/tick_runner.py` using `FixedStepClock`.
- [ ] Move shared logic from `BaseGameplayMode._run_deterministic_session_ticks` into `TickRunner`.
- [ ] Delegate Survival/Rush/Quest mode tick advancement to `TickRunner`.
- [ ] Keep output behavior identical (same tick counts and apply ordering).
- [ ] Delete or reduce `_run_deterministic_session_ticks` to thin wrapper/shim.
- [ ] Run full test gate suite.

### PR-4 Checklist: Hook Bus Migration

- [ ] Implement concrete hooks: replay recording, checkpoint capture, profiling timing, net hash sync.
- [ ] Move inline replay/checkpoint wiring out of mode update paths into hooks.
- [ ] Ensure hook order matches required stage boundaries (pre-sim, post-sim, post-presentation, end).
- [ ] Emit hook timing metrics in telemetry output.
- [ ] Run full test gate suite.

### PR-5 Checklist: Replay Path Unification

- [ ] Implement `ReplayInputProvider` against replay playback driver input stream.
- [ ] Make `ReplayPlaybackMode` use `TickRunner` for deterministic stepping.
- [ ] Remove bespoke replay stepping/orchestration loop from `ReplayPlaybackMode`.
- [ ] Keep replay controls (pause/step/speed) mapped through provider/runner boundaries.
- [ ] Run replay-specific tests plus full test gate suite.

### PR-6 Checklist: Presentation Plan/Apply Split

- [ ] Extract deterministic `plan_world_presentation_step(...)` from current presentation path.
- [ ] Extract side-effectful `apply_presentation_plan(...)` for audio/visual/output application.
- [ ] Ensure planning runs inside tick flow in live, replay, and headless verify modes.
- [ ] Ensure apply runs only in output/render phase and can be skipped in headless.
- [ ] Add/enable `tests/test_tick_runner_stall_debt.py` and determinism artifact assertions around hash/checkpoint parity.
- [ ] Keep command hash/checkpoint parity with baseline golden replays.
- [ ] Run full test gate suite.

### PR-7 Checklist: Render Backend and Sink Migration

- [ ] Implement `RaylibBackend` adapter wrapping current raylib draw operations.
- [ ] Implement `VideoSink` and migrate replay render output path to it.
- [ ] Route live and replay rendering through shared backend + sink entrypoint.
- [ ] Keep `WindowSink` as default interactive target.
- [ ] Keep `NullSink` for headless benchmark/verify.
- [ ] Add `tests/test_render_backend_sink_contract.py` for lifecycle/resize/error-policy behavior.
- [ ] Run replay render and replay benchmark smoke checks.
- [ ] Run full test gate suite.

### PR-8 Checklist: `GameWorld` Split and Final Cleanup

- [ ] Introduce `SimWorldState`, `RenderResources`, `AudioBridge`, `TerrainRuntime` modules.
- [ ] Move GPU lifecycle and render resources out of `GameWorld`.
- [ ] Move audio routing/state out of `GameWorld`.
- [ ] Keep temporary compatibility facade only if needed for transitional call-sites.
- [ ] Remove compatibility shims once all call-sites migrated.
- [ ] Remove collapsed legacy paths:
- [ ] per-mode LAN orchestration duplication (`_update_lan_match` variants)
- [ ] mode-local runtime pumping
- [ ] replay bespoke stepping loop
- [ ] duplicated checkpoint/record code in mode update methods
- [ ] Run full test gate suite.

### Final Merge Checklist

- [ ] Architecture matches \"Concrete End Shape\" exactly.
- [ ] No duplicate orchestration paths remain.
- [ ] All acceptance criteria in this PRD are met.
- [ ] `plan_synth.md` remains the single source of truth for loop architecture refactor.

## Risks and Mitigations

1. Determinism drift during presentation split.
- Mitigation: golden replay parity gates per PR.

2. Silent lockstep stalls from provider returning `None`.
- Mitigation: explicit stall metrics + watchdog assertions.

3. `GameWorld` split causes broad API churn.
- Mitigation: temporary compatibility facade and subsystem-by-subsystem migration.

4. Large refactor blast radius.
- Mitigation: strict PR slice boundaries and behavior-preserving intermediate states.

## Scope Guardrails

Do not refactor deterministic gameplay math unless parity tests prove a bug.

Treat these as stable unless failing tests demand change:
- `run_deterministic_step` core semantics
- session `step_tick` contracts
- `FixedStepClock` semantics
- `PlayerInput` / `InputFrame` contracts
