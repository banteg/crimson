# PRD: Main Loop Orchestration Simplification (Python Runtime)

## Document Control

- Status: Approved for implementation
- Last updated: 2026-03-04
- Audience: implementer of gameplay/runtime architecture
- Primary codebase scope: `src/crimson` Python runtime
- Source synthesis: consolidated from prior refactor drafts and review notes

## Problem Statement

The deterministic kernel is strong, but orchestration around it is still overly layered.

Concrete issues:

1. Runtime ownership is split across layers.
- Runtime pumping has historically existed in both frame loop and mode-local/network paths.

2. Input ownership is split.
- Frame-latched input exists, but different control-flow conventions (`None`, exceptions, implicit queues) are mixed.

3. Deterministic stepping orchestration is duplicated.
- Shared stepping logic is partially centralized, but orchestration remains distributed across mode and replay paths.

4. Presentation planning and output application are still not fully isolated at boundaries.

5. Rendering abstraction has extra wrapper/facade layers without clear behavioral value.

6. World decomposition still contains compatibility-oriented facades that increase lifecycle complexity.

## Goals

1. Make input source pluggable (`local`, `replay`, `network`) behind one explicit contract.
2. Keep deterministic tick orchestration single-path and mode-agnostic.
3. Preserve deterministic contracts (RNG stream, command hashes, replay parity).
4. Keep presentation planning deterministic and separate from output application.
5. Keep render destination pluggable (`window`, `video`, `headless`).
6. Remove duplicated LAN/replay orchestration and implicit hook indirection.
7. Reduce mode classes to composition/configuration instead of orchestration hosts.
8. Collapse world architecture to meaningful components only.

## Non-Goals

1. No redesign of gameplay rules or deterministic world math.
2. No visual redesign of HUD/effects.
3. No netcode protocol redesign beyond boundary cleanup.
4. No immediate renderer backend replacement beyond boundary enforcement.

## Hard Invariants

1. `GameLoopView` is the authoritative owner of `runtime.update()` for interactive gameplay contexts.
2. Replay playback/verify contexts are local-only and do not own a network runtime.
3. Input control flow uses explicit status (`READY`, `STALLED`, `EOS`); no `None`/exception signaling for normal control flow.
4. `TickRunner` is pure/stateless: it does not own fixed-step debt accumulation and does not own hook-bus dispatch.
5. Presentation planning is deterministic, consumes the same RNG stream, and is side-effect free with respect to I/O.
6. Headless/replay-verify may skip presentation apply, but must execute deterministic planning so RNG consumption stays identical.
7. Mode classes assemble components and policies only; they do not call raw network runtime methods.

## Runtime Pump Ownership Matrix

| Context | Runtime Present | RuntimePumpOwner | Notes |
|---|---|---|---|
| Interactive gameplay (menu + survival/rush/quest) | Sometimes | `GameLoopView` frame loop | Pump exactly once per frame when runtime exists. |
| Replay playback (interactive) | No | N/A | Replay is local-only. |
| Headless replay verify/benchmark | No | N/A | Replay is local-only. |
| Dedicated network runner (future, if added) | Yes | That runner's frame loop | Must still satisfy one-owner invariant. |

## Closed Design Decisions

1. Runtime pump authority is `GameLoopView` for interactive gameplay.
2. Replay is always local and never attaches a network runtime.
3. `TickRunner` is pure/stateless; fixed-step debt is owned by frame-driver context.
4. Hook bus is not an end-state architecture primitive.
5. Input status is standardized (`InputStatus`) across providers.
6. `ReplayInputProvider` remains, but only as a thin adapter over `Journal` read APIs.
7. Headless verify skips presentation apply.
8. World architecture end-state is `SimWorldState` + `PresentationLayer`.
9. `NullSink` remains the headless sink contract.

## Functional Requirements

### FR-1: Input Boundary

Introduce explicit status-based input contract:

```python
class InputStatus(Enum):
    READY = "ready"
    STALLED = "stalled"
    EOS = "eos"

@dataclass
class TickInput:
    status: InputStatus
    inputs: list[PlayerInput]

class InputProvider(Protocol):
    def begin_frame(self, frame_ctx: FrameContext) -> None: ...
    def pull_tick_input(self, tick_index: int) -> TickInput: ...
    def pull_tick_commands(self, tick_index: int) -> list[InputCommand]: ...
    def push_command(self, command: InputCommand) -> None: ...
```

Requirements:
- Replace `None`-based stalls and exception-driven EOS with `InputStatus`.
- Local provider always returns `READY`.
- Network provider may return `STALLED`.
- Replay provider returns `EOS` when Journal read stream is exhausted.
- For `player_count > 0`, no-op tick is a full-length list (`[PlayerInput() for _ in range(player_count)]`).
- `[]` is invalid when players exist.
- Tick input ordering is canonical by player index `0..player_count-1`.
- Network merge/tie-break behavior remains runtime-canonical; providers do not invent merge rules.

### FR-2: Pure TickRunner

`TickRunner` is a pure deterministic orchestrator.

Requirements:
- No internal `FixedStepClock`/accumulator ownership.
- No hook-bus ownership.
- Input: explicit tick range (`start_tick`, `ticks_requested`, `tick_dt`).
- Output: `TickBatchResult` with ordered per-tick `TickResult` values and terminal batch status.
- Batch status values include `ready`, `stalled`, and `eos`.
- If batch status is `stalled` or `eos`, already-completed ticks in the same batch remain committed.

Required `TickBatchResult` minimum fields:
- `ticks_completed`
- `batch_status`
- `next_tick_index`
- `completed_results`

### FR-3: Replay Journal

Use a symmetric `Journal` abstraction for replay recording/playback.

Requirements:
- Journal supports read mode (playback) and append mode (recording).
- `ReplayInputProvider` is a thin adapter that forwards read requests to Journal and maps them to `TickInput`.
- Frame drivers explicitly commit `TickResult`/checkpoint data to Journal.
- Network sync and checkpoint side effects are explicit frame-driver calls, not implicit hook fan-out.

### FR-4: Presentation Split (Plan vs Apply)

Split presentation logic into:
- `plan_world_presentation_step` (deterministic planning)
- `apply_presentation_plan` (output-side effects)

Requirements:
- Plan stage executes in deterministic tick path.
- Apply stage executes in output phase.
- Headless/verify paths may skip apply.
- Planning still runs in headless/verify to preserve RNG parity.
- Multi-tick frame plans are applied in strict tick order when apply is enabled.

### FR-5: Render Abstraction

Keep two seams:

1. `RenderPipeline` (draw orchestration)
2. `RenderSink` (destination transport)

Minimum sinks:
- `WindowSink`
- `VideoSink`
- `NullSink`

Requirements:
- Same render pass logic feeds window and video.
- Replay render path reuses shared pipeline.
- `RenderPipeline` owns resize/lifecycle orchestration and optional begin/end drawing scope.
- `RenderSink` owns destination lifecycle (`open`, `present`, `flush`, `close`).
- Sink failure policy is explicit:
- `WindowSink`: present callback optional/no-op when absent.
- `VideoSink`: fail-fast on transport/export errors.
- `NullSink`: always no-op/success.

### FR-6: World Decomposition End-State

Collapse world architecture to two meaningful components:

- `SimWorldState`: deterministic sim state, deterministic terrain/bootstrap data, deterministic visual stamp data required for parity.
- `PresentationLayer`: render resources + audio routing/application.

Requirements:
- One-way dependency: `PresentationLayer` consumes `SimWorldState` outputs.
- Sim layer has no dependency on GPU/audio runtime objects.
- Remove compatibility facades that only forward between split classes.
- `TerrainRuntime` is not a long-lived architectural runtime component in end-state; keep only helper/bootstrap utilities where needed.

### FR-7: Replay Path Unification

`ReplayPlaybackMode` must use the same frame-driver + `TickRunner` orchestration style as gameplay.

Requirements:
- Replay is local-only.
- Replay input path: `Journal` -> `ReplayInputProvider` -> `TickRunner`.
- Remove replay-specific bespoke stepping loops.

### FR-8: Event-Driven UI Commands

UI outcomes (for example perk picks) enter deterministic sim via input commands.

Flow:
1. Tick result surfaces pending UI state.
2. UI collects choice.
3. Choice becomes `InputCommand`.
4. Command is queued to provider.
5. Next deterministic tick consumes command in canonical order.

### FR-9: Replay Pause/Step/Speed Semantics

Replay interactivity remains in frame-driver layer.

Requirements:
- `paused=True`: no fixed-step debt accumulation.
- `step_once` while paused advances exactly one deterministic tick, then returns to paused.
- `speed_multiplier` scales effective dt only while unpaused.
- On unpause, accumulation resumes from post-pause state with no hidden carry-over.
- EOS is terminal and never converted into stall.

## Non-Functional Requirements

1. Determinism
- Golden replay checkpoint/hash parity must hold.

2. Observability
- Required counters: `runtime_updates_per_frame`, `input_stall_count`, `ticks_advanced_per_frame`.
- Required timings: `sim_ms`, `presentation_plan_ms`, `presentation_apply_ms`.

3. Simplicity
- Avoid architectural facades that only proxy calls.
- Prefer explicit orchestration calls over implicit hook fan-out.

4. Test Realism
- Prefer runtime types and production wiring in tests for deterministic/runtime paths.
- Avoid internal shim/stub-heavy tests for core runtime orchestration (`TickRunner`, frame drivers, providers, journal, sync dispatch).
- Limit doubles to hard external boundaries (for example: OS process, filesystem transport, network socket transport, video encoder transport).
- Do not add test-only runtime fallbacks/default branches that mask missing wiring or invalid states.
- If runtime code is hard to test with real types, treat that as a design signal and simplify composition boundaries instead of adding special test accommodations.

## Concrete End Shape

### Final Runtime Shape

`FrameDriver` (context-specific owner):
- owns fixed-step accumulator/debt
- calls `input_provider.begin_frame(...)`
- pumps runtime exactly once per frame in interactive gameplay (`GameLoopView`)
- requests candidate tick count from accumulator
- calls pure `tick_runner.advance_ticks(...)`
- dispatches `TickBatchResult` explicitly to:
- simulation state application
- journal recording/checkpoint emission
- network sync actions (where applicable)
- presentation apply (if enabled)
- telemetry collection

`GameLoopView`:
- interactive frame driver and sole runtime pump owner for gameplay contexts

`ReplayPlaybackMode` / replay runners:
- local-only frame drivers with no network runtime
- `Journal`-backed replay input

`Mode` classes:
- configure session/policies/components
- no custom deterministic orchestration loops
- no raw runtime pumping or net runtime method calls

`TickRunner`:
- pure deterministic orchestration over explicit tick ranges

### Expected Collapses / Cleanups

1. Collapse `BaseGameplayMode._run_deterministic_session_ticks` into pure `TickRunner` invocation + frame-driver dispatch.
2. Collapse per-mode LAN orchestration duplication into shared frame-driver/network adapter path.
3. Remove hook-bus architecture from deterministic tick pipeline.
4. Remove exception/`None` input control flow in favor of `InputStatus`.
5. Remove replay bespoke stepping loop and use shared runner path.
6. Collapse world facades into `SimWorldState` + `PresentationLayer`.
7. Keep headless output path minimal through `NullSink`.

### Expected Deletions (End-State)

- Hook bus classes used only for orchestration indirection.
- Replay/mode-specific bespoke deterministic stepping loops.
- Mode-local runtime pumping paths.
- Compatibility facades that proxy between split world components.

## Implementation Plan (Phases)

### Phase 0: Instrumentation Baseline

Changes:
- Ensure runtime pump, stall, tick-count, and stage timing counters are emitted consistently.

Primary files:
- `src/crimson/game/loop_view.py`
- `src/crimson/modes/survival_mode.py`
- `src/crimson/modes/rush_mode.py`
- `src/crimson/modes/quest_mode.py`

Exit criteria:
- Existing behavior unchanged.
- Required counters visible in telemetry/debug output.

### Phase 1: Status + Journal Interfaces

Changes:
- Add `InputStatus`/`TickInput` contract.
- Introduce `Journal` read/append interface.
- Convert `ReplayInputProvider` to thin Journal adapter.

Primary files:
- `src/crimson/sim/input_providers.py`
- `src/crimson/replay/journal.py`
- `src/crimson/sim/tick_runner.py`

Exit criteria:
- Input status and replay journal APIs compile and tests pass.

### Phase 2: Runtime Ownership Consolidation

Changes:
- Keep runtime pumping only in `GameLoopView` for interactive gameplay.
- Remove/guard all mode-local runtime pumping codepaths.

Primary files:
- `src/crimson/game/loop_view.py`
- `src/crimson/modes/survival_mode.py`
- `src/crimson/modes/rush_mode.py`
- `src/crimson/modes/quest_mode.py`

Exit criteria:
- Exactly one runtime pump per interactive frame when runtime exists.

### Phase 3: Pure TickRunner + Frame Accumulator Ownership

Changes:
- Make `TickRunner` stateless/pure.
- Move fixed-step debt ownership to frame-driver context.

Primary files:
- `src/crimson/sim/tick_runner.py`
- `src/crimson/game/loop_view.py`
- `src/crimson/modes/base_gameplay_mode.py`
- `src/crimson/modes/replay_playback_mode.py`

Exit criteria:
- Tick orchestration is shared and deterministic with frame-owned debt.

### Phase 4: Remove Hook-Bus Orchestration

Changes:
- Replace implicit hook flow with explicit frame-driver dispatch for replay recording, checkpointing, sync, and telemetry.

Primary files:
- `src/crimson/sim/tick_runner.py`
- `src/crimson/sim/hooks.py`
- `src/crimson/modes/base_gameplay_mode.py`
- `src/crimson/replay/journal.py`

Exit criteria:
- No behavior regressions in replay/hash/checkpoint outputs.
- Orchestration is explicit in frame-driver layer.

### Phase 5: Replay Local Path Unification

Changes:
- Ensure replay playback/verify are local-only.
- Ensure replay uses the same runner orchestration shape as gameplay.

Primary files:
- `src/crimson/modes/replay_playback_mode.py`
- `src/crimson/sim/driver/playback_driver.py`
- `src/crimson/sim/input_providers.py`

Exit criteria:
- Replay has no network runtime dependency and no bespoke stepping loop.

### Phase 6: Presentation Plan/Apply Finalization

Changes:
- Keep deterministic plan in tick path.
- Keep apply in output phase.
- Keep headless/verify apply skipped while preserving planning RNG parity.

Primary files:
- `src/crimson/sim/step_pipeline.py`
- `src/crimson/sim/presentation_step.py`
- `src/crimson/modes/replay_playback_mode.py`

Exit criteria:
- Command hash/checkpoint parity remains stable across live/replay/headless paths.

### Phase 7: Render Pipeline/Sink Cleanup

Changes:
- Keep shared render pipeline for window/video.
- Keep `NullSink` as headless sink.

Primary files:
- `src/crimson/render/pipeline.py`
- `src/crimson/render/sink.py`
- replay render driver files

Exit criteria:
- Shared draw path across window/video; headless uses `NullSink`.

### Phase 8: World Collapse and Final Cleanup

Changes:
- Collapse world architecture to `SimWorldState` + `PresentationLayer`.
- Remove obsolete compatibility facades and dead orchestration paths.

Primary files:
- `src/crimson/world/sim_world_state.py`
- `src/crimson/world/render_resources.py`
- `src/crimson/world/audio_bridge.py`
- `src/crimson/world/*` (new `presentation_layer` module as needed)
- `src/crimson/modes/base_gameplay_mode.py`

Exit criteria:
- End-state architecture achieved.
- No duplicate orchestration paths remain.

## Acceptance Criteria

### Functional

1. Local gameplay works in Survival/Rush/Quest with unchanged behavior.
2. Replay playback and replay verify remain deterministic and unchanged in outcomes.
3. Lockstep and rollback sessions function with no duplicate runtime pumping.
4. Video rendering path uses shared render pipeline.

### Determinism

Canonical parity artifacts:

1. Per-tick `command_hash`.
2. Per-tick `state_hash` where enabled.
3. Checkpoint hash rows.
4. Terminal replay/session summary fields.

Pass criteria:

1. Golden replay checkpoints match baseline for sampled ticks.
2. `command_hash` matches baseline for deterministic parity fixtures.
3. `state_hash` behavior is unchanged where produced.
4. No first-bad-tick in parity runner outputs for gated fixtures.

### Observability

1. Runtime update and stall counters are emitted.
2. Stage timing metrics are emitted.

## Test Gates

### Gate Definitions

`G0` (commit gate, always):

```bash
uv run pytest --no-cov
```

`G2` (determinism artifact gate):

```bash
uv run crimson replay verify-checkpoints <replay.crd>
uv run crimson replay diff-checkpoints <expected> <actual>
```

### Gate Policy

1. After every commit: run `G0`.
2. At the end of each phase: latest commit in that phase has a green `G0`.
3. For determinism/presentation/replay-hash phases (`Phase 4`, `Phase 5`, `Phase 6`): run `G2`.
4. Do not stack new implementation commits on a failing suite; fix forward immediately.

### Runtime-First Test Policy

1. Tests for runtime orchestration should instantiate real runtime types and composition wiring by default.
2. Avoid stubs/shims for internal runtime contracts unless isolating an external boundary.
3. New runtime behavior must not depend on fallback/default code paths introduced only to satisfy tests.
4. When a scenario is difficult to test without stubs, prefer refactoring runtime composition for explicit dependency seams that are also valid in production.

### Required Invariant-Focused Tests

- `tests/test_runtime_pump_ownership.py`
- `tests/test_input_provider_semantics.py` (updated for `InputStatus`)
- `tests/test_tick_runner_result_order.py`
- `tests/test_tick_runner_stall_eos.py`
- `tests/test_replay_journal_parity.py`
- `tests/test_render_backend_sink_contract.py`
- `tests/test_presentation_plan_granularity.py`
- `tests/test_replay_pause_step_clock_semantics.py`
- `tests/test_input_normalization_contract.py`
- `tests/test_world_presentation_layer_boundaries.py`

## Risks and Mitigations

1. Determinism drift during presentation split.
- Mitigation: golden replay parity gates per phase.

2. Silent lockstep stalls from provider status handling.
- Mitigation: explicit stall metrics and watchdog assertions.

3. Frame-driver complexity increase after removing hook bus.
- Mitigation: keep explicit, tested helper functions for dispatch and result application.

4. World collapse causes API churn.
- Mitigation: phase migration and temporary shim removal only after call-site cutover.

## Scope Guardrails

Do not refactor deterministic gameplay math unless parity tests prove a bug.
Do not introduce test-only fallback/default behavior in runtime code; simplify runtime composition instead.

Treat these as stable unless failing tests demand change:
- `run_deterministic_step` core semantics
- session `step_tick` contracts
- `PlayerInput`/input normalization contracts
- deterministic RNG stream order and hash artifact semantics
