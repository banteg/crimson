# Stronger Synthesis Plan: Composable Main Loop

This plan merges `plan_codex.md`, `plan_gem.md`, `plan_claude.md`, and `plan.md` into one execution-oriented refactor strategy.

## Objectives

1. Make input pluggable (`local`, `replay`, `network`) without mode-specific branching.
2. Keep deterministic simulation authoritative and instrumentable (profiling, observability, netcode hashes).
3. Make rendering target-agnostic (`interactive raylib`, `video export`, `headless/null`).
4. Remove split ownership of frame/network/sim responsibilities.

## Current Failure Modes To Fix

- Duplicate network pumping across loop + modes causes unclear ownership and potential double updates.
- Input sampling is split between logical input pipeline and direct raw raylib polling.
- Deterministic tick + presentation side effects are coupled in one boundary.
- Rendering stack is hard-bound to global raylib API and global monkeypatch telemetry.
- Replay video pipeline mixes stepping, window lifecycle, framebuffer capture, and ffmpeg transport.
- `GameWorld` mixes sim state, GPU resources, rendering behavior, audio bridge, and terrain lifecycle in one object.
- `ReplayPlaybackMode` runs a parallel orchestration path instead of using the same sim runner architecture as gameplay modes.

## Target Architecture

### 1) Composition Root (Mode Assembler)

Modes become assembly/config only (choose components), not giant orchestration hosts.

- Choose session type (`SurvivalDeterministicSession`, `RushDeterministicSession`, `QuestDeterministicSession`)
- Choose input provider
- Choose tick runtime hooks
- Choose renderer backend + sink

### 1.5) `GameWorld` Decomposition

Split responsibilities currently bundled in `GameWorld` into explicit components:

- `SimWorldState`: deterministic state + step result application inputs/outputs
- `RenderResources`: textures/shaders/render caches + lifecycle (`open/close`)
- `AudioBridge`: FX/music routing and audio randomness integration
- `TerrainRuntime`: terrain state + bootstrap/runtime terrain transitions

This avoids render/audio resource concerns leaking into deterministic orchestration.

### 2) Input Boundary

```python
class InputProvider(Protocol):
    def begin_frame(self, frame_ctx: FrameContext) -> None: ...
    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None: ...
    def push_command(self, command: InputCommand) -> None: ...
```

`pull_tick_input(...)->None` is meaningful for lockstep/rollback providers: it signals
"tick not ready yet, stall deterministic advancement for now."

Implementations:
- `LocalInputProvider` (raylib polling + local mapping)
- `ReplayInputProvider` (decoded replay stream)
- `NetworkInputProvider` (lockstep/rollback runtime adapter)
- `CompositeInputProvider` (for command/UI overlays or local+network hybrid ownership)

### 3) Deterministic Tick Runtime

```python
class TickRunner:
    def advance_frame(self, dt: float) -> TickBatchResult: ...
```

Internal stages per tick:
1. `InputNormalize`
2. `PreSimEvents`
3. `WorldSim`
4. `PostSimDeterministic`
5. `PresentationPlan` (command generation, no draw side effects)
6. `IntegrityHash`
7. `Emit`

### 4) Hook Bus (Profiling/Observability/Netcode)

```python
class TickHook(Protocol):
    def on_tick_begin(self, ctx: TickContext) -> None: ...
    def on_pre_sim(self, ctx: TickContext) -> None: ...
    def on_world_step_done(self, ctx: TickContext, result: StepResult) -> None: ...
    def on_post_presentation(self, ctx: TickContext, result: TickResult) -> None: ...
    def on_tick_end(self, ctx: TickContext, result: TickResult) -> None: ...
```

Examples:
- replay recorder hook
- profiling hook
- desync/hash hook
- telemetry exporter hook

Multi-stage hooks are required so net hash hooks can run post-sim/pre-apply, while
profiling can separately time sim, presentation planning, and output apply.

### 5) Render Separation

Two seams:

- `RenderBackend`: draw API adapter (raylib first)
- `RenderSink`: where frames go
  - `WindowSink` (interactive)
  - `VideoSink` (ffmpeg pipeline)
  - `NullSink` (headless fast sim/testing)

Render flow:
`WorldSnapshot + PresentationPlan -> RenderBackend calls -> RenderSink`

### 6) Event-Driven UI Commands

UI decisions (notably perk picks) should become commands injected via input boundary:

1. Sim emits `perk_selection_pending` in tick results.
2. UI opens menu based on that signal.
3. Player choice is converted to `PerkPickCommand`.
4. Command is fed to `InputProvider.push_command(...)`.
5. Next tick consumes it as regular deterministic input.

This unifies local/replay/network behavior and removes special pause wiring in mode loops.
The simulation can remain fully deterministic without a UI-specific pause state; waiting for a choice is simply "no command yet."

## Ownership Rules (Hard Invariants)

1. Only one component pumps network runtime per frame.
2. Only `InputProvider` reads external input systems.
3. `TickRunner` owns deterministic stepping and hash production.
4. Presentation planning cannot mutate renderer/window state directly.
5. Headless mode still runs presentation planning (for RNG parity), but skips apply/output side effects.
6. Mode classes do not call raw net runtime methods except through adapters.

## Rollout Plan (Low Risk)

### Phase 0: Baseline And Safety Nets

- Add/update parity tests around step pipeline, replay runners, and mode ticking.
- Add frame/tick counters + assertions to detect duplicate network updates.

Exit criteria:
- Existing replay parity tests pass.
- No behavior change in live modes.

### Phase 1: Interfaces Without Behavior Change

- Add `InputProvider`, `TickHook`, `RenderSink`, and net runtime protocol interfaces.
- Wrap existing implementations with adapters; no call-site migration yet.

Exit criteria:
- Code compiles/tests pass with adapter layer unused by default.

### Phase 2: Single Network Owner

- Choose loop-level owner (`GameLoopView`) for `runtime.update()`.
- Remove mode-level duplicate pumps; modes consume prepared frames only.

Exit criteria:
- LAN/rollback/lockstep smoke tests pass.
- Per-frame runtime update assertion guarantees one pump per frame.

### Phase 3: Input Provider Migration

- Route local/replay/network tick inputs through `InputProvider`.
- Remove direct raw input polling from mode hot paths.

Exit criteria:
- Local play and replay playback produce same checkpoints as pre-refactor baseline.

### Phase 4: Shared TickRunner

- Extract shared deterministic runner from duplicated mode/session loops.
- Move Quest bespoke loop onto the shared runner.
- Deduplicate LAN orchestration into shared middleware/adapters rather than per-mode copy.

Exit criteria:
- Survival/Rush/Quest use same tick orchestration entrypoint.

### Phase 5: Presentation Plan Split

- Make presentation stage emit commands/plans only.
- Apply plans in render/output phase.
- Keep planning mandatory in headless/replay verify paths to preserve RNG contract.

Exit criteria:
- Deterministic command hashes unchanged for golden replays.
- FX/audio behavior parity in visual smoke checks.

### Phase 6: Replay Path Unification

- Migrate `ReplayPlaybackMode` to the same `TickRunner` + `InputProvider` contracts.
- Keep replay-specific behavior in hooks/sinks, not in a parallel stepping pipeline.

Exit criteria:
- Replay playback uses shared deterministic orchestration code path.
- Replay-only behavior lives in adapters/hooks.

### Phase 7: Render Backend + Sink Migration

- Introduce `RaylibBackend` and `WindowSink`.
- Move replay video export to `VideoSink`; keep same mode draw path.
- Add `NullSink` for headless benchmark/verify runs.

Exit criteria:
- `replay render` output matches current baseline visually and timing-wise.
- headless replay benchmark path no longer depends on window lifecycle.

## Acceptance Matrix

- Local gameplay:
  - Survival/Rush/Quest playability unchanged.
- Replay:
  - verify/checkpoint parity unchanged.
  - render export path stable.
- Network:
  - lockstep and rollback stay functional with hash plumbing intact.
- Tooling:
  - observability/profiling hooks attach without mode code edits.
- Architecture:
  - `GameWorld` responsibilities are decomposed and each component has a single concern.
  - Perk/UI command flow is exercised through `InputProvider` (no mode-local special casing).

## Scope Guardrails

Avoid unnecessary churn in the deterministic kernel unless parity tests prove a defect.

Treat these as stable foundations and refactor around them:
- `run_deterministic_step` / session stepping contracts
- `FixedStepClock`
- `PlayerInput` / `InputFrame` data contracts
- Existing deterministic replay/checkpoint parity behavior

## Risks And Mitigations

- Risk: Determinism drift during presentation split.
  - Mitigation: gate each phase with checkpoint/hash comparisons on golden replays.
- Risk: Stall semantics (`None` input) can freeze progression silently.
  - Mitigation: add explicit stall telemetry counters and watchdog assertions in net/replay runners.
- Risk: Net regressions from ownership changes.
  - Mitigation: add explicit runtime update counters and adapter contract tests.
- Risk: `GameWorld` split creates broad API churn.
  - Mitigation: first introduce facade adapters, then migrate call-sites incrementally by subsystem.
- Risk: Large PR blast radius.
  - Mitigation: ship phase-by-phase behind thin adapters and keep each phase independently mergeable.

## Immediate Next PR Slice

1. Add protocol interfaces (`InputProvider`, `TickHook`, `RenderSink`, net runtime protocol).
2. Add single-owner network pump assertion instrumentation.
3. Add stall telemetry (`input_not_ready` counters) and hook stage timing scaffolding.
4. Wire adapters in parallel with existing logic (no behavior changes).

This is the highest leverage first step with minimal regression risk.
