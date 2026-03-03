# Loop Refactor Architecture Synthesis

Status: implemented.

## Runtime Ownership

- Interactive gameplay runtime pump owner: `GameLoopView`.
- Replay runtime pump owner (when runtime exists): `ReplayPlaybackMode`.
- Headless replay verify/benchmark: no runtime pump owner.
- Modes do not call `runtime.update()` directly.

## Deterministic Tick Flow

- Single deterministic orchestrator: `TickRunner`.
- Shared per-tick hook bus: replay recorder, checkpoints, network hash sync, profiling.
- Input sources unified behind providers (`LocalInputProvider`, `ReplayInputProvider`, `NetworkInputProvider`).
- `None` input only represents network stall (never EOS).

## Presentation + Rendering

- Deterministic presentation planning and side-effect apply are split:
  - planning in deterministic tick flow;
  - apply in output/render phase.
- Shared render path:
  - backend: `RaylibBackend`;
  - sinks: `WindowSink`, `VideoSink`, `NullSink`;
  - orchestration: `RenderPipeline`.
- Replay video export and live window rendering use the same backend/sink pipeline.

## GameWorld Decomposition

- `SimWorldState`: deterministic simulation state.
- `RenderResources`: GPU resources and render caches.
- `AudioBridge`: presentation-audio application.
- `TerrainRuntime`: deterministic terrain bootstrap + render-side terrain scheduling.
- Compatibility sync shims removed; `GameWorld` now exposes component-backed accessors/properties.

## LAN Orchestration

- Shared LAN frame consume/capture/hash/broadcast logic lives in `BaseGameplayMode`.
- `survival`, `rush`, and `quest` keep only mode-specific LAN behavior/state transitions.
- No duplicate LAN runtime pumping or bespoke parallel orchestration loops remain.

## Acceptance Summary

- Full suite gate: `uv run pytest --no-cov` passes.
- Replay fixtures + integration lanes remain green.
- Deterministic checkpoint/hash paths remain intact under the unified loop architecture.
