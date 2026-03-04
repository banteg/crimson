# PRD: Stage 6 Completion — Batch Apply Unification and Facade Collapse

## Document Control

- Status: Draft for review
- Last updated: 2026-03-05
- Audience: implementer of gameplay/runtime architecture
- Primary codebase scope: `src/crimson` Python runtime
- Branch: `feat/split20`
- Context: Stages 1–5 of `plan.md` are complete. This document covers remaining Stage 6 work.

## Current State Assessment

Stages 1–5 delivered the hard structural wins:
- Hook bus removed — zero `getattr`-based dispatch remaining.
- `TickRunner` is pure/stateless — no clock, no tick index, no frame index.
- `InputStatus` enum replaces `None`-as-stall and exception-based EOS.
- `sandbox_step.py` deleted, `WorldHost` protocol unified.
- Test suite cleaned: no `inspect.stack()`, no call-chain shape assertions.
- Presentation plan/apply split exists as pure functions.
- Mode subclasses no longer duplicate orchestration loops.
- `ReplayPlaybackMode` migrated to `WorldRuntime` for world lifecycle.

Stage 6 is **half-done**. The world composition container exists and deduplicates lifecycle, but batch-apply unification and facade collapse have not landed.

## Problem Statement

### P1: Batch apply is tripled

Three independent implementations of the identical core sequence:

| Location | Method | Lines |
|---|---|---|
| `world/runtime.py:296-326` | `_apply_tick_batch()` | per tick: `apply_step_metadata → sync_audio → apply_plan → update_camera` |
| `modes/base_gameplay_mode.py:2052-2074` | `_apply_sim_step_result()` | per tick: `apply_step_metadata → sync_audio → apply_plan → update_camera` |
| `modes/replay_playback_mode.py:575-615` | `_apply_tick_outcome()` | per tick: `apply_step_metadata → sync_audio → apply_plan → update_camera` + quest extras |

If the step metadata shape changes, three call sites must be updated in lockstep.

### P2: Per-tick audio/camera side effects inside batch loop

`plan.md` FR-4 requires:
> `apply_audio` / `update_camera` are not deterministic tick-apply controls; audio apply and camera update run at frame/output boundary.

All three batch-apply implementations call `sync_audio_bridge_state()`, `audio_bridge.apply_plan(apply_audio=True)`, and `update_camera()` **per tick inside the iteration**, not once per frame at the output boundary.

Evidence:
- `WorldRuntime._apply_tick_batch()` lines 319-324: audio sync + apply + camera per tick.
- `BaseGameplayMode._apply_sim_step_result()` lines 2068-2074: audio apply + camera per tick, called from `_process_tick_batch_results()` loop at line 2132.
- `ReplayPlaybackMode._on_runner_tick_complete()` lines 637-643: apply outcome (with audio) + camera per tick.

### P3: `PresentationLayer` is a pure forwarding facade

`world/presentation.py` (100 lines) contains zero behavioral logic. Every method is a 1-line forward to `self.render_resources`, `self.audio_bridge`, or `self.terrain_runtime`. `WorldRuntime` then re-exposes the underlying components through forwarding properties anyway:

```python
# world/runtime.py:106-115
@property
def render_resources(self) -> RenderResources:
    return self.presentation.render_resources

@property
def audio_bridge(self) -> AudioBridge:
    return self.presentation.audio_bridge

@property
def terrain_runtime(self) -> TerrainRuntime:
    return self.presentation.terrain_runtime
```

Callers access `runtime.render_resources`, `runtime.audio_bridge`, `runtime.terrain_runtime` — never `runtime.presentation.sync_audio(...)`. The forwarding facade adds a layer without behavioral value. `plan.md` says: *"Remove compatibility facades that only forward between split classes."*

### P4: `WorldRuntime` has grown beyond "temporary"

`plan.md` decision 13:
> A temporary `WorldRuntime` composition container is allowed only for migration/deduplication and must not become a long-lived facade API.

`WorldRuntime` now owns:
- `FixedStepClock` + `_frame_index` + `_next_tick_index` (mutable frame-stepping state)
- `_session` / `_runner` lifecycle (`init_tick_runner`, `reset_tick_runner`, `_ensure_runner`)
- Its own `_apply_tick_batch()` (duplicated apply logic)
- `advance_tick_frame()` — a full frame-driver entry point

The tick-stepping half (lines 215-362) is only used by demo/debug/test consumers, not by gameplay modes or replay. It replicates frame-driver concerns (clock management, session caching, batch apply) that `plan.md` says belong to frame-driver contexts, not to a composition container.

### P5: `cast(Any, ...)` type erasure

`CONTRIBUTING.md`: *"Avoid casting to Any or duct-taping with .get()/getattr() to dodge typing."*

Two violations:
- `base_gameplay_mode.py:2060` — `_apply_sim_step_result(step: object)` → `cast(Any, step)` to access `.events`, `.presentation`, `.command_hash`, `.dt_sim`.
- `replay_playback_mode.py:698` — `_apply_completed(batch_results: list[object])` → `cast(Any, tick_result)` to access `.payload`, `.tick_index`.

Both are symptoms of untyped boundaries in the batch-apply path. A shared typed helper would eliminate these.

### P6: `world_tick_runner_harness.py` vestigial naming

File contains `WorldHost` protocol + `step_world_once()` helper. The "harness" class was absorbed into `WorldRuntime` but the file keeps its old name. 4 test files import from it. Not a correctness issue but a clarity issue.

## Non-Problems (Corrected from Initial Review)

- **`ReplayPlaybackMode` parallel world ownership**: Already migrated. Uses `self._runtime: WorldRuntime` (line 129, 376-389). No separate `_sim_world`/`_render_resources`/`_audio_bridge`/`_terrain_runtime` fields remain.
- **`PlaybackDriver` as stepping indirection**: `PlaybackDriver` is a replay setup/config factory, not a stepping orchestrator. It builds sessions, resolves tick timing, provides `build_tick_runner()` and `apply_terminal_events()`. `ReplayPlaybackMode._advance_runner()` owns stepping directly via `TickRunner`. `PlaybackDriver.run_to_completion()` is used only by headless verify/benchmark CLI paths — separate frame-driver context as plan allows. This is config/setup, not indirection.

## Goals

1. Extract one shared deterministic batch-apply helper that all three paths use.
2. Separate deterministic sim-metadata application from output-phase audio/camera side effects.
3. Collapse `PresentationLayer` forwarding facade — inline composition into `WorldRuntime`.
4. Scope `WorldRuntime`'s tick-stepping to its actual consumers (demo/debug/test), mark it clearly as a convenience for non-production paths.
5. Eliminate `cast(Any, ...)` in batch-apply boundaries.
6. Rename `world_tick_runner_harness.py` to reflect its actual content.

## Non-Goals

1. No changes to `TickRunner`, `InputProvider`, or `InputStatus` contracts (already clean).
2. No changes to `PlaybackDriver` (setup/config, not orchestration).
3. No changes to deterministic stepping math or RNG consumption.
4. No changes to hook data structures in `hooks.py`.

## Hard Invariants

1. Deterministic sim-metadata application order must be identical across all contexts (gameplay, replay, demo/debug).
2. Audio/camera side effects must not change the order of deterministic operations.
3. `command_hash` and `state_hash` parity must be preserved across live/replay/headless.
4. RNG consumption must remain identical whether audio/camera apply runs or not.

## Functional Requirements

### FR-1: Shared Deterministic Tick-Apply Helper

Extract a single function that applies one tick's sim-state changes:

```python
def apply_tick_to_sim(
    *,
    sim_world: SimWorldState,
    step: DeterministicStepResult,
    game_tune_started: bool,
) -> None:
    """Apply one tick's deterministic results to sim state. No audio/camera side effects."""
    sim_world.apply_step_metadata(
        events=step.events,
        presentation=step.presentation,
        command_hash=str(step.command_hash),
        dt_sim=float(step.dt_sim),
        game_tune_started=bool(game_tune_started),
    )
```

Requirements:
- Takes typed `DeterministicStepResult`, not `object`.
- Performs only sim-state mutation (metadata, elapsed_ms, etc.).
- No audio sync, no audio apply, no camera update.
- Used by all three current apply paths.

### FR-2: Output-Phase Audio/Camera at Frame Boundary

After the full tick batch has been applied to sim state:
1. Frame driver calls `sync_audio_bridge_state()` once.
2. Frame driver applies accumulated presentation plans (in tick order) once.
3. Frame driver calls `update_camera()` once with the last tick's `dt_sim`.

Requirements:
- Per-tick sim-apply loop calls `apply_tick_to_sim()` only.
- Audio apply and camera update move out of the per-tick loop to the frame-driver output boundary.
- Each frame-driver context (gameplay, replay, demo/debug) owns its own output-phase call sequence.
- Headless/verify paths skip audio/camera entirely (already true for `run_to_completion`).

### FR-3: Collapse `PresentationLayer` Facade

Inline `PresentationLayer`'s three fields directly into `WorldRuntime`:

```python
class WorldRuntime:
    def __init__(self, ...):
        self.sim_world = SimWorldState(...)
        self.render_resources = RenderResources(...)
        self.audio_bridge = AudioBridge(...)
        self.terrain_runtime = TerrainRuntime(...)
        # ...
```

Requirements:
- Delete `world/presentation.py`.
- Remove `PresentationLayer` from `world/__init__.py` exports.
- Update all callers that reference `runtime.presentation.*` to use direct attributes.
- No behavioral change — only remove the forwarding layer.

### FR-4: Type the Batch-Apply Boundary

Replace `cast(Any, ...)` with proper typed parameters.

In `BaseGameplayMode._apply_sim_step_result()`:
- Change `step: object` to `step: DeterministicStepResult`.
- Delete `cast(Any, step)`.

In `ReplayPlaybackMode._advance_runner()`:
- Change `_apply_completed(batch_results: list[object])` to use `TickResult` type.
- Delete `cast(Any, tick_result)`.

### FR-5: Rename Harness File

Rename `src/crimson/sim/world_tick_runner_harness.py` → `src/crimson/sim/world_step.py` (or similar).

Requirements:
- Update 4 test imports.
- Keep `WorldHost` protocol and `step_world_once()` function unchanged.

### FR-6: Clarify `WorldRuntime` Tick-Stepping Scope

The tick-stepping methods in `WorldRuntime` (`init_tick_runner`, `reset_tick_runner`, `_ensure_runner`, `_apply_tick_batch`, `advance_tick_frame`) serve demo/debug/test consumers only.

Requirements:
- Add a clear docstring section marking tick-stepping as a convenience for non-mode consumers.
- Refactor `_apply_tick_batch` to use the shared `apply_tick_to_sim` helper from FR-1.
- Keep audio/camera calls in `advance_tick_frame` at the frame boundary (after batch loop), not per-tick.

## Implementation Plan

### Phase A: Extract Shared Tick-Apply Helper

**Changes:**
1. Create `apply_tick_to_sim()` function (location: `sim/tick_apply.py` or inline in `world/runtime.py` — prefer a small standalone module for importability).
2. Refactor `WorldRuntime._apply_tick_batch()` to call `apply_tick_to_sim()` per tick, then audio/camera once after the loop.
3. Refactor `BaseGameplayMode._apply_sim_step_result()` to call `apply_tick_to_sim()`, remove `cast(Any, step)`, type `step` properly.
4. Refactor `ReplayPlaybackMode._apply_tick_outcome()` to call `apply_tick_to_sim()`.

**Primary files:**
- New: `src/crimson/sim/tick_apply.py`
- Modified: `src/crimson/world/runtime.py`
- Modified: `src/crimson/modes/base_gameplay_mode.py`
- Modified: `src/crimson/modes/replay_playback_mode.py`

**Exit criteria:**
- One shared sim-apply function used by all three paths.
- Zero `cast(Any, ...)` in batch-apply boundaries.
- Audio/camera calls moved out of per-tick loops.
- `uv run pytest --no-cov` passes.

### Phase B: Collapse PresentationLayer Facade

**Changes:**
1. Inline `PresentationLayer` fields into `WorldRuntime.__init__`.
2. Delete forwarding properties that accessed `self.presentation.*`.
3. Delete `world/presentation.py`.
4. Remove from `world/__init__.py` exports.
5. Update any callers that reference `PresentationLayer` type or `runtime.presentation`.

**Primary files:**
- Deleted: `src/crimson/world/presentation.py`
- Modified: `src/crimson/world/__init__.py`
- Modified: `src/crimson/world/runtime.py`

**Exit criteria:**
- `PresentationLayer` class does not exist.
- `WorldRuntime` directly owns `render_resources`, `audio_bridge`, `terrain_runtime`.
- `uv run pytest --no-cov` passes.

### Phase C: Rename Harness File + Clarify WorldRuntime Scope

**Changes:**
1. Rename `world_tick_runner_harness.py` → `world_step.py`.
2. Update 4 test imports.
3. Add docstring to `WorldRuntime` tick-stepping section clarifying scope.

**Primary files:**
- Renamed: `src/crimson/sim/world_tick_runner_harness.py` → `src/crimson/sim/world_step.py`
- Modified: `tests/test_camera_shake.py`, `tests/test_bonus_pickup_fx.py`, `tests/test_game_world_audio.py`, `tests/test_step_pipeline_parity.py`
- Modified: `src/crimson/world/runtime.py` (docstring only)

**Exit criteria:**
- No file named `*harness*` in `src/crimson/sim/`.
- `uv run pytest --no-cov` passes.

## Acceptance Criteria

### Functional

1. One shared `apply_tick_to_sim()` used by gameplay, replay, and demo/debug paths.
2. Audio sync + apply and camera update called once per frame (not per tick) in all batch-apply contexts.
3. `PresentationLayer` class deleted; no forwarding facade between WorldRuntime and its components.
4. Zero `cast(Any, ...)` in modes or world directories for batch-apply boundaries.
5. `world_tick_runner_harness.py` renamed.
6. `WorldRuntime` tick-stepping section documented as demo/debug/test convenience.

### Determinism

1. `command_hash` parity unchanged across live/replay/headless.
2. `state_hash` behavior unchanged where produced.
3. Golden replay checkpoint parity preserved.
4. RNG consumption identical whether audio/camera apply is enabled or skipped.

### Structural

1. No new abstractions or indirection layers introduced.
2. Total line count should decrease (removing ~100 lines of facade + ~40 lines of duplicated apply logic).
3. No new `cast(Any, ...)` or `getattr()` usage introduced.

## Test Gates

`G0` after every commit:
```bash
uv run pytest --no-cov
```

`G2` after Phase A (determinism-touching):
```bash
uv run crimson replay verify-checkpoints <replay.crd>
uv run crimson replay diff-checkpoints <expected> <actual>
```

## Risks and Mitigations

1. **Audio apply order change when moving from per-tick to per-frame.**
   - Risk: If presentation plans contain sfx that must fire in strict tick order, batching them to frame boundary could change perceived audio timing.
   - Mitigation: `apply_presentation_plan()` is already called per tick result in order. Moving to frame boundary means iterating plans in tick order at the boundary instead of inline — same order, same calls, just at a different point in the frame. Verify with replay audio parity.

2. **Camera position difference from single vs per-tick update.**
   - Risk: Camera currently computes focus from alive players per tick. Moving to once-per-frame with last tick's dt would skip intermediate camera positions.
   - Mitigation: Camera position is display-only (not deterministic). Multi-tick frames are typically 0-2 ticks. Visual difference is negligible. If problematic, apply camera per tick but audio per frame — the plan allows per-context output phase.

3. **`PresentationLayer` removal breaks external callers.**
   - Mitigation: Grep for `PresentationLayer` across entire codebase before deleting. It's only referenced in `world/__init__.py` exports and internal `WorldRuntime` construction. No external consumers found.
