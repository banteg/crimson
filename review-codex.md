# PRD: Split-Brain and Scaffolding Cleanup Plan (Post-Audit)

## Document Control

- Status: Proposed
- Date: 2026-03-05
- Author: Codex (strict branch audit synthesis)
- Scope: `src/crimson` runtime orchestration and related tests
- Primary inputs: `plan.md`, `refactor.md`, `CONTRIBUTING.md`, strict branch review findings

## Executive Summary

The branch completed key foundational work (hook-bus removal, `InputStatus` contract, pure `TickRunner`), but the implementation is not at the intended end-state.

The architecture is still split across multiple orchestration paths:

1. Deterministic apply is duplicated across gameplay, replay, and world runtime paths.
2. Audio/camera apply is still executed inline during deterministic tick apply in multiple contexts.
3. Modes still directly orchestrate LAN runtime behavior and contain LAN template scaffolding.
4. World lifecycle and camera logic are duplicated between `BaseGameplayMode`, `ReplayPlaybackMode`, and `WorldRuntime`.
5. Test/runtime scaffolding (`world_tick_runner_harness`, `WorldRuntimeHost` wrapper) remains significant and keeps two worlds alive.

This PRD defines a concrete migration to one coherent frame-driver architecture that satisfies the spirit and explicit requirements of `plan.md` and `CONTRIBUTING.md`.

## Problem Statement

Current branch behavior still violates end-shape expectations in `plan.md` and acceptance items left open in `refactor.md` Stage 6.

### Confirmed Gaps

1. Duplicate deterministic batch apply brains still exist.
2. Output-side effects (audio/camera) are still mixed into deterministic apply loops.
3. Mode classes still call raw net runtime methods.
4. LAN template methods (`_prepare_lan_frame`, `_allow_lan_frame_pop`, `_on_tick_applied`) still exist and are overridden per mode.
5. `WorldRuntime` is not the shared runtime owner for gameplay/replay paths.
6. `step_world_once` harness path still exists and is used.

## Goals

1. Establish a single deterministic batch-apply contract used by gameplay, replay, and debug/demo stepping.
2. Move output-side effects (audio apply, camera update) to explicit frame-driver output phases.
3. Remove mode-owned raw network runtime orchestration from gameplay modes.
4. Collapse duplicated world lifecycle/camera/render wiring to one shared runtime host.
5. Remove long-lived scaffolding (`world_tick_runner_harness`, LAN template method surface, oversized test host wrapper).
6. Preserve deterministic parity and replay checksum stability.

## Non-Goals

1. No gameplay math redesign.
2. No netcode protocol redesign.
3. No renderer backend rewrite.
4. No UI visual redesign.

## Hard Invariants (Must Hold)

1. `GameLoopView` remains sole runtime pump owner for interactive gameplay contexts.
2. `TickRunner` remains pure/stateless.
3. Input control flow remains `InputStatus`-based (`READY`, `STALLED`, `EOS`).
4. Replay contexts remain local-only with no network runtime ownership.
5. Presentation planning executes in deterministic path for RNG parity.
6. Headless/verify can skip presentation apply but must execute deterministic planning.
7. Mode classes configure policies/components; they do not call raw net runtime methods.
8. No compatibility scaffolding is left as permanent architecture.

## Target End-State Architecture

### Runtime Layers

1. `FrameDriver` (context owner: gameplay, replay playback, headless verify, demo/debug)
2. `TickRunner` (pure advance over explicit tick ranges)
3. Shared deterministic batch-apply helper (single implementation)
4. Shared output apply helper (single implementation)
5. `WorldRuntime` (single world lifecycle/composition owner)

### Deterministic Pipeline Shape

1. FrameDriver computes candidate ticks from owned clock/debt.
2. FrameDriver calls `input_provider.begin_frame(...)` and `tick_runner.advance_ticks(...)`.
3. FrameDriver calls shared deterministic batch-apply helper.
4. Helper returns ordered output-phase command list(s).
5. FrameDriver executes output apply (audio/camera/presentation apply) in strict tick order.

## Implementation Plan

## Phase 0: Guardrails and Baseline Lock

### Tasks

1. Add architecture guardrails that fail on regressions.
2. Add focused checks preventing reintroduction of split-brain code paths.
3. Snapshot current deterministic parity baselines before major cuts.

### File Changes

1. `tools/ast-grep/rules/` add rules:
- no direct `sim_world.apply_step_metadata` in mode/replay drivers (except shared apply module)
- no direct `audio_bridge.apply_plan` in deterministic apply loops
- no mode direct net-runtime calls for LAN orchestration
2. `tests/test_architecture_contracts.py` add behavior-focused assertions for shared apply path usage.
3. `refactor.md` append phase tracking section linked to this PRD.

### Acceptance

1. New guardrails fail on intentionally injected prohibited patterns.
2. Baseline replay verification and deterministic test set pass unchanged.

## Phase 1: Extract Shared Deterministic Batch-Apply Core

### Tasks

1. Create a single shared module for deterministic tick-result apply.
2. Move duplicated apply logic out of:
- `BaseGameplayMode._process_tick_batch_results`
- `ReplayPlaybackMode._apply_tick_outcome`/runner completion path
- `WorldRuntime._apply_tick_batch`
- `step_world_once`
3. Keep LAN/replay checkpoint and sync extension points explicit and ordered.

### Proposed New Module

- `src/crimson/sim/batch_apply.py`

### API Sketch

1. `apply_deterministic_batch(...) -> DeterministicApplyOutcome`
2. `build_output_commands(...) -> list[PresentationApplyCommand]`

`DeterministicApplyOutcome` contains only deterministic state and metadata outputs, no direct audio/camera side effects.

### Acceptance

1. One shared deterministic apply implementation is referenced by gameplay, replay, and world runtime stepping paths.
2. No duplicated per-context loops mutating sim metadata directly.

## Phase 2: Move Presentation/Audio/Camera to Output Boundary

### Tasks

1. Introduce shared output apply helper for ordered per-tick output commands.
2. Ensure deterministic apply only plans/records output; frame drivers perform apply.
3. Maintain strict tick-order output apply in all contexts.
4. Headless verify path executes planning and skips apply.

### File Changes

1. `src/crimson/sim/presentation_step.py` and new output apply helper module.
2. `src/crimson/modes/base_gameplay_mode.py` update frame loop to call output apply phase.
3. `src/crimson/modes/replay_playback_mode.py` move side effects out of deterministic loop.
4. `src/crimson/world/runtime.py` align demo/debug stepping to same boundary.

### Acceptance

1. No inline `audio_bridge.apply_plan` inside deterministic batch-apply core.
2. No inline camera update inside deterministic batch-apply core.
3. All contexts apply output in strict tick order.

## Phase 3: Cut Gameplay + Replay World Lifecycle to `WorldRuntime`

### Tasks

1. Replace duplicated world lifecycle code in `BaseGameplayMode` with `WorldRuntime` ownership.
2. Replace duplicated world lifecycle code in `ReplayPlaybackMode` with `WorldRuntime` ownership.
3. Remove duplicate camera/build_render_frame plumbing from those modes.

### File Changes

1. `src/crimson/modes/base_gameplay_mode.py` adopt `WorldRuntime` instead of owning `SimWorldState` + `RenderResources` + `AudioBridge` + `TerrainRuntime` fields directly.
2. `src/crimson/modes/replay_playback_mode.py` same cutover.
3. `src/crimson/world/runtime.py` add any missing hooks required by gameplay/replay.

### Acceptance

1. Gameplay/replay world lifecycle methods are not duplicated locally.
2. `WorldRuntime` is shared runtime owner across gameplay/replay/debug/demo.

## Phase 4: Remove Mode-Level Raw Net Runtime Orchestration

### Tasks

1. Introduce explicit LAN frame-driver orchestration component.
2. Move runtime operations out of modes:
- recovery pop/apply
- queued local input injection
- host readiness gating
- LAN tick frame pop handling
3. Keep mode-level responsibilities to policy/config callbacks only.

### File Changes

1. New module: `src/crimson/net/frame_driver.py` (or `src/crimson/sim/driver/lan_driver.py`).
2. `src/crimson/modes/base_gameplay_mode.py` remove direct net-runtime method calls.
3. `src/crimson/modes/{survival,rush,quest}_mode.py` convert to policy-only contributions.

### Acceptance

1. No direct raw net runtime calls in gameplay modes.
2. Runtime orchestration lives in explicit frame-driver code.

## Phase 5: Remove LAN Template Scaffolding

### Tasks

1. Delete `_prepare_lan_frame`, `_allow_lan_frame_pop`, `_on_tick_applied` template-method surface.
2. Replace with explicit policy objects or typed callbacks passed to LAN frame driver at assembly time.
3. Keep deterministic ordering explicit and local in one orchestration module.

### Acceptance

1. No per-mode overrides of LAN orchestration template methods remain.
2. LAN stepping path is explicit, flat, and centralized.

## Phase 6: Retire Harness and Test Scaffolding

### Tasks

1. Remove `src/crimson/sim/world_tick_runner_harness.py`.
2. Migrate tests using `step_world_once` to runtime-first stepping via shared frame-driver/runtime APIs.
3. Shrink or delete `tests/world_runtime.py` wrapper in favor of direct `WorldRuntime` fixtures.

### Acceptance

1. `world_tick_runner_harness.py` deleted.
2. No test imports from harness module.
3. Test runtime host wrapper reduced to minimal fixture helper or removed.

## Phase 7: Simplify or Remove Low-Value `PresentationLayer` Facade

### Tasks

1. Decide one final architecture option:
- Option A: keep `PresentationLayer` as minimal pure composition data object (no method forwarding)
- Option B: remove `PresentationLayer`, keep explicit fields on `WorldRuntime`
2. Execute chosen cutover fully.

### Acceptance

1. No method-only forwarding layer remains as permanent architecture.
2. Composition boundaries are explicit and behavior-bearing.

## Verification Strategy

### Required Checks Per Phase

1. `uv run pytest --no-cov tests/test_input_provider_semantics.py tests/test_tick_runner_stall_debt.py tests/test_runtime_pump_ownership.py tests/test_architecture_contracts.py tests/test_replay_playback_mode_timing.py`
2. `uv run pytest --no-cov` for full suite gate before each phase close.
3. `just check` at each phase close.

### Determinism and Parity Gates

1. Replay command hash parity on golden fixtures.
2. Replay checkpoint/state hash parity on golden fixtures.
3. No regressions in pause/step/speed replay semantics.
4. No regressions in LAN stall/debt and resync handling tests.

## Concrete Acceptance Checklist

1. Shared deterministic batch-apply helper exists and is used by gameplay/replay/debug paths.
2. Frame-driver output apply owns audio/camera/presentation apply in strict order.
3. `BaseGameplayMode` no longer contains LAN template method scaffolding.
4. `BaseGameplayMode` and `ReplayPlaybackMode` no longer duplicate world lifecycle internals currently implemented in `WorldRuntime`.
5. No direct raw net-runtime orchestration methods in gameplay mode classes.
6. `world_tick_runner_harness.py` removed.
7. All new guardrails and full test suite pass.

## Risk Register and Mitigations

1. Risk: replay parity drift during apply-boundary migration.
- Mitigation: phase-by-phase parity gates using stable fixtures and command-hash assertions.
2. Risk: LAN desync regressions when moving runtime calls.
- Mitigation: preserve ordering in one frame-driver path; keep and extend LAN sync tests.
3. Risk: broad refactor churn in mode classes.
- Mitigation: migrate by adapter shims with strict removal deadlines in same phase.

## Delivery Order (Strict)

1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5
7. Phase 6
8. Phase 7

## Definition of Done

The branch is considered compliant with the spirit of `plan.md`, `refactor.md`, and `CONTRIBUTING.md` when:

1. One deterministic apply brain exists.
2. One world lifecycle brain exists.
3. One LAN orchestration brain exists.
4. Modes are composition/policy owners, not orchestration hosts.
5. No long-lived compatibility scaffolding remains.
6. Deterministic parity gates and full checks are green.
