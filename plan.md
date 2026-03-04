# PRD: Split-Brain Cleanup and Runtime Convergence

## Document Control

- Status: Approved for implementation
- Last updated: 2026-03-05
- Audience: runtime/gameplay architecture implementers
- Scope: `src/crimson` + targeted runtime tests
- Source synthesis: `review-amp.md`, `review-claude.md`, `review-codex.md`, `review-gem.md`

## Why This Rewrite

Core wins are in place (`TickRunner` purity, `InputStatus`, hook-bus removal), but reviews agree the branch still has architectural split-brain:

1. Deterministic tick-apply is duplicated across gameplay, replay, and world runtime paths.
2. Audio/camera side effects still run inside per-tick deterministic apply loops.
3. Mode classes still own too much LAN/network orchestration.
4. World lifecycle and render/camera plumbing are duplicated or wrapped by compatibility facades.
5. Test scaffolding still carries compatibility host wrappers instead of runtime-first wiring.

This PRD replaces prior plan text with a single phased convergence plan that closes those gaps.

## Goals

1. One deterministic stepping/apply architecture across gameplay, replay, debug/demo, and tests.
2. One explicit frame/output boundary for presentation/audio/camera side effects.
3. Mode classes as composition/policy owners, not orchestration hosts.
4. One world lifecycle owner, with no long-lived forwarding facades.
5. Runtime-first tests that exercise production wiring by default.
6. Preserve determinism and replay parity artifacts throughout refactor.

## Non-Goals

1. No redesign of gameplay math, player rules, or economy.
2. No netcode protocol redesign beyond orchestration boundary cleanup.
3. No renderer backend rewrite.
4. No HUD/visual redesign.

## Hard Invariants

1. `GameLoopView` is sole `runtime.update()` owner for interactive gameplay.
2. Replay playback/verify remain local-only and do not own a network runtime.
3. `TickRunner` remains pure/stateless; frame drivers own clocks/debt.
4. Input flow remains explicit with `InputStatus` (`READY`, `STALLED`, `EOS`).
5. Deterministic planning always runs; headless/verify may skip only output apply.
6. Mode classes do not call raw net runtime methods for LAN stepping lifecycle.
7. No long-lived compatibility wrappers/protocols that only forward existing data.

## Functional Requirements

### FR-1: Shared Deterministic Batch Apply

Create one shared deterministic batch-apply helper used by gameplay, replay, and world runtime/debug paths.

Requirements:
- Single implementation for sim metadata application from ordered `TickBatchResult.completed_results`.
- Typed boundary (`DeterministicStepResult` / `TickResult`), no `cast(Any, ...)` at apply boundary.
- Existing deterministic ordering and metadata semantics preserved.

### FR-2: Output Boundary Separation

Keep deterministic apply side-effect free relative to audio/camera output.

Requirements:
- Per-tick deterministic loop applies sim metadata only.
- Frame/output phase owns `sync_audio_bridge_state`, presentation apply (in strict tick order), and camera update.
- Headless/verify paths keep deterministic planning, skip output apply.

### FR-3: LAN Orchestration Consolidation

Remove mode-level template-method LAN stepping surface and raw runtime orchestration.

Requirements:
- Retire `_prepare_lan_frame`, `_allow_lan_frame_pop`, `_on_tick_applied` override chain.
- Centralize LAN stepping and stop semantics in one explicit frame-driver path.
- Mode-specific variation represented as config/policy callbacks only.

### FR-4: World Runtime Convergence

Eliminate duplicated world lifecycle codepaths across gameplay/replay/runtime helpers.

Requirements:
- One shared lifecycle owner for world init/reset/open/close/sync.
- Remove duplicated helpers in modes where runtime owner already provides behavior.
- Keep one-way dependency: presentation consumes sim outputs; sim never depends on GPU/audio runtime objects.

### FR-5: Facade and Scaffolding Removal

Remove compatibility layers that only proxy existing objects.

Requirements:
- Remove `world_tick_runner_harness` path and migrate callsites to shared runtime stepping.
- Remove or simplify forwarding-only host wrappers in tests.
- Renderer boundary must consume explicit render context/data, not a sprawling host shim protocol.

### FR-6: Runtime-First Test Posture

Bring orchestration tests back to production-like wiring.

Requirements:
- Prefer real `TickRunner` + providers + frame-driver wiring.
- Keep doubles only at true external boundaries (sockets/process/filesystem/encoder transport).
- No test-only runtime fallback/default branches.

## Architecture Direction

1. End-state world boundary remains two meaningful components: deterministic sim + presentation domain.
2. If `PresentationLayer` is kept, it must be behavior-bearing composition and not a forwarding facade.
3. If `PresentationLayer` is removed, replacement must be explicit and still preserve the same two-domain separation.
4. `WorldRuntime` may coordinate composition/lifecycle, but must not become a permanent compatibility proxy API.

## Phased Implementation Plan

### Phase 0: Guardrails and Baseline

Changes:
- Add architecture guardrails (tests/ast-grep) to block reintroduction of split-brain patterns.
- Capture deterministic replay/checkpoint baselines before structural changes.

Exit criteria:
- Guardrails fail on prohibited patterns.
- Baseline parity and full tests pass.

### Phase 1: Shared Batch-Apply Extraction

Changes:
- Implement one shared deterministic batch-apply helper.
- Migrate gameplay/replay/world runtime apply loops to this helper.
- Remove `cast(Any, ...)` in apply boundaries.

Exit criteria:
- Single deterministic apply path in codebase.
- No duplicated per-context metadata apply loops.

### Phase 2: Output Boundary Cut

Changes:
- Move audio/presentation/camera side effects from per-tick loops to frame/output boundary.
- Preserve strict tick-order apply semantics.

Exit criteria:
- No deterministic apply loop contains direct audio/camera side effects.
- Gameplay/replay/debug contexts all use explicit output-phase apply.

### Phase 3: LAN Frame-Driver Consolidation

Changes:
- Introduce/finish explicit LAN frame-driver orchestration owner.
- Remove mode direct net-runtime orchestration calls.
- Flatten stop semantics into one linear owner path.

Exit criteria:
- No template-method LAN override chain in gameplay mode classes.
- LAN stepping/apply ownership visibly centralized.

### Phase 4: World Lifecycle Unification

Changes:
- Cut duplicated world lifecycle helpers from gameplay/replay modes.
- Route lifecycle ownership through shared runtime composition owner.

Exit criteria:
- No duplicate world init/reset/open/close/sync logic across mode drivers.
- Replay and gameplay share lifecycle ownership model.

### Phase 5: Facade Removal Pass

Changes:
- Remove `world_tick_runner_harness.py` and migrate callers.
- Remove forwarding-only wrappers/protocols (runtime and tests).
- Normalize renderer boundary onto explicit render context/data contract.

Exit criteria:
- No harness import usage in runtime orchestration.
- No forwarding-only compatibility host layer remains.

### Phase 6: Runtime-First Test Migration

Changes:
- Refactor orchestration tests to use real runtime wiring.
- Keep mocks only at external boundaries.

Exit criteria:
- Runtime orchestration coverage primarily exercises production paths.
- Mock-heavy internal orchestration tests reduced to boundary-only scope.

### Phase 7: Documentation Truth Pass

Changes:
- Update `refactor.md` checkboxes to match repository reality.
- Add evidence links/line refs for completed items.

Exit criteria:
- No checked item contradicts current code.

## Acceptance Criteria

1. One deterministic batch-apply implementation is shared across gameplay, replay, and debug/demo stepping.
2. Output side effects run at frame/output boundary, not inside deterministic per-tick apply loops.
3. No mode class directly owns LAN runtime stepping lifecycle.
4. World lifecycle orchestration is not duplicated across gameplay/replay/runtime helper paths.
5. No lingering harness/facade compatibility layers for runtime orchestration.
6. Deterministic replay/checkpoint/hash parity remains green.

## Verification Gates

### Core Gate (Each Commit)

```bash
uv run pytest --no-cov
```

### Determinism Gate (Phases 1-5)

```bash
uv run crimson replay verify-checkpoints <replay.crd>
uv run crimson replay diff-checkpoints <expected> <actual>
```

### Structural Grep Gates

```bash
rg -n "world_tick_runner_harness|step_world_once\(" src tests
rg -n "def _prepare_lan_frame|def _allow_lan_frame_pop|def _on_tick_applied" src/crimson/modes
```

## Risks and Mitigations

1. Parity drift during apply-boundary migration; mitigate with phase-by-phase replay/checkpoint gates.
2. LAN desync regressions during orchestration move; mitigate with explicit ordering tests and centralized frame-driver ownership.
3. Camera/audio feel changes from boundary shift; mitigate by preserving strict tick-order command apply and validating replay behavior.

## Definition of Done

1. One deterministic stepping/apply brain.
2. One world lifecycle brain.
3. One LAN orchestration brain.
4. Modes reduced to assembly/policy roles.
5. Runtime-first tests enforce architecture and block drift.
