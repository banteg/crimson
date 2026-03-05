# PRD: Deterministic Split-Brain Elimination

## 1. Summary

The codebase currently executes deterministic gameplay through multiple orchestration paths:

- live interactive gameplay loop
- replay verification loop
- replay playback loop
- LAN/lockstep loop

These paths share core components (`DeterministicSession`, `TickRunner`) but differ in tick orchestration, replay-event application timing, result accounting, and side-effect handling. This causes behavior drift and "same replay, different outcome" failures.

This PRD defines a redesign to converge all deterministic execution onto one orchestration architecture with explicit adapters and profiles.

## 2. Problem Statement

Today, the same replay can produce different outcomes depending on entrypoint (`replay verify` vs `replay play`), and recorded checkpoints can diverge from verifier checkpoints. This is a structural architecture issue, not just a bug-by-bug issue.

### Root cause class

- Orchestration duplication: multiple loops around the same simulation core.
- Policy drift: flags and mode-specific behavior encoded in multiple locations.
- Output coupling: simulation and presentation concerns mixed differently per path.
- Contract ambiguity: no single canonical "deterministic run contract."

## 3. Goals

1. One deterministic orchestration contract used by live, replay verify, replay play, and LAN.
2. Zero semantic drift between `replay verify` and `replay play` for deterministic state/result outputs.
3. Centralize replay-event semantics, elapsed-time semantics, and run-result stats semantics.
4. Make divergence detection CI-enforced, not manual.

## 4. Non-Goals

1. No rewrite of `DeterministicSession` internals.
2. No rendering/audio feature redesign.
3. No replay file format migration in this effort.

## 5. Product Requirements

### PR-1: Single deterministic run engine

Create a shared execution layer (`DeterministicRunEngine`) that owns:

- tick scheduling (`begin_frame`, `advance_ticks`)
- replay/live event application timing
- tick finalization metadata
- checkpoint emission hooks
- run-result accumulation

### PR-2: Explicit adapters

Execution context differences must be adapter-based, not loop-based:

- `InputAdapter`: live input, replay journal, LAN frame provider
- `PresentationAdapter`: none/headless, replay rendering, live runtime bridge
- `SyncAdapter`: LAN hash/sync hooks or no-op

### PR-3: Explicit run profiles

Introduce typed profile config (single source of truth):

- `RunProfile.Live`
- `RunProfile.ReplayVerify`
- `RunProfile.ReplayPlayback`
- `RunProfile.LanHost/LanJoin`

Profiles encode policy (terminal-event timing, quest elapsed source, etc.) once.

### PR-4: Canonical run result contract

All entrypoints use one `RunResultBuilder` for:

- elapsed_ms
- score_xp
- kill count
- shots fired/hit
- RNG state

No per-entrypoint recomputation.

## 6. Proposed Architecture

## 6.1 Core

- `DeterministicRunEngine`
  - state: session, runner, clocks, tick index, accumulators
  - method: `step(frame_ctx) -> StepBatchOutcome`
  - method: `run_to_completion(...) -> RunResult`

## 6.2 Contracts

- `TickLifecycleHooks`
  - `before_tick`
  - `after_tick`
  - `after_batch`
  - `on_terminal_tick`
- `RunResultBuilder`
  - canonical stat extraction and elapsed semantics

## 6.3 Entry point mapping

- `BaseGameplayMode` delegates deterministic stepping to engine.
- `PlaybackDriver` becomes a thin orchestration facade over engine.
- `ReplayPlaybackMode` consumes same engine path as verification, with rendering adapter enabled.
- CLI commands (`verify`, `info`, `benchmark`, `render`) all compose from same engine + adapters.

## 7. Migration Plan

## Phase 0: Contract capture and safety net

- Define deterministic run contract doc (ordering, policy fields, expected invariants).
- Add parity tests for known fixture replays:
  - verify vs playback result equality
  - checkpoint equivalence at sample ticks
- Add failing regression fixture for currently divergent replays.

Exit criteria:

- Tests clearly expose current split behavior.

## Phase 1: Extract shared engine (no behavior change intent)

- Introduce `DeterministicRunEngine` behind existing APIs.
- Keep current entrypoint behavior by wiring old config into profiles.
- Add telemetry assertions to detect unhandled policy fields.

Exit criteria:

- Existing tests pass.
- New engine path available behind one code path without feature regression.

## Phase 2: Route replay verify + replay play through one engine

- Remove duplicate replay-playback tick orchestration.
- Ensure replay events, tick timing, and terminal events are identical.
- Make benchmark/render rely on same replay engine.

Exit criteria:

- `replay verify` == `replay benchmark --mode render` run_result for fixtures.
- No deterministic mismatch errors across sampled replays.

## Phase 3: Route live + LAN through same engine abstractions

- Move LAN/live loops to engine adapters.
- Keep networking policy in `SyncAdapter`, not mode loops.
- Eliminate duplicate checkpoint/stat plumbing.

Exit criteria:

- Live replay recordings verify and replay exactly for fixture scenarios.
- LAN hash checks continue to pass unchanged.

## Phase 4: Cleanup and deletion

- Delete obsolete orchestration paths and dead config knobs.
- Remove temporary compatibility shims.
- Freeze deterministic architecture docs.

Exit criteria:

- Single deterministic orchestration implementation remains.

## 8. Acceptance Criteria (Definition of Done)

1. One shared deterministic execution loop for all modes/entrypoints.
2. No known replay where `verify` and `playback` disagree on `RunResult`.
3. Checkpoint diff at tick 0 and sampled ticks is clean for fixture replays.
4. CI includes deterministic parity gates and blocks regressions.
5. Architecture docs reflect final contracts and extension points.

## 9. Testing Strategy

### Mandatory CI gates

- `verify_vs_playback_run_result_parity` for replay fixtures.
- `verify_vs_playback_checkpoint_parity` (sampled and full for small fixtures).
- `record_then_verify_roundtrip` for live-run integration tests.
- `lan_hash_contract_regression` unchanged for host/join paths.

### Diagnostics

- First-divergence reporter includes:
  - tick index
  - event timeline at divergence window
  - RNG marks
  - state hash summary

## 10. Risks and Mitigations

1. Hidden policy dependencies in mode code.
   - Mitigation: profile completeness checks + strict constructor typing.
2. Performance regressions from added abstraction.
   - Mitigation: benchmark gates before/after each phase.
3. LAN regressions from orchestration movement.
   - Mitigation: isolate sync behavior to adapter and keep protocol tests unchanged.

## 11. Open Questions

1. Should checkpoint elapsed for quest always use spawn timeline, or profile-selectable?
2. Do we preserve current sidecar compatibility if elapsed semantics change?
3. Should replay playback ever intentionally diverge from verifier for UX-only concerns?

## 12. Delivery Plan (PR slicing)

1. PR-A: Contract tests + failing fixture coverage + engine skeleton.
2. PR-B: Verify/playback unification over shared engine.
3. PR-C: Live/LAN adapter migration.
4. PR-D: Cleanup, deletions, docs finalization.

