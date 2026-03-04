# Refactor: Remaining Work Toward Simplified End-State

## Scope

This document tracks only the remaining work.
Completed stages were removed.

Target architecture is defined by `plan.md`:
- `GameLoopView` is the only interactive runtime pump owner.
- Replay paths are local-only.
- `TickRunner` is pure/stateless (no internal clock/debt ownership).
- Input control flow is explicit (`InputStatus`: `READY`/`STALLED`/`EOS`).
- Replay uses `Journal` with `ReplayInputProvider` as a thin adapter.
- Hook-bus orchestration is removed from end-state.
- Headless verify skips apply but preserves deterministic planning RNG.
- World architecture collapses to `SimWorldState` + `PresentationLayer`.
- `NullSink` remains the headless sink.
- Tests are runtime-first (no test-only runtime fallback/default behavior).

---

## Stage 1: Remove Hook-Bus Orchestration

Current state still uses dynamic hook dispatch and hook-owned orchestration data flow.

### Tasks

- [ ] Remove `TickHookBus` as the runtime orchestration primitive.
- [ ] Move replay/checkpoint/network-sync/profiler side effects to explicit frame-driver dispatch from `TickBatchResult`.
- [ ] Delete dynamic method lookup dispatch (`getattr` + string method names) from tick orchestration path.
- [ ] Remove mode-level hook wiring fields that only exist to feed `TickHookBus`.
- [ ] Keep deterministic ordering guarantees by explicit, ordered dispatch calls in one place.

### Evidence (current code)

- `src/crimson/sim/hooks.py:40` (`TickHook: TypeAlias = object`)
- `src/crimson/sim/hooks.py:55` (`getattr` dispatch)
- `src/crimson/sim/tick_runner.py:8` (`TickHookBus` dependency)
- `src/crimson/modes/base_gameplay_mode.py:1661` (hook bundle construction in `_ensure_tick_runner`)

### Acceptance

- [ ] No `TickHookBus` used in runtime tick orchestration.
- [ ] Zero `getattr`-based hook dispatch in runtime orchestration path.
- [ ] Replay/checkpoint/network sync behavior parity preserved.
- [ ] `uv run pytest --no-cov` passes.

---

## Stage 2: Standardize Input Status + Journal Replay Contract

Current state still mixes `None` stalls and exception-driven EOS (`ReplayEndOfStream`).

### Tasks

- [ ] Introduce `InputStatus` and `TickInput` contract in `input_providers`.
- [ ] Convert providers to return explicit status (`READY`/`STALLED`/`EOS`) instead of `None`/exceptions.
- [ ] Remove `ReplayEndOfStream` / `ReplayAdvanceEndOfStream` control-flow exceptions from normal tick advancement.
- [ ] Keep `ReplayInputProvider` as a thin adapter over `Journal` read APIs.
- [ ] Define command semantics explicitly for all providers (no “not supported” runtime errors in normal interface usage).
- [ ] Update runner/mode/replay callers to consume status-based control flow only.

### Evidence (current code)

- `src/crimson/sim/input_providers.py:13` (`ReplayEndOfStream`)
- `src/crimson/sim/input_providers.py:34` (`pull_tick_input -> list[...] | None`)
- `src/crimson/sim/input_providers.py:146` (`ReplayInputProvider.push_command` raises)
- `src/crimson/sim/tick_runner.py:180` (exception-based replay EOS path)

### Acceptance

- [ ] No `None`-as-stall control flow in provider/runner contracts.
- [ ] No replay EOS exceptions used for normal per-frame advancement control flow.
- [ ] Replay input path is `Journal -> ReplayInputProvider -> TickRunner`.
- [ ] Input provider tests cover status semantics and pass.

---

## Stage 3: Make TickRunner Pure and Frame-Owned for Debt

Current state still keeps fixed-step clock/debt inside `TickRunner`.

### Tasks

- [ ] Remove `FixedStepClock` ownership from `TickRunner`.
- [ ] Replace `advance_frame(dt, max_ticks)` with explicit tick-range advancement API (frame drivers compute candidate ticks/debt).
- [ ] Move all accumulator/debt ownership to frame-driver layer(s).
- [ ] Delete pass-through call chain (`_invoke_tick_runner_advance` -> `_advance_tick_runner_with_profile` -> `_advance_tick_runner`).
- [ ] Ensure stop actions cannot advance hidden extra ticks before finalize decisions.

### Evidence (current code)

- `src/crimson/sim/tick_runner.py:7` (`FixedStepClock` import)
- `src/crimson/sim/tick_runner.py:76` (clock stored in runner)
- `src/crimson/sim/tick_runner.py:91` (`advance_frame`)
- `src/crimson/modes/base_gameplay_mode.py:1543` (pass-through chain)
- `src/crimson/modes/base_gameplay_mode.py:2137` (stop action after batched application)

### Acceptance

- [ ] `TickRunner` has no internal accumulator/clock state.
- [ ] Frame drivers own debt and candidate tick count calculation.
- [ ] No pass-through orchestration chain remains.
- [ ] Determinism parity and stall/debt tests pass.

---

## Stage 4: Close Correctness Gaps in LAN/Recovery Paths

Before final cleanup, fix existing correctness holes.

### Tasks

- [ ] Ensure rollback resync snapshots are actually applied to runtime/mode state, not only validated and marked applied.
- [ ] Ensure LAN stop semantics are honored without state/checkpoint divergence under backlog.
- [ ] Remove or migrate any remaining non-shared deterministic stepping path (`sandbox_step`) that bypasses final orchestration architecture.

### Evidence (current code)

- `src/crimson/modes/base_gameplay_mode.py:1272` (decode path)
- `src/crimson/modes/base_gameplay_mode.py:1300` (`mark_resync_applied` without state apply)
- `src/crimson/sim/sandbox_step.py:62` (alternate direct deterministic path)

### Acceptance

- [ ] Recovery snapshots have observable state-application behavior.
- [ ] No known backlog-induced finalize/checkpoint divergence remains.
- [ ] Deterministic stepping paths are unified behind target architecture.

---

## Stage 5: Runtime-First Test Suite Cleanup

Replace brittle/internal-chain assertions with runtime-type behavioral coverage.

### Tasks

- [ ] Remove stack/frame inspection assertions (for example `inspect.stack()`-based architecture checks).
- [ ] Reduce heavy mock-based tests of runtime internals; prefer runtime-type integration for orchestration paths.
- [ ] Keep only behaviorally meaningful assertions (observable output/state/telemetry), not incidental call-chain shape.
- [ ] Fix stale ast-grep guardrail paths that reference deleted files.
- [ ] Align tests with `InputStatus` + Journal + pure-runner contracts.

### Evidence (current code)

- `tests/test_architecture_contracts.py:48` (`inspect.stack`)
- `tests/test_runtime_pump_ownership.py:91` (mock-heavy LAN runner simulation)
- `tools/ast-grep/rules/no-gameplay-rng-out-of-band.yml:6` (`src/crimson/game_world.py` stale path)

### Acceptance

- [ ] Zero stack/frame-inspection assertions in test suite.
- [ ] Runtime orchestration tests primarily use real runtime types and composition.
- [ ] Guardrail rules reference only existing files.
- [ ] `uv run pytest --no-cov` passes.

---

## Stage 6: Collapse World Facades and Host Duplication

Current world/runtime hosting still has duplication and facade residue.

### Tasks

- [ ] Collapse to end-state components: `SimWorldState` + `PresentationLayer`.
- [ ] Remove long-lived `TerrainRuntime` facade role; keep only helper/bootstrap utilities.
- [ ] Deduplicate host lifecycle/camera/render glue across debug/test hosts.
- [ ] Reconcile `world_tick_runner_harness` and host protocols with collapsed world architecture.

### Evidence (current code)

- `src/crimson/world/render_resources.py`
- `src/crimson/world/audio_bridge.py`
- `src/crimson/world/terrain_runtime.py`
- `src/crimson/views/arsenal_debug.py:162`
- `src/crimson/views/lighting_debug.py:1325`
- `tests/world_runtime.py:22`

### Acceptance

- [ ] Runtime-facing world composition is `SimWorldState` + `PresentationLayer`.
- [ ] Host lifecycle/camera/render setup exists in one shared implementation path.
- [ ] Debug and world-runtime tests pass.

---

## Prioritization

1. Stage 1 (remove hook-bus orchestration)
2. Stage 2 (InputStatus + Journal contract)
3. Stage 3 (pure runner + frame-owned debt)
4. Stage 4 (LAN/recovery correctness)
5. Stage 5 (runtime-first tests + guardrail cleanup)
6. Stage 6 (world collapse + host dedupe)

This order minimizes risk: first remove hidden orchestration indirection, then lock contracts, then move time/debt ownership, then finish correctness and cleanup.

---

## Strict Audit Addendum (2026-03-04)

These work items were added from the latest strict branch review so nothing remains implicit.

### Added work items

- [ ] Stage 1: Replace `TickHook: TypeAlias = object` with a real protocol/ABC and remove dynamic hook method lookup from runtime orchestration.
- [ ] Stage 2: Remove the `InputProvider.push_command` LSP violation by splitting command-capable and read-only providers (replay provider must not expose a runtime-throwing command method).
- [ ] Stage 3: Remove LAN wrapper/no-op scaffolding in `BaseGameplayMode` (`_on_lan_tick_applied`, `_prepare_lan_frame`, `_allow_lan_frame_pop`, `_after_join_lan_consume`) and collapse to one explicit tick-apply path.
- [ ] Stage 4: Apply decoded rollback resync snapshot payloads to mode/runtime state (not just validate + `mark_resync_applied`).
- [ ] Stage 4: Ensure stop semantics cannot leave runner-simulated state ahead of finalized/checkpointed state under backlog.
- [ ] Stage 5: Replace architecture tests that assert internal call-stack shape/call-chain form with observable behavior assertions.
- [ ] Stage 5: Fix stale ast-grep guardrail scope in `no-gameplay-rng-out-of-band.yml` (`src/crimson/game_world.py` no longer exists).
- [ ] Stage 6: Extract shared world host bootstrap/lifecycle ownership used by demo, debug views, and test host runtime.

### Added evidence references

- `src/crimson/sim/hooks.py:40`
- `src/crimson/sim/hooks.py:55`
- `src/crimson/sim/input_providers.py:31`
- `src/crimson/sim/input_providers.py:146`
- `src/crimson/modes/base_gameplay_mode.py:1813`
- `src/crimson/modes/base_gameplay_mode.py:1840`
- `src/crimson/modes/base_gameplay_mode.py:2008`
- `src/crimson/modes/base_gameplay_mode.py:2137`
- `src/crimson/modes/base_gameplay_mode.py:1285`
- `src/crimson/modes/base_gameplay_mode.py:1300`
- `tests/test_architecture_contracts.py:48`
- `tools/ast-grep/rules/no-gameplay-rng-out-of-band.yml:6`
- `src/crimson/demo.py:88`
- `src/crimson/views/arsenal_debug.py:116`
- `src/crimson/views/lighting_debug.py:1214`
- `tests/world_runtime.py:49`
