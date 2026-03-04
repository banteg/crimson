# Runtime-First Test Quality Plan

## Purpose

This plan upgrades the test suite from implementation-coupled, mock-heavy checks to runtime-typed, behavior-driven coverage.

Primary objective: make tests fail for real regressions and stay stable through harmless refactors.

## Scope

In scope:
- `tests/` quality and architecture
- deterministic runtime orchestration tests
- replay/lan frame-driver tests
- fixture/builder strategy and typed test data

Out of scope:
- gameplay feature changes
- netcode protocol redesign
- production behavior changes made only to satisfy brittle tests

## Quality Principles

1. Test externally observable invariants, not internal call-stack shape.
2. Prefer production runtime types (`msgspec.Struct`, dataclasses, domain structs) over `SimpleNamespace` and `Any` casts.
3. Allow mocks at hard boundaries only (OS, network transport, process exec, raylib adapter edge).
4. Keep deterministic path tests close to production wiring (`TickRunner`, providers, sessions, frame drivers).
5. If something is hard to test with real types, simplify composition boundaries instead of adding test-only fallbacks.

## Current Risk Snapshot

Baseline indicators from suite scan:
- `inspect.stack` usage: 1 file (`tests/test_architecture_contracts.py`)
- `SimpleNamespace` usage: 22 test files
- mock-heavy patterns: 67 test files

High-priority files:
- `tests/test_architecture_contracts.py`
- `tests/test_runtime_pump_ownership.py`
- `tests/test_replay_playback_mode_timing.py`

## Success Criteria

1. Zero `inspect.stack` assertions in tests.
2. No `SimpleNamespace` or `cast(Any, ...)` in core runtime orchestration tests.
3. Deterministic orchestration tests assert behavior/invariants only (tick counts, status transitions, telemetry, parity).
4. Test builders provide typed fixtures for tick/session/runtime payloads.
5. Full suite passes with `uv run pytest --no-cov`.

## Metrics To Track Per Phase

1. Count of `inspect.stack` assertions in `tests/`.
2. Count of `SimpleNamespace` references in runtime orchestration test modules.
3. Count of `cast(Any, ...)` references in those modules.
4. Number of tests using typed builders instead of ad-hoc fake payloads.
5. Pass/fail and duration for targeted suites and full suite.

## Quality Dashboard

### Baseline (Phase 0)

| Metric | Value |
|--------|-------|
| `inspect.stack` in `tests/` | 0 |
| `SimpleNamespace` in `test_architecture_contracts.py` | 4 |
| `SimpleNamespace` in `test_runtime_pump_ownership.py` | 16 |
| `SimpleNamespace` in `test_replay_playback_mode_timing.py` | 14 |
| `cast(Any, ...)` in `test_architecture_contracts.py` | 4 |
| `cast(Any, ...)` in `test_runtime_pump_ownership.py` | 6 |
| `cast(Any, ...)` in `test_replay_playback_mode_timing.py` | 0 |
| Files importing `unittest.mock` | 13 |
| `test_architecture_contracts.py` timing | 2.40s (4 tests) |
| `test_runtime_pump_ownership.py` timing | 0.33s (6 tests) |
| `test_replay_playback_mode_timing.py` timing | 0.22s (4 tests) |

### Final (Phase 7)

| Metric | Baseline | Final | Delta |
|--------|----------|-------|-------|
| `inspect.stack` in `tests/` | 0 | 0 | — |
| `SimpleNamespace` in 3 target files | 34 | 0 | -34 |
| `cast(Any, ...)` in 3 target files | 10 | 0 | -10 |
| `cast(LanTickSync, ...)` in production | 2 | 0 | -2 |
| `test_architecture_contracts.py` timing | 2.40s | 0.29s | -88% |
| `test_runtime_pump_ownership.py` timing | 0.33s | 0.23s | -30% |
| `test_replay_playback_mode_timing.py` timing | 0.22s | 0.19s | -14% |
| Shared typed builders in `tests/builders/` | 0 | 4 modules | +4 |

## Contributor Guidance

### When to mock

Use mocks only at hard system boundaries:
- GPU/raylib draw calls and texture operations
- Network transport (`send_packet`, `recv_packets`)
- Audio device/hardware I/O
- File system loading (fonts, assets, terrain)
- OS-level APIs (`time.perf_counter_ns`, screen queries)

Do **not** mock:
- Internal methods (`_reset_tick_runner_state`, `_apply_sim_step_result`)
- Production types that are cheap to construct (msgspec.Struct, dataclass)
- Implementation ordering (unless explicitly testing ordering contracts)

### How to build typed fixtures

Use shared builders from `tests/builders/`:

```python
from builders import FakeRunner, make_tick_payload, make_tick_result, make_tick_batch

# Tick payload with defaults
payload = make_tick_payload(command_hash="h0", elapsed_ms=16.67)

# Full tick result
result = make_tick_result(tick_index=0, command_hash="h0")

# Batch of results
batch = make_tick_batch(ticks=[result], status=InputStatus.READY)

# Configurable fake runner
runner = FakeRunner(results=[batch])
```

### Good vs bad patterns

**Bad** — `SimpleNamespace` payload tree:
```python
payload = SimpleNamespace(
    step=SimpleNamespace(events=SimpleNamespace(), command_hash="h0", ...),
    elapsed_ms=16.67,
)
```

**Good** — typed production struct:
```python
payload = make_tick_payload(command_hash="h0", elapsed_ms=16.67)
```

**Bad** — `cast(Any, ...)` to bypass types:
```python
result = cast(Any, batch.completed_results[0]).payload
```

**Good** — assert and narrow:
```python
result = batch.completed_results[0]
assert isinstance(result.payload, DeterministicSessionTick)
```

## Phase 0: Baseline And Guardrails

Goal: establish a measurable baseline before changing tests.

Tasks:
1. Capture current grep metrics for `inspect.stack`, `SimpleNamespace`, `cast(Any, ...)`, and mock density.
2. Record targeted suite timing for:
   - `tests/test_architecture_contracts.py`
   - `tests/test_runtime_pump_ownership.py`
   - `tests/test_replay_playback_mode_timing.py`
3. Add a short "quality dashboard" section in this document with initial numbers.

Acceptance:
1. Baseline metrics and timings are recorded in this file.
2. No code/test behavior changes yet.

## Phase 1: Remove Brittle Architecture Assertions

Goal: eliminate tests that lock internal call-chain shape.

Targets:
- `tests/test_architecture_contracts.py`

Tasks:
1. Remove `_TickRunnerStackSpy` + `inspect.stack` based assertions.
2. Replace with invariant-driven checks:
   - identical externally visible tick advancement outcomes
   - identical `InputStatus` handling (`READY`, `STALLED`, `EOS`)
   - identical telemetry outputs where expected
3. Keep architectural intent by naming invariants clearly in test names/docstrings.

Acceptance:
1. No `inspect.stack` usage remains in `tests/`.
2. Architecture contract tests continue validating behavior parity without implementation coupling.
3. Target file passes standalone.

## Phase 2: Runtime-Pump Test Typing Cleanup

Goal: remove namespace/`Any` payload fakes from LAN/runtime pump tests.

Targets:
- `tests/test_runtime_pump_ownership.py`

Tasks:
1. Introduce typed test fixtures for tick payloads:
   - use minimal `msgspec.Struct` or dataclass matching fields consumed by mode logic.
2. Replace nested `SimpleNamespace` payload trees with typed fixtures.
3. Remove `cast(Any, ...)` where runtime/test protocols can be met with small typed helper classes.
4. Keep mocks only for unavoidable boundaries; avoid patching private mode internals unless the test explicitly targets internal branching.

Acceptance:
1. No `SimpleNamespace` in this module for tick payload/state wiring.
2. No `cast(Any, ...)` in this module for normal test flow.
3. Tests still validate runtime pump ownership and LAN stop/finalize semantics.

## Phase 3: Replay Timing Tests Use Real Runner Paths

Goal: convert fake-runner loop tests into realistic runner-driven tests.

Targets:
- `tests/test_replay_playback_mode_timing.py`

Tasks:
1. Replace inline `_FakeRunner` classes with minimal real `TickRunner` setups where feasible.
2. Use typed session fixtures to drive deterministic tick outcomes.
3. Keep boundary stubs only for input devices and file/resource loading edges.
4. Verify pause/step/speed/EOS semantics through observed view state transitions.

Acceptance:
1. Reduced fake orchestration classes in this file.
2. Assertions remain about behavior (`_tick_index`, finished state, debt behavior), not internals.
3. File passes standalone.

## Phase 4: Shared Typed Builders For Orchestration Tests

Goal: centralize reusable runtime-typed fixture construction.

Targets:
- `tests/builders/` (expand from current minimal state)
- selected orchestration tests migrated to builders

Tasks:
1. Add builders for:
   - tick payload/result objects
   - minimal deterministic session fixtures
   - LAN sync samples/callback containers
2. Migrate duplicated local helper classes in tests to shared builders.
3. Ensure builders use production types first, with narrowly-scoped protocol-conforming helper types only when necessary.

Acceptance:
1. At least 3 high-priority orchestration modules use shared typed builders.
2. Duplicate fake payload class definitions drop significantly.
3. Builder interfaces remain simple and explicit.

## Phase 5: Boundary-Mock Policy And Suite-Wide Triage

Goal: reduce ceremonial mocking in the broader suite.

Targets:
- top mock-dense modules discovered by scan (batch by batch)

Tasks:
1. Categorize each mock site:
   - valid boundary mock
   - replaceable with runtime type
   - implementation-coupled/ceremonial
2. Refactor ceremonial cases in priority order (core runtime first).
3. Document accepted boundary mocks in a short policy note inside this file.

Acceptance:
1. A reviewed list of top mock-heavy files exists with status (`keep`, `refactor`, `defer`).
2. Core runtime path files no longer rely on private-method patch webs.

### Boundary-Mock Policy

Valid mock boundaries (keep):
- **GPU/raylib**: `rl.*` draw calls, texture operations, blend modes, screen queries
- **Network I/O**: `transport.send_packet`, `transport.recv_packets`
- **Audio hardware**: audio device init, playback via OS audio subsystem
- **File I/O**: font loading, asset loading, terrain file I/O
- **Process/OS**: `time.perf_counter_ns`, screen resolution

Invalid mock targets (refactor):
- Internal method patches (e.g. `_reset_tick_runner_state`, `_apply_sim_step_result`)
- Internal draw helpers (`_draw_small`, `_text_width`)
- Implementation ordering checks via spy capture

### Mock Triage Table

| File | Mocks | Status | Notes |
|------|-------|--------|-------|
| test_primary_beam_rtx.py | 9 | keep | GPU boundary; 2 internal draw helpers are borderline |
| test_net_runtime_rollback.py | 4 | keep | network I/O boundary |
| test_relay_service.py | 3 | keep | network I/O boundary |
| test_net_runtime_resync.py | 3 | keep | network I/O boundary |
| test_net_reconnect.py | 3 | keep | network I/O boundary |
| test_resync_snapshot_apply.py | 2 | refactor | internal method mocks |
| test_quest_results_layout.py | 2 | keep | GPU boundary; internal draw methods borderline |
| test_perk_database_view.py | 2 | refactor | internal utility mocks |
| test_net_runtime_heartbeat.py | 2 | keep | network I/O boundary |
| test_game_over_sfx.py | 2 | keep | GPU/input boundary |
| test_console_command_generateterrain.py | 2 | refactor | internal state management mocks |
| test_replay_playback_mode_audio.py | 1 | defer | test infrastructure |
| test_replay_runners_survival.py | 1 | refactor | internal implementation ordering |
| test_game_tune_trigger.py | 1 | refactor | internal audio method mocks |

## Phase 6: Contract Tightening For Typed Runtime Results

Goal: reduce type-erasure pressure in production-facing test seams.

Targets:
- `src/crimson/sim/hooks.py`
- runner/frame-driver touchpoints

Tasks:
1. Evaluate tightening `TickResult.payload` and `TickResult.lan_sync` typing (or provide typed wrappers at frame-driver boundary).
2. Introduce stricter protocol/type aliases that preserve flexibility but prevent `object`-driven test fakes.
3. Update affected tests to consume stricter contracts.

Acceptance:
1. Clear reduction in `object`-typed payload handling in runtime orchestration tests.
2. No determinism regression.

## Phase 7: Stabilization, CI Ratchet, And Documentation

Goal: prevent regression back to ceremonial test patterns.

Tasks:
1. Add lightweight static checks/grep-based CI guardrails:
   - forbid `inspect.stack` in tests
   - forbid new `SimpleNamespace` in designated core runtime test modules
2. Add contributor guidance section to this plan:
   - when to mock
   - how to build typed fixtures
   - example good vs bad patterns
3. Re-run full suite and compare performance/flake profile with baseline.

Acceptance:
1. CI or pre-merge checks enforce no reintroduction of banned patterns in core areas.
2. Contributors have clear examples and decision rules.

## Execution Order And Batch Strategy

Recommended order:
1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5
7. Phase 6
8. Phase 7

Batch each phase as small PRs with isolated test intent.

Example PR slicing:
1. PR A: Phase 1 only
2. PR B: Phase 2 only
3. PR C: Phase 3 only
4. PR D: Phase 4 + partial Phase 5 triage

## Validation Commands

Use these commands at each phase boundary:

```bash
uv run pytest --no-cov tests/test_architecture_contracts.py
uv run pytest --no-cov tests/test_runtime_pump_ownership.py
uv run pytest --no-cov tests/test_replay_playback_mode_timing.py
uv run pytest --no-cov
```

Pattern tracking:

```bash
rg -n "inspect\.stack\(" tests
rg -n "SimpleNamespace|cast\(Any," tests/test_architecture_contracts.py tests/test_runtime_pump_ownership.py tests/test_replay_playback_mode_timing.py
```

## Risks And Mitigations

1. Risk: over-correction removes useful low-level checks.
   Mitigation: replace each removed assertion with a documented runtime invariant.

2. Risk: typed fixture migration slows test writing initially.
   Mitigation: invest early in shared builders (Phase 4).

3. Risk: integration-leaning tests become slower.
   Mitigation: keep fast deterministic fixtures; reserve full integration for selected paths.

4. Risk: hidden coupling appears during refactor.
   Mitigation: phase gating + targeted file runs before full suite.

## Definition Of Done

This plan is complete when:
1. High-priority modules are runtime-typed and behavior-driven.
2. Core orchestration tests avoid `SimpleNamespace`, `Any` casts, and stack-shape assertions.
3. Shared typed builders are in active use.
4. Quality guardrails prevent easy regression.
5. Full suite is green.
