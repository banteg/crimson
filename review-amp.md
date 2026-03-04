# Architecture Review Follow-Up Checklist (Amp)

This checklist converts the branch review into concrete implementation work.

Goal: remove split-brain orchestration, delete migration scaffolding, and align runtime + tests with the spirit of `plan.md`, `refactor.md`, and `CONTRIBUTING.md`.

---

## 1) Remove Split-Brain Tick Paths

- [ ] Delete `src/crimson/sim/world_tick_runner_harness.py`.
- [ ] Migrate all callers of `step_world_once(...)` to shared runtime stepping (`WorldRuntime` + `TickRunner` path).
- [ ] Replace `run_deterministic_step(...)` direct calls in harness-style tests with the same deterministic stepping pipeline used by production frame drivers.
- [ ] Ensure no production or test orchestration path bypasses `TickRunner` unless explicitly scoped as low-level step-pipeline unit tests.

### Acceptance

- [ ] `rg -n "world_tick_runner_harness|step_world_once\(" src tests` returns no runtime orchestration usages.
- [ ] `rg -n "run_deterministic_step\(" tests` only matches tests intentionally targeting step-pipeline internals.

---

## 2) Collapse LAN Scaffolding in Modes

- [ ] Replace overridable LAN template-method chain in `BaseGameplayMode` (`_prepare_lan_frame`, `_allow_lan_frame_pop`, `_on_tick_applied`) with a single explicit LAN frame/apply orchestration flow.
- [ ] Move mode-specific LAN behavior into explicit data/config callbacks (or narrow strategy objects) that do not control stepping lifecycle.
- [ ] Keep stop semantics (`stop_before_finalize`, `stop_after_finalize`) explicit and linear in one owner.
- [ ] Preserve current correctness fixes: no simulated-but-unapplied ticks under stop actions.

### Acceptance

- [ ] No lifecycle template-method override chain for LAN stepping remains across `survival_mode.py`, `rush_mode.py`, `quest_mode.py`.
- [ ] LAN stepping/apply ownership is visibly centralized in one frame-driver path.

---

## 3) Complete WorldRuntime Cutover (Remove Duplicate Lifecycle Code)

- [ ] Refactor `BaseGameplayMode` to use `WorldRuntime` / `PresentationLayer` composition instead of directly owning `SimWorldState`, `RenderResources`, `AudioBridge`, `TerrainRuntime` as peer fields.
- [ ] Refactor `ReplayPlaybackMode` to use `WorldRuntime` and delete duplicated lifecycle helpers:
  - [ ] `_sync_world_size_ownership`
  - [ ] `_reset_world_runtime`
  - [ ] `_open_world_runtime`
  - [ ] `_close_world_runtime`
- [ ] Keep one-way dependency: presentation consumes sim outputs; no sim dependency on render/audio runtime.

### Acceptance

- [ ] Core gameplay and replay modes no longer duplicate world init/reset/open/close/sync code.
- [ ] `WorldRuntime` is the shared lifecycle owner for gameplay/replay/debug/test runtime hosts.

---

## 4) Unify Deterministic Batch Apply Boundary

- [ ] Extract shared deterministic batch-apply helper used by both gameplay and replay frame drivers.
- [ ] Keep deterministic metadata updates separate from output side effects.
- [ ] Ensure audio apply and camera update happen at frame/output boundary (owner-specific), not as hidden per-tick side effects in shared deterministic core.
- [ ] Preserve strict tick order in multi-tick frames.

### Acceptance

- [ ] No duplicated apply loops between gameplay and replay for core tick-result handling.
- [ ] Shared helper has clear deterministic contract and explicit output-phase hooks.

---

## 5) Bring Tests Back to Runtime-First Principles

- [ ] Rewrite `tests/test_runtime_pump_ownership.py` to rely on real runtime types/wiring where practical, minimizing fake runner/provider machinery.
- [ ] Keep mocks only at true external boundaries (socket/process/filesystem/video transport).
- [ ] Remove test narratives that justify mock-heavy internal orchestration by default.
- [ ] Add regression tests that validate parity-sensitive behavior through real frame-driver paths.

### Acceptance

- [ ] Runtime orchestration coverage primarily executes real `TickRunner` + provider + session wiring.
- [ ] Mock-heavy LAN orchestration simulation is reduced to narrowly scoped boundary tests.

---

## 6) Documentation Integrity Pass

- [ ] Update `refactor.md` checkboxes so they reflect code reality (no false `[x]`).
- [ ] Add direct evidence links/line references for each completed checklist item.
- [ ] Keep unresolved work explicitly unchecked with short rationale.

### Acceptance

- [ ] No completed item in `refactor.md` contradicts current repository state.

---

## Verification Gates

- [ ] `uv run pytest --no-cov`
- [ ] `just check`
- [ ] `rg -n "world_tick_runner_harness|step_world_once\(" src tests`
- [ ] `rg -n "def _prepare_lan_frame|def _allow_lan_frame_pop|def _on_tick_applied" src/crimson/modes`

---

## Done Definition

- [ ] One deterministic stepping architecture (`TickRunner`-owned orchestration path in frame drivers).
- [ ] No lingering compatibility/scaffolding layers for LAN/frame apply/world lifecycle.
- [ ] Tests enforce runtime-first behavior and do not mask architecture drift.
- [ ] Planning docs truthfully match implementation state.
