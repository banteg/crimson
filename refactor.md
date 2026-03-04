# Refactor: Eliminate Split Brain & Scaffolding

## Problem

The feat/split20 branch delivers on the letter of the plan but betrays its spirit. Complexity was moved, not eliminated. Split-brain patterns persist behind new vocabulary. Abstractions exist but some are hollow — protocols that lie, generics nobody varies, hooks that dispatch on strings. The local/LAN split brain, the core problem the plan identified, still exists in the mode layer wearing different clothes.

---

## Stage 1: Consolidate Sessions

Six session classes (`Survival`, `Rush`, `Tutorial`, `Typo`, `WorldTick`, `Quest`) are ~85% identical. Every one duplicates `timing_for_dt()`, `rng_marks` tracking, creature counting, lifecycle finalization. The only real difference is `_mid_step_spawns()`.

672 lines → ~150 with composition.

### Tasks

- [x] Extract shared tick-step boilerplate into a single base or helper
- [x] Accept spawn strategy as a callable parameter, not a class override
- [x] Collapse six session classes into one parameterized session (or one base + minimal subclasses)
- [x] Remove all duplicated `timing_for_dt()` implementations
- [x] Remove all duplicated `rng_marks` / creature-count / lifecycle-finalization boilerplate

### Acceptance

- [x] Only one implementation of `timing_for_dt()` exists
- [x] Only one implementation of post-step boilerplate (rng_marks, creature count, lifecycle finalize) exists
- [x] A bug fix in shared tick logic requires touching exactly one file
- [x] All existing session tests pass without modification
- [x] Replay determinism parity unchanged (`uv run pytest --no-cov`)

---

## Stage 2: Eliminate Local/LAN Split Brain in Modes

Same outcomes (state update, game-over detection, replay checkpoint, perk application) are reached through two parallel code paths: `_on_tick` callbacks for local and `_on_lan_tick_applied()` for LAN. This is the old split brain renamed.

### Tasks

- [x] Unify tick-applied callbacks — one path for both local and LAN tick results
- [x] Remove `_on_lan_tick_applied()` as a separate override hierarchy
- [x] Merge `_apply_input_command()` and `_apply_perk_pick_input_command()` into one path
- [x] Remove `_before_lan_tick_step()`, `_after_join_lan_consume()`, `_allow_lan_frame_pop()` no-op overrides from base — push LAN-specific logic into hooks or the single tick-applied path
- [x] Remove dead parameters from `_prepare_lan_frame()` (`dt` and `lockstep_runtime` removed; `role`, `dt_ui_ms`, `dt_tick` kept — used by survival perk menu)
- [x] Remove dead `_after_join_lan_consume` override from survival (on join `_perk_menu.active` is always False; `_allow_lan_frame_pop` kept — correctly stalls host tick consumption during perk menu)

### Remaining findings

- **[medium]** Survival LAN perk-menu flow is intentionally asymmetric: only `PerkPick` affects sim state (mapped via `_resolve_tick_commands`); `PerkMenuOpen`/`PerkMenuClose` events exist for replay recording, not sim commands. Host-side menu pause gating uses local menu state by design. Join-side `_allow_lan_frame_pop` is not called (join pops from received frames, not capture clock). `_after_join_lan_consume` was dead code (removed).

### Acceptance

- [x] Each of these operations has exactly one code path, not two:
  - [x] State update (elapsed_ms, stage, spawn_cooldown)
  - [x] Game-over detection
  - [x] Replay checkpoint recording
  - [x] Perk application
- [x] No method in `BaseGameplayMode` has `_ = role, dt, dt_ui_ms, ...` ignoring all its parameters (base `_on_lan_tick_applied` discards role/lockstep/session but delegates immediately)
- [x] LAN and local gameplay both pass existing tests
- [x] Replay determinism parity unchanged

---

## Stage 3: Drop Unused Generics from TickRunner

`TimingT` and `TickT` generic parameters are never varied — all sessions use `FrameTiming` and `DeterministicSessionTick`. `inspect.signature()` introspection for `trace_rng` and `getattr` for `resolve_tick_dt` are duck-typing around the protocol.

### Tasks

- [x] Replace `TickSession[TimingT, TickT]` with concrete types (`FrameTiming`, `DeterministicSessionStepTick`)
- [x] Remove `TickSessionWithTraceRng` protocol — add `trace_rng` to the single `TickSession` contract
- [x] Remove `inspect.signature()` introspection in `TickRunner.__init__`
- [x] Move `resolve_tick_dt` into the `InputProvider` protocol or a named optional protocol, remove `getattr` call
- [x] Remove redundant type coercions (`float(dt_seconds)` when already float, `int(self._frame_index)` when already int, etc.)

### Remaining findings

- **[high]** Replay RNG trace sink has an exception-path leak: trace context is manually entered in `on_pre_sim` and only exited in `on_tick_end`; if stepping raises, sink restoration is skipped. `playback_driver.py:296,343`, `tick_runner.py:144`
- **[low]** TickRunner no longer touches `step.presentation`; malformed payloads can pass runner execution and fail later in apply consumers. `tick_runner.py:159`

### Acceptance

- [x] Zero `inspect.signature()` calls in tick_runner.py
- [x] Zero `getattr(self._input_provider, ...)` calls in tick_runner.py
- [x] Zero redundant `float()` / `int()` / `bool()` coercions on already-typed values
- [x] No generic type parameters on `TickRunner` or `TickSession`
- [x] All tick runner tests pass

---

## Stage 4: Make TickHook a Real Protocol

`TickHook` is aliased to `object`. The bus dispatches via `getattr` with magic strings and runtime `callable()` checks. `on_tick_end` can't use the shared `_dispatch()` because it needs boolean aggregation — breaking the abstraction it supposedly uses.

### Tasks

- [ ] Define `TickHook` as a `Protocol` with all hook methods (default no-op via `...` or a base class)
- [ ] Replace string-based `_dispatch()` / `_resolve_method()` with direct method calls
- [ ] Remove `getattr` + `callable()` runtime checks from `TickHookBus`
- [ ] Handle `on_tick_end` boolean aggregation directly, not as a special case of a broken abstraction

### Remaining findings

- **[medium]** Hook contract is looser than intended: `TickHook` typed as `object`, `TickContext` missing richer identity fields like mode/session kind, which weakens enforceability. `hooks.py:14,40`

### Acceptance

- [ ] `TickHook` is a `Protocol` (or ABC), not `TypeAlias = object`
- [ ] Zero `getattr` calls in hooks.py
- [ ] Zero `callable()` checks in hooks.py
- [ ] All hook ordering tests pass
- [ ] Hook dispatch is type-safe (mypy/pyright clean)

---

## Stage 5: Fix InputProvider Protocol Honesty

The protocol declares `push_command()` but `ReplayInputProvider` raises `RuntimeError` on it (LSP violation). `resolve_tick_dt` is used via `getattr` but isn't in the protocol. Three implementations have three different failure modes that the protocol documents none of.

### Tasks

- [ ] Remove `push_command()` and `pull_tick_commands()` from base `InputProvider` protocol — only providers that support commands should declare them
- [ ] Create `CommandableInputProvider` (or similar) protocol for providers that accept commands
- [ ] Add `resolve_tick_dt` to the protocol (or a named optional protocol) — remove `getattr` usage
- [ ] Document stall semantics: local never stalls, replay raises, network returns None
- [ ] Remove `ReplayInputProvider.push_command()` that just raises

### Acceptance

- [ ] No method in any InputProvider implementation raises "not supported"
- [ ] Zero `getattr` calls against input providers in tick_runner.py
- [ ] Each provider only implements methods it actually supports
- [ ] All input provider tests pass
- [ ] Replay and network provider contracts are documented in protocol docstrings

---

## Stage 6: Clean Up Composition Leaks

Running ticks requires three separate calls (`_ensure_tick_runner`, `_advance_tick_runner`, `_process_tick_batch_results`). TickRunner internals leak into modes.

### Tasks

- [ ] Collapse the three-call tick sequence into a single method on BaseGameplayMode
- [ ] Hide TickRunner, provider, and hook construction behind the single method
- [ ] Modes should only see: "advance by dt, get outcome"
- [ ] Collapse pass-through orchestration chain (`_invoke_tick_runner_advance` → `_advance_tick_runner_with_profile` → `_advance_tick_runner`) into a single method

### Remaining findings

- **[high]** LAN stop actions are applied after batch simulation, so the runner can advance extra ticks before `stop_before_finalize` / `stop_after_finalize` is honored. Under backlog conditions this leaves sim state ahead of finalized/checkpointed state. `base_gameplay_mode.py:2097`, `tick_runner.py:122`, `base_gameplay_mode.py:2236`
- **[high]** Rollback resync snapshots are encoded/stored but never applied in mode recovery; recovery path validates payload and immediately marks applied (`mark_resync_applied`). Snapshot content is effectively dead. `base_gameplay_mode.py:1272,1300`, `survival_mode.py:545`, `rush_mode.py:289`, `quest_mode.py:301`
- **[medium]** A non-TickRunner deterministic path still exists (`sandbox_step.py`) and fuses planning/application side effects — remaining split-brain scaffolding against the stated architecture. `sandbox_step.py:62,82`
- **[low]** Pass-through orchestration scaffolding `_invoke_tick_runner_advance` → `_advance_tick_runner_with_profile` → `_advance_tick_runner` with no specialization at any layer. `base_gameplay_mode.py:1543`

### Acceptance

- [ ] Modes call one method to advance ticks, not three
- [ ] Modes do not reference `TickRunner`, `InputProvider`, or `TickHookBus` directly
- [ ] All mode tests pass

---

## Stage 7: Trim Ceremonial Tests

~30% of architecture contract tests are brittle or ceremonial. Stack inspection in contract_2 is coupled to internal call chains. LAN mocking tests check counters, not behavior.

### Tasks

- [ ] Replace stack inspection in contract_2 with behavioral assertions (e.g., "both paths call advance_frame once")
- [ ] Simplify or remove `test_lan_tick_consumption_*` tests — replace with "did runner advance?" checks
- [ ] Move `test_normalize_terrain_ids_falls_back_to_defaults_on_invalid_rows` to unit tests
- [ ] Remove any tests that only assert mock call counts without verifying observable behavior
- [ ] Fix stale ast-grep guardrail targeting deleted `game_world.py` (`tools/ast-grep/rules/no-gameplay-rng-out-of-band.yml:6`)

### Acceptance

- [ ] Zero `inspect.stack()` or frame-inspection assertions in test suite
- [ ] Every remaining architecture test asserts on observable behavior, not internal call chains
- [ ] Test suite still catches: hook order changes, input validation skips, debt preservation failures, RNG mutation during terrain setup, replay pause/step semantics
- [ ] `uv run pytest --no-cov` passes
- [ ] All guardrail rules reference only files that exist

---

## Stage 8: Fix GameWorld Runtime Host Duplication

`GameWorld` split did not result in a clean shared runtime-host abstraction. Lifecycle, camera, and render ownership glue is duplicated across debug/test hosts.

### Tasks

- [ ] Extract shared lifecycle/camera/render host interface from `arsenal_debug.py`, `lighting_debug.py`, and `tests/world_runtime.py`
- [ ] Eliminate duplication — each host should only override what is actually different

### Remaining findings

- **[medium]** Debug and test hosts (`arsenal_debug.py:168`, `lighting_debug.py:1331`, `tests/world_runtime.py:91`) duplicate the same initialization and camera/render ownership glue

### Acceptance

- [ ] Lifecycle, camera, and render setup code exists in exactly one place
- [ ] Debug/test hosts compose or inherit from the shared abstraction
- [ ] All debug view and world runtime tests pass
