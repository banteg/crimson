# PRD: Replay V2 Type-Driven Deterministic Runtime

Date: 2026-03-05  
Status: Ready for implementation  
Owner: sim/replay stack

## 1. Summary

We will replace the current replay architecture with a single type-driven deterministic runtime contract.

Hard decisions for simplicity:

- No replay backward compatibility.
- No legacy event side-channel (`Replay.events`).
- No stringly command payloads (`InputCommand.name/payload`).
- No terminal tick event phase.
- Perk menu opening remains explicit as a typed command to preserve deterministic RNG draw timing.
- Replay playback reads replay ticks directly (no replay `InputProvider`/`Journal` layer).
- LAN deterministic commands travel on host-authored canonical tick frames (not out-of-band net messages).
- Command model is intentionally closed: only perk menu open + perk pick command variants.
- No hash/checksum fields in deterministic runtime or replay sidecars.
- One tick orchestration path for live, replay verify, replay play, replay render, replay benchmark, and LAN.

Core change:

- Encode deterministic actions as typed per-tick commands (union types), stored inline with tick inputs.
- Apply commands in deterministic tick execution, not in mode-specific post-step hooks.

## 2. Problem Statement

Current split-brain comes from structural duplication:

- Replay verify/info use `PlaybackDriver` tick meta pipeline.
- Replay play drives `TickRunner` directly in `ReplayPlaybackMode`.
- Replay commands are split between `inputs[]` and `events[]`.
- Live/LAN perk picks use dynamic command dicts and are applied outside deterministic tick step.

This permits silent drift: a path can run valid ticks while forgetting replay events/commands.

## 3. Goals

1. One deterministic execution contract across all entrypoints.
2. Strictly typed command model end-to-end.
3. Replay file format where each tick is self-contained (`inputs + commands`).
4. Remove replay-only orchestration knobs and branching semantics.
5. Make split-brain impossible by type/contract, not convention.

## 4. Non-Goals

1. Preserve old `.crd` files.
2. Keep current replay wire/storage schema.
3. Keep dynamic command dictionaries.
4. Preserve exact pre-change perk timing edge semantics.

## 5. Design Principles

1. Type-first APIs: tagged unions and structs only, no string dispatch.
2. Single source of truth: one engine step path for all modes.
3. Tick locality: all deterministic inputs for tick `N` live in tick record `N`.
4. Deletion over adaptation: remove legacy branches rather than maintain toggles.
5. Closed command scope: do not build extension machinery for command kinds that do not exist in game scope.

## 6. Target Architecture

### 6.1 Domain Types (new)

Introduce a closed typed command union (no extensibility hooks), colocated with existing sim input contracts (no standalone `sim/commands.py` file):

```python
from __future__ import annotations
from typing import TypeAlias
import msgspec

class PerkMenuOpenCommand(msgspec.Struct, tag="perk_menu_open", frozen=True):
    player_index: int

class PerkPickCommand(msgspec.Struct, tag="perk_pick", frozen=True):
    player_index: int
    choice_index: int

GameCommand: TypeAlias = PerkMenuOpenCommand | PerkPickCommand
```

Replay v2 tick record type:

```python
class ReplayTick(msgspec.Struct, frozen=True):
    inputs: PackedTickInputs
    commands: tuple[GameCommand, ...] = ()
```

Replay v2 root type:

```python
class Replay(msgspec.Struct):
    header: ReplayHeader
    ticks: list[ReplayTick]
```

### 6.2 Deterministic Tick Contract (new canonical flow)

For each tick:

1. Runtime resolves inputs + commands for the tick.
2. Session applies typed commands in deterministic command phase.
3. Session runs deterministic world step.
4. Session returns `DeterministicSessionStepTick` + applied-command metadata.

No separate replay event pre/post phase exists.

### 6.3 Command Phase Placement

Commands are applied at tick start (before world step) within `DeterministicSession.step_tick`.

Rationale:

- Deterministic state mutation belongs to deterministic phase.
- Typed command tuples are explicit and can be compared directly.
- Replay/live/LAN naturally share exact semantics.

### 6.4 Replay Runtime Unification

`ReplayPlaybackMode` must not orchestrate tick semantics itself.

- It may own rendering/audio/UI only.
- Tick progression must call the same engine that verify/info use.
- No direct custom semantics around replay events.
- `PlaybackDriver` iterates `Replay.ticks` directly.
- `ReplayInputProvider` and `ReplayJournal` are removed instead of being retyped.

### 6.5 Perk Menu RNG Semantics (explicit decision)

`PerkMenuOpenEvent` is removed only after replacing it with `PerkMenuOpenCommand`.

- `PerkMenuOpenCommand` runs in the deterministic command phase at tick start.
- Its handler must execute the same choice-generation path (`perk_selection_current_choices`) currently triggered by menu-open handling.
- This preserves RNG consumption timing even when menu is opened and closed without picking.

## 7. File-Level Implementation Plan

### 7.1 Replay Types and Codec

Update:

- `src/crimson/replay/types.py`
- `src/crimson/replay/codec.py`
- `src/crimson/replay/recorder.py`
- `src/crimson/replay/__init__.py`

Changes:

1. Bump replay format version (v9).
2. Replace `inputs + dt + events` with `ticks: list[ReplayTick]`.
3. Delete `PerkPickEvent`, `PerkMenuOpenEvent`, `ReplayEvent`.
4. Keep per-tick dt only if source capture requires it; do not assume fixed dt unless fixtures confirm it.
5. Recorder writes commands inline per tick via append-only `record_tick(inputs, commands=...)`.
6. Delete recorder random-access/event helper APIs (`record_tick_at`, `record_perk_pick`, `record_perk_menu_open`).
7. Delete replay journal adapter (`src/crimson/replay/journal.py`) and replay journal exports.

### 7.2 Input Provider and Runner Contracts

Update:

- `src/crimson/sim/input_providers.py`
- `src/crimson/sim/tick_runner.py`
- `src/crimson/sim/hooks.py` (if needed for metadata)

Changes:

1. Retype existing command hooks to typed command values (`pull_tick_commands -> tuple[GameCommand, ...]`).
2. Remove command queue dictionary from providers.
3. `TickRunner` passes typed commands into session.
4. Remove fallback string-command plumbing.
5. Remove replay-specific provider paths entirely (`ReplayInputProvider`, `ReplayJournal` protocol usage).

### 7.3 Deterministic Session Command Application

Update:

- `src/crimson/sim/sessions.py`
- `src/crimson/sim/step_pipeline.py`
- `src/crimson/sim/input_providers.py` (or existing command contract module)

Changes:

1. Extend `DeterministicSession.step_tick(..., commands: tuple[GameCommand, ...])`.
2. Apply commands via typed `match` dispatch.
3. Remove all hash generation/propagation from deterministic tick outputs.
4. Remove command application from mode post-processing hooks.

### 7.4 Gameplay Modes (Live/LAN)

Update:

- `src/crimson/modes/base_gameplay_mode.py`
- `src/crimson/modes/survival_mode.py`
- `src/crimson/modes/quest_mode.py`

Changes:

1. Remove `InputCommand` dynamic usage.
2. Replace `_record_perk_pick_command` with typed command enqueue.
3. Record perk-menu-open as `PerkMenuOpenCommand` at the same points where `record_perk_menu_open` is currently emitted.
4. Remove `_apply_tick_commands` path and post-tick command mutation.
5. Use one typed command queue consumed deterministically at tick boundaries.

### 7.5 Replay Drivers

Update:

- `src/crimson/sim/driver/playback_driver.py`
- `src/crimson/sim/driver/replay_runner.py`
- `src/crimson/sim/driver/replay_info.py`
- `src/crimson/modes/replay_playback_mode.py`
- `src/crimson/sim/driver/replay_benchmark.py`
- `src/crimson/sim/driver/replay_render.py`

Changes:

1. Collapse `PlaybackDriverConfig` to a minimal surface and remove per-caller policy matrix construction.
2. Add canonical `PlaybackDriver.step_tick(...) -> PlaybackTickOutcome | None`.
3. Make `run_to_completion` iterate via `step_tick` (no duplicate orchestration loop).
4. Make `ReplayPlaybackMode` advance simulation via `PlaybackDriver.step_tick`.
5. Delete replay event partition/apply code paths and terminal-event phase machinery completely.
6. Collapse `PlaybackTickOutcome` to core deterministic data (`tick_index`, `dt`, session step payload, rng marks, command stream metadata).
7. Remove `PlaybackTickOutcome` fields that only exist for event split (`tick_events`, `pre_step_events`, `post_step_events`, `rng_before_events`, `rng_after_events`, `rng_before_post_events`, `rng_after_post_events`).
8. Keep playback mode focused on presentation only.
9. Tick observers receive applied commands only (no replay event lists).

### 7.6 LAN Typed Command Parity

Update:

- LAN input provider helpers in `base_gameplay_mode.py`
- lockstep event translation modules

Changes:

1. Move perk commands into host-authored canonical tick frame payloads.
2. Remove `PerkMenuOpen`/`PerkMenuClose`/`PerkPick` out-of-band `NetMessage` variants and pending perk-event queues.
3. Do not attach commands to `InputSample`; keep host-authoritative command stream in canonical frame path.
4. Remove string command generation.
5. Compare command streams directly (`tuple[GameCommand, ...]` equality) and compare canonical state snapshots structurally.

## 8. Planned Deletions

Delete completely:

- `Replay.events` and related types/codec validation.
- Replay event helpers (`sim/driver/replay_events.py`) and callers.
- `InputCommand(name, payload)` string dictionary path.
- Hash/checksum fields and plumbing in this stack:
- `command_hash`, `state_hash`, `status_hash` fields/computation/plumbing.
- replay/checkpoint digest links (`replay_sha256`) and related validation.
- trace/resync payload checksums and digests used only for replay/debug artifacts.
- `ReplayInputProvider` and replay `ReplayJournal` protocol/adapter layers.
- `ReplayRecorder.record_tick_at`, `ReplayRecorder.record_perk_pick`, `ReplayRecorder.record_perk_menu_open`.
- Event-partitioning-only outcome/config surface (`PlaybackTickOutcome` event split fields, `PlaybackEventConfig`, runtime `partition_tick_events` hooks).
- `PlaybackEventConfig`, `apply_terminal_events`, `_terminal_events_applied`, and other terminal-event code paths.
- Duplicated per-entrypoint `PlaybackDriverConfig` policy matrices.
- Mode-level `_apply_input_command` pattern for deterministic commands.
- Replay timing/event knobs that existed only for split paths.
- Lockstep out-of-band perk net messages and `_pending_perk_events` alignment queues.

## 9. PR Slicing

### PR-A: Typed Command Contract

Scope:

- Add closed typed command unions.
- Migrate providers, runner, and session signatures to typed command flow.
- Remove stringly command usage from deterministic runtime paths.
- Remove hash/checksum plumbing in favor of direct typed-struct comparison.

Exit checks:

- All callsites compile with new typed contracts.
- Command application happens only in `DeterministicSession.step_tick`.
- No hash/checksum fields remain in deterministic contracts.

### PR-B: Replay v2 Schema + Recorder Simplification

Scope:

- Replace replay schema with `ticks[]`.
- Codec/recorder rewrite to replay v2 only.
- Make recorder append-only via `record_tick(inputs, commands=...)`.
- Delete replay journal adapter and replay-provider usage.
- Regenerate replay fixtures/checkpoints in replay v2.

Exit checks:

- Replay roundtrip encode/decode works for new fixtures.
- Loading old replay versions fails fast with clear error.
- Recorder has no random-access/event helper APIs.
- Playback driver reads replay ticks directly without `ReplayInputProvider`.

### PR-C: Playback Driver Unification + Deletion Pass

Scope:

- Collapse `PlaybackDriverConfig` surface.
- Add canonical `PlaybackDriver.step_tick`.
- Route both `run_to_completion` and playback mode through `step_tick`.
- Delete replay-event and terminal-event machinery.
- Remove event-bearing tick observers/outcome fields.

Exit checks:

- Replay play and verify share the same replay-tick execution method.
- No replay-event/terminal-event branches remain in runtime code paths.
- Tick observers operate on commands, not replay events.

### PR-D: LAN + Guardrails

Scope:

- Move LAN command path to typed unions on canonical tick frames.
- Delete remaining dynamic command plumbing and stale split-path code.
- Add/refresh deterministic parity guardrails and docs.

Exit checks:

- LAN deterministic parity tests pass using typed-command and structural state comparisons.
- Verify-vs-playback fixture parity test is available as a slow opt-in validation and passes when run explicitly.
- New architecture docs merged.
- No out-of-band perk net messages remain.
- No hash/checksum protocol fields remain; LAN command parity uses direct tuple equality.

## 10. PRD Checks (Pass/Fail Gates)

### Check Group A: Replay v2 + Type Safety

- [ ] Deterministic command APIs accept only `GameCommand` union.
- [ ] Replay schema is `ticks[]` only (no `events`).
- [ ] Recorder API is append-only.
- [ ] Deterministic contracts contain no hash/checksum fields.

Validation:

- `uv run ty`
- `uv run pytest tests/test_replay_codec.py tests/test_replay_cli.py`

### Check Group B: Single Replay Tick Engine

- [ ] `PlaybackDriver.step_tick` is the canonical replay tick executor.
- [ ] `run_to_completion` and `ReplayPlaybackMode` both execute replay ticks via `step_tick`.
- [ ] Terminal-event phase is deleted.
- [ ] Replay tick execution does not instantiate replay-specific providers/journals.

Validation:

- `uv run pytest tests/test_architecture_contracts.py`

### Check Group C: Verify-vs-Playback Fixture Parity

- [ ] `verify` vs chunked `PlaybackDriver.step_tick` playback run result parity on all replay fixtures.
- [ ] `verify` vs chunked `PlaybackDriver.step_tick` playback checkpoint structural parity on sampled fixture ticks.

Validation:

- `uv run pytest tests/test_replay_fixture_integrations.py --run-replay-fixtures -k verify_vs_playback_parity`

### Check Group D: LAN Deterministic Parity

- [ ] LAN host/join structural state parity unchanged.
- [ ] LAN command path uses canonical tick-frame commands; no out-of-band perk messages.
- [ ] LAN command parity uses direct typed-command tuple equality (no hash fallback).

Validation:

- `uv run pytest tests/test_lan_* tests/test_net_* tests/test_relay_*`

## 11. Risks and Mitigations

Risk: semantic changes around perk timing may alter feel.  
Mitigation: explicitly lock new command-phase contract; update tests and docs to match.

Risk: large compile break across providers/modes.  
Mitigation: PR-A introduces shared types and mechanical migration first.

Risk: replay tooling churn.  
Mitigation: ship converter only if needed for developer fixtures; no runtime dual support.

## 12. Definition of Done

1. Replay v2 type schema merged and old schema removed.
2. Stringly command path removed from deterministic runtime.
3. Replay play/verify/info/render/benchmark share one deterministic stepping contract.
4. CI parity gates pass and guard against regression.
5. Architecture docs match implementation and deletion set is complete.
