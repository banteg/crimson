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

## 6. Target Architecture

### 6.1 Domain Types (new)

Introduce typed command unions:

- `src/crimson/sim/commands.py`

```python
from __future__ import annotations
from typing import TypeAlias
import msgspec

class PerkPickCommand(msgspec.Struct, tag="perk_pick", frozen=True):
    player_index: int
    choice_index: int
    expected_perk_id: int | None = None

GameCommand: TypeAlias = PerkPickCommand
```

Tick packet type:

```python
class TickPacket(msgspec.Struct, frozen=True):
    status: InputStatus
    inputs: list[PlayerInput]
    commands: tuple[GameCommand, ...] = ()
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

1. Provider returns `TickPacket(status, inputs, commands)`.
2. Session applies typed commands in deterministic command phase.
3. Session runs deterministic world step.
4. Session returns `DeterministicSessionStepTick` + command hash/state hash metadata.

No separate replay event pre/post phase exists.

### 6.3 Command Phase Placement

Commands are applied at tick start (before world step) within `DeterministicSession.step_tick`.

Rationale:

- Deterministic state mutation belongs to deterministic phase.
- Command hash can include command effects.
- Replay/live/LAN naturally share exact semantics.

### 6.4 Replay Runtime Unification

`ReplayPlaybackMode` must not orchestrate tick semantics itself.

- It may own rendering/audio/UI only.
- Tick progression must call the same engine that verify/info use.
- No direct custom semantics around replay events.

## 7. File-Level Implementation Plan

### 7.1 Replay Types and Codec

Update:

- `src/crimson/replay/types.py`
- `src/crimson/replay/codec.py`
- `src/crimson/replay/recorder.py`
- `src/crimson/replay/journal.py`
- `src/crimson/replay/__init__.py`

Changes:

1. Bump replay format version (v9).
2. Replace `inputs + dt + events` with `ticks: list[ReplayTick]`.
3. Delete `PerkPickEvent`, `PerkMenuOpenEvent`, `ReplayEvent`.
4. Delete dt-row logic in codec and runner contracts.
5. Recorder writes commands inline per tick.

### 7.2 Input Provider and Runner Contracts

Update:

- `src/crimson/sim/input_providers.py`
- `src/crimson/sim/tick_runner.py`
- `src/crimson/sim/hooks.py` (if needed for metadata)

Changes:

1. Replace `pull_tick_input + pull_tick_commands` with `pull_tick_packet`.
2. Remove command queue dictionary from providers.
3. `TickRunner` consumes `TickPacket` and passes commands into session.
4. Remove fallback string-command plumbing.

### 7.3 Deterministic Session Command Application

Update:

- `src/crimson/sim/sessions.py`
- `src/crimson/sim/step_pipeline.py` (hash input if needed)
- new `src/crimson/sim/commands.py`

Changes:

1. Extend `DeterministicSession.step_tick(..., commands: tuple[GameCommand, ...])`.
2. Apply commands via typed `match` dispatch.
3. Include command stream in command-hash material.
4. Remove command application from mode post-processing hooks.

### 7.4 Gameplay Modes (Live/LAN)

Update:

- `src/crimson/modes/base_gameplay_mode.py`
- `src/crimson/modes/survival_mode.py`
- `src/crimson/modes/quest_mode.py`

Changes:

1. Remove `InputCommand` dynamic usage.
2. Replace `_record_perk_pick_command` with typed command enqueue.
3. Remove `_apply_tick_commands` path and post-tick command mutation.
4. Use one typed command queue consumed by provider into packet.

### 7.5 Replay Drivers

Update:

- `src/crimson/sim/driver/playback_driver.py`
- `src/crimson/sim/driver/replay_runner.py`
- `src/crimson/sim/driver/replay_info.py`
- `src/crimson/modes/replay_playback_mode.py`
- `src/crimson/sim/driver/replay_benchmark.py`
- `src/crimson/sim/driver/replay_render.py`

Changes:

1. Delete replay event partition/apply code paths.
2. Delete `PlaybackEventConfig` replay-event semantics.
3. Remove `terminal_events_use_resolved_dt` and related behavior.
4. Playback mode delegates simulation stepping to the same driver engine as verify/info.
5. Keep playback mode focused on presentation only.

### 7.6 LAN Typed Command Parity

Update:

- LAN input provider helpers in `base_gameplay_mode.py`
- lockstep event translation modules

Changes:

1. Translate network perk events into `GameCommand` typed union.
2. Remove string command generation.
3. Preserve host/join deterministic hash parity with command stream included.

## 8. Planned Deletions

Delete completely:

- `Replay.events` and related types/codec validation.
- Replay event helpers (`sim/driver/replay_events.py`) and callers.
- `InputCommand(name, payload)` string dictionary path.
- Mode-level `_apply_input_command` pattern for deterministic commands.
- Replay timing/event knobs that existed only for split paths.

## 9. PR Slicing

### PR-A: Type Foundations

Scope:

- Add typed command unions and packet types.
- Introduce runner/provider API changes behind compile break.

Exit checks:

- All callsites compile with new typed contracts.
- No `InputCommand.name` string dispatch remains in touched paths.

### PR-B: Deterministic Session Command Phase

Scope:

- Apply commands in `DeterministicSession.step_tick`.
- Hash command stream.

Exit checks:

- Live mode command effects still function.
- Command hash changes when command stream changes.

### PR-C: Replay v2 Format

Scope:

- Replace replay schema with `ticks[]`.
- Codec/recorder/journal rewrite.

Exit checks:

- Replay roundtrip encode/decode works for new fixtures.
- Loading old replay versions fails fast with clear error.

### PR-D: Replay Runtime Unification

Scope:

- Remove replay event plumbing from playback driver.
- Route replay play through same deterministic stepping semantics as verify/info.

Exit checks:

- `replay verify` and playback-derived run result parity for fixtures.
- No custom replay semantic branches in playback mode.

### PR-E: LAN and Cleanup

Scope:

- Move LAN command path to typed unions.
- Delete legacy command/replay event code.

Exit checks:

- LAN hash contract tests pass.
- Deleted modules not referenced.

### PR-F: Docs + Guardrails

Scope:

- Update docs and architecture contracts.
- Add regression tests that enforce single-path semantics.

Exit checks:

- New architecture docs merged.
- CI guards block reintroduction of split paths.

## 10. PRD Checks (Pass/Fail Gates)

### Check Group A: Type Safety

- [ ] No `InputCommand(name: str, payload: dict)` in deterministic flow.
- [ ] Deterministic command APIs accept only `GameCommand` union.
- [ ] Replay schema has no `events` field.

Validation:

- `rg "InputCommand\\(|name=\"perk_pick\"|payload=" src`
- `uv run ty`

### Check Group B: Single Orchestration

- [ ] Replay verify/info/play use one deterministic tick orchestration contract.
- [ ] Playback mode contains no replay event timing logic.

Validation:

- Contract tests in `tests/test_architecture_contracts.py`
- grep check for deleted replay-event functions in live code paths.

### Check Group C: Deterministic Parity

- [ ] `verify` vs playback run result parity on all replay fixtures.
- [ ] `verify` vs playback checkpoint/state-hash parity on sampled ticks.
- [ ] LAN host/join state hash parity unchanged.

Validation:

- `uv run pytest tests/test_replay_fixture_integrations.py --run-replay-fixtures`
- `uv run pytest tests/test_architecture_contracts.py`
- `uv run pytest tests/test_lan_* tests/test_net_* tests/test_relay_*`

### Check Group D: Replay v2 Behavior

- [ ] Recorder emits replay v2 only.
- [ ] Old replay versions fail load with explicit unsupported-version error.
- [ ] Replay CLI commands operate only on replay v2.

Validation:

- replay codec tests + CLI tests:
- `uv run pytest tests/test_replay_codec.py tests/test_replay_cli.py`

### Check Group E: Deletion Completeness

- [ ] `sim/driver/replay_events.py` deleted.
- [ ] No references to `PerkMenuOpenEvent` or `PerkPickEvent` in runtime replay execution.
- [ ] No references to `terminal_events_use_resolved_dt`.

Validation:

- `rg "PerkMenuOpenEvent|PerkPickEvent|terminal_events_use_resolved_dt|replay_events"`

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
