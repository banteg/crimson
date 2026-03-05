# Split-Brain Architecture Note

This note supplements `plan.md`.

Its purpose is narrower: describe the current architectural split-brain in the runtime, show what is already unified, and make the target shape concrete enough that future refactors can be judged against it.

## What Is Already Unified

Not everything is split-brained anymore.

- `DeterministicSession` is already the center of the deterministic step.
- Replay ticks already carry `dt + inputs + commands`.
- Lockstep `TickFrame` already carries deterministic `commands`.
- The sim plan/apply split is already shared in important paths.

That matters because the remaining work is no longer "invent a deterministic runtime". The remaining work is to remove the mismatched ownership and orchestration layers still wrapped around it.

## Current Split-Brain

Today the runtime still has several competing representations of the same truth.

### 1) One tick is still fetched as two things

The provider/runner contract still treats a deterministic tick as:

- `pull_tick_input(tick_index)`
- `pull_tick_commands(tick_index)`

That means replay and lockstep already think in canonical ticks, while the runtime API still reconstructs the same tick from separate calls.

### 2) Mode runtime state has multiple owners

The same gameplay truth is often mirrored across:

- mode-local shadow state such as `_SurvivalState`, `_RushState`, `_QuestRunState`
- deterministic spawn/runtime state such as `SurvivalSpawnState`, `RushSpawnState`, `QuestSpawnState`
- generic tick result objects such as `DeterministicSessionTick` and `PlaybackTickOutcome`

Quest is the clearest example: state is copied into `QuestSpawnState`, stepped deterministically, then copied back into `_QuestRunState`, while some of the same data is also carried through generic tick/result types.

### 3) The frame pump exists in several places

Variants of the same loop exist in:

- `src/crimson/modes/base_gameplay_mode.py`
- `src/crimson/world/runtime.py`
- `src/crimson/modes/replay_playback_mode.py`
- `src/crimson/sim/driver/playback_driver.py`

They all decide how many ticks to run, step the session, apply metadata, apply presentation outputs, and optionally record/checkpoint/sync.

### 4) Presentation reactions are not yet fully single-sourced

The deterministic step can already plan presentation work, but some reactions still live in ad hoc runtime code:

- perk-pick UI SFX
- quest hit SFX
- quest completion music
- mode-specific "after tick" presentation behavior

That creates live-vs-replay duplication pressure.

## Current Architecture

```mermaid
flowchart TD
    subgraph Sources["Tick / Input Sources"]
        Local["LocalInputProvider"]
        Lan["LAN lockstep runtime<br/>TickFrame {inputs, commands}"]
        Replay["ReplayTick {dt, inputs, commands}"]
    end

    subgraph ProviderLayer["Provider / Runner Contract"]
        Provider["InputProvider<br/>pull_tick_input()<br/>pull_tick_commands()"]
        Runner["TickRunner"]
        Session["DeterministicSession"]
    end

    subgraph StateOwners["Competing State Owners"]
        ModeShadow["Mode shadow state<br/>_SurvivalState / _RushState / _QuestRunState"]
        SpawnState["Spawn/runtime state<br/>SurvivalSpawnState / RushSpawnState / QuestSpawnState"]
        GenericTick["Generic tick/result payloads<br/>DeterministicSessionTick / PlaybackTickOutcome"]
    end

    subgraph Drivers["Frame Drivers"]
        Base["BaseGameplayMode"]
        World["WorldRuntime"]
        ReplayMode["ReplayPlaybackMode"]
        Playback["PlaybackDriver"]
    end

    Local --> Provider
    Lan --> Provider
    Provider --> Runner --> Session
    Replay --> Playback --> Session

    Session --> SpawnState
    Session --> GenericTick
    SpawnState <-->|copy in/out| ModeShadow
    GenericTick -->|re-expresses mode state| ModeShadow

    Base -->|step + apply + record + sync| Runner
    World -->|step + apply| Runner
    ReplayMode -->|apply + special reactions| Playback
```

## Why This Hurts

The cost is not just conceptual neatness.

- The same gameplay fact can drift between multiple owners.
- Tests have to know about implementation wiring instead of one contract.
- Replay, live, LAN, and rollback stay harder to compare because they do not all enter the core through the same shape.
- Refactors tend to add compatibility with both the old and new model instead of deleting the old one.

## Goal Architecture

The goal is not "more layers". The goal is one canonical tick shape, one authoritative owner for mode runtime state, and one shared stepping/apply path.

### Canonical Tick

At the runtime boundary, one deterministic tick should be one object:

```python
@dataclass(frozen=True)
class ResolvedTick:
    tick_index: int
    dt_seconds: float
    inputs: list[PlayerInput]
    commands: list[GameCommand]
```

This does not need to become a giant new subsystem. It just needs to replace the split provider contract decisively.

### Authoritative Mode Runtime State

Per mode, there should be one authoritative owner for dynamic deterministic state.

- Survival: session timing + `SurvivalSpawnState`
- Rush: session timing + `RushSpawnState`
- Quest: quest metadata + `QuestSpawnState`

UI-facing caches or read models are fine, but they should not be separate sources of truth.

### Shared Frame-Step / Apply Path

Local play, lockstep, replay playback, and rollback should all feed the same basic runtime loop shape:

1. get a canonical tick
2. step the deterministic session
3. apply sim metadata
4. apply presentation outputs/reactions
5. optionally record, checkpoint, or sync

## Goal Architecture Diagram

```mermaid
flowchart TD
    subgraph Sources2["Canonical Tick Sources"]
        Local2["Local tick source"]
        Lockstep2["Lockstep tick source"]
        Replay2["Replay tick source"]
        Rollback2["Rollback controller<br/>+ committed tick source"]
    end

    Tick["ResolvedTick<br/>{tick_index, dt, inputs, commands}"]

    subgraph Core2["Shared Runtime Core"]
        Loop["Shared frame-step/apply path"]
        Session2["DeterministicSession"]
        Present["Single-sourced presentation reactions"]
        Record["Replay recording / checkpoints / sync hooks"]
    end

    subgraph Mode2["Mode Runtime"]
        ModeRuntime["Authoritative mode runtime state"]
        UI["Mode UI / HUD / transitions"]
    end

    Local2 --> Tick
    Lockstep2 --> Tick
    Replay2 --> Tick
    Rollback2 --> Tick

    Tick --> Loop
    Loop --> Session2
    Session2 --> ModeRuntime
    Loop --> Present
    Loop --> Record
    ModeRuntime --> UI
    Present --> UI
```

## Guardrails

The target shape should reduce complexity, not relocate it.

- Do not add a new tick type unless it replaces an old one.
- Do not introduce a `ModeRuntimeAdapter` that becomes a second god object.
- Do not extract a `SimulationLoop` so broad that mode-specific concerns become harder to see.
- Prefer shrinking contracts and deleting duplicate ownership before introducing named abstractions.

## Highest-Value Next Step

The best next refactor is to unify the provider contract so one tick is returned in one call.

That is the highest-leverage remaining split-brain because:

- replay already has canonical ticks
- lockstep already has canonical frames
- `TickRunner` is still reconstructing a tick from split provider calls
- deleting that split will simplify tests, live/replay parity, and future mode-state cleanup

If that contract is cleaned up first, the later state-ownership and orchestration refactors become smaller and easier to reason about.
