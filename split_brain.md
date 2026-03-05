# Split-Brain Architecture Note

This note supplements `plan.md`.

Its purpose is narrower: describe the current architectural split-brain in the runtime, show what is already unified, and make the target shape concrete enough that future refactors can be judged against it.

## What Is Already Unified

Not everything is split-brained anymore.

- `DeterministicSession` is already the center of the deterministic step.
- The provider/runner contract now uses one canonical pre-step tick object: `ResolvedTick`.
- Replay ticks already carry `dt + inputs + commands`.
- Lockstep `TickFrame` already carries deterministic `commands`.
- `TickResult` now carries the source `ResolvedTick`, so replay/live/LAN share the same in-memory pre-step tick shape.
- Quest dynamic runtime state now lives in `QuestSpawnState` plus `DeterministicSession.elapsed_ms`; generic tick/result types no longer re-express quest-only fields.
- Survival and rush dynamic runtime now live in `DeterministicSession.elapsed_ms` plus `SurvivalSpawnState` / `RushSpawnState`; the live mode shadow structs are gone.
- Survival and rush now also share one explicit session-timer access path in gameplay code, instead of each mode carrying its own mirror helper.
- Quest rollback/resync snapshots now carry the authoritative quest runtime, including the remaining spawn table.
- Live `TickRunner` frame advancement is now shared between `BaseGameplayMode` and `WorldRuntime`, including `FrameContext` setup, tick-index bookkeeping, and stall/EOS debt refund.
- Replay playback frame advancement is now also shared, including replay clock advancement, `step_tick()` iteration, immediate sim metadata apply, and replay tick-limit debt refund.
- The sim plan/apply split is already shared in important paths.

That matters because the remaining work is no longer "invent a deterministic runtime". The remaining work is to remove the mismatched orchestration and reaction layers still wrapped around it.

## Current Split-Brain

Today the runtime still has a couple of architectural seams where the same work is expressed in more than one place.

Timer semantics are no longer one of the fuzzy parts:

- survival and rush use the deterministic session elapsed timer
- quest runtime still owns `spawn_timeline_ms` for quest progression, replay elapsed stats, and quest results timing
- session-timer access in active gameplay now asserts on invalid lifecycle use instead of silently falling back

### 1) Replay stepping still has some higher-level duplication

The lowest-level frame bookkeeping is now shared for both live and replay stepping, but some replay consumers still open-code their own `step_tick()` loops above that layer:

- `src/crimson/sim/driver/playback_driver.py`
- `src/crimson/sim/driver/replay_info.py`

That is a smaller problem than before. `ReplayPlaybackMode` no longer hand-rolls the replay clock/step/apply loop, so the remaining drift is concentrated in driver-level utilities and higher-level bookkeeping around stepped replay ticks.

### 2) Presentation reactions are not yet fully single-sourced

The deterministic step can already plan presentation work, and quest now computes its runtime flags in one place, but some reactions still live in ad hoc runtime code:

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

    subgraph TickContract["Canonical Tick Contract"]
        Provider["InputProvider<br/>pull_tick()"]
        Tick["ResolvedTick"]
        Runner["TickRunner"]
        Session["DeterministicSession"]
        Result["TickResult<br/>source_tick + payload"]
    end

    subgraph StateOwners["Authoritative Runtime Owners"]
        SurvivalState["Survival runtime<br/>shared session.elapsed_ms + SurvivalSpawnState"]
        RushState["Rush runtime<br/>shared session.elapsed_ms + RushSpawnState"]
        QuestState["Quest runtime<br/>QuestSpawnState + session.elapsed_ms<br/>plus quest timeline for results/replay"]
    end

    subgraph Drivers["Frame Drivers"]
        Base["BaseGameplayMode"]
        World["WorldRuntime"]
        ReplayMode["ReplayPlaybackMode"]
        ReplayPump["Shared replay playback frame pump"]
        Playback["PlaybackDriver"]
    end

    Local --> Provider
    Lan --> Provider
    Provider --> Tick --> Runner --> Session --> Result
    Replay --> Playback --> Tick

    Session --> SurvivalState
    Session --> RushState
    Session --> QuestState

    Base -->|step + apply + record + sync| Runner
    World -->|step + apply| Runner
    ReplayMode -->|presentation callbacks + finish logic| ReplayPump
    ReplayPump -->|shared replay step + apply| Playback
    Playback --> QuestState
```

## Why This Hurts

The cost is not just conceptual neatness.

- The same stepping and apply responsibilities can drift between multiple call sites.
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

The best next refactor is now to finish centralizing presentation reactions.

That is the highest-leverage remaining split-brain because:

- canonical ticks already landed
- quest, survival, and rush now use authoritative runtime owners instead of mode-local mirrors
- live and replay frame advancement now share their low-level bookkeeping
- replay and live mode code still carry custom post-tick side effects for perk picks, quest hit SFX, quest completion music, and similar reactions

After presentation reactions are single-sourced, the remaining cleanup is mostly driver-level replay loop consolidation and other narrower orchestration tidy-ups.
