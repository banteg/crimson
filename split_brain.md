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
- Post-apply presentation reactions are now shared too: perk-apply bonus SFX, quest hit SFX, quest completion music, and replay/live quest overlay timer updates all route through one small reaction layer.
- Driver-side replay utilities now share one canonical multi-tick walk path through `PlaybackDriver.walk_ticks()`, and replay checkpoint construction is no longer hidden behind private driver helpers.
- Replay stepping itself now also converges on `TickResult`; `PlaybackTickOutcome`, `run_replay()`, and `run_replay_info()` are gone.
- Most replay consumers now build drivers through `build_verify_playback_driver()` / `build_runtime_playback_driver()`, and replay info collection goes through `collect_replay_info(driver, ...)`.
- Ordinary repo call sites are now factory-first; raw `PlaybackDriver(...)` construction is kept only as a low-level/manual surface and a focused default-parity test.
- Quest title and completion overlays now also read directly from authoritative quest runtime instead of keeping separate live/replay timer copies.
- The sim plan/apply split is already shared in important paths.

That matters because the remaining work is no longer "invent a deterministic runtime". The remaining work is to remove the mismatched orchestration and reaction layers still wrapped around it.

## Current Split-Brain

Today the large split-brain targets are mostly gone. What remains is much smaller and is closer to API-shape polish than to competing runtime owners.

Timer semantics are no longer one of the fuzzy parts:

- survival and rush use the deterministic session elapsed timer
- quest runtime still owns `spawn_timeline_ms` for quest progression, replay elapsed stats, and quest results timing
- session-timer access in active gameplay now asserts on invalid lifecycle use instead of silently falling back

### 1) Replay still exposes a low-level constructor surface, but normal usage is factory-first

Normal replay consumers now route through:

- `src/crimson/sim/driver/playback_driver.py`
- `src/crimson/sim/driver/replay_info.py`

`PlaybackDriver(...)` plus `PlaybackDriverConfig` is still available alongside the factory helpers, but that is now an advanced/manual edge rather than the normal repo path. That is not a runtime split brain anymore; it is just a wider-than-ideal low-level API surface.

### 2) Live and replay still use separate shared frame-pump helpers

Both sides now share their own bookkeeping:

- `src/crimson/sim/frame_pump.py`
- `src/crimson/sim/driver/playback_pump.py`

That is acceptable for now because live steps through `TickRunner` while replay steps through `PlaybackDriver.step_tick()`. The important point is that the duplication is now small, explicit, and local.

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
        Playback["PlaybackDriver<br/>step_tick -> TickResult<br/>walk_ticks + run + build_checkpoint"]
        ReplayFactories["Replay driver factories<br/>build_verify / build_runtime"]
        ReplayInfo["collect_replay_info(driver, ...)"]
        PostApply["Shared post-apply reactions"]
    end

    Local --> Provider
    Lan --> Provider
    Provider --> Tick --> Runner --> Session --> Result
    Replay --> ReplayFactories --> Playback --> Tick

    Session --> SurvivalState
    Session --> RushState
    Session --> QuestState

    Base -->|step + apply + record + sync| Runner
    World -->|step + apply| Runner
    ReplayMode -->|presentation callbacks + finish logic| ReplayPump
    ReplayPump -->|shared replay step + apply| Playback
    Playback --> ReplayInfo
    Base --> PostApply
    World --> PostApply
    ReplayMode --> PostApply
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

The big architectural goal is largely in place now.

The highest-leverage next cleanup is probably not another major convergence refactor. It is smaller surface-area tightening:

- decide whether the remaining low-level replay constructor/config surface should stay public or be more explicitly demoted
- keep pruning tests and tools away from low-level replay setup where that setup is now policy, not mechanism
- only revisit live-vs-replay pump unification if a smaller shared contract appears naturally; do not force a broad universal loop abstraction now

At this point the architecture is much closer to "one core with a few explicit edges" than to a real split-brain system.
