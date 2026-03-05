I studied the Python rewrite in `src/` and the test contracts in `tests/`.

Update (March 6, 2026): the canonical tick contract described here has since landed via `ResolvedTick` / `TickSupply`. The sections about split input/command pulling are now historical; the next highest-value target is authoritative mode-state ownership.

The important headline is that the core deterministic work is in better shape than the repo’s older docs imply. Two of the biggest architectural problems already appear to be fixed:

* Replay V2 is mostly real now: `ReplayTick` already carries `dt`, `inputs`, and `commands` in `src/crimson/replay/types.py`, and `ReplayRecorder.record_tick(..., commands=...)` writes them inline in `src/crimson/replay/recorder.py`.
* The old “quest needs its own session class” split has already been collapsed: `DeterministicSession` in `src/crimson/sim/sessions.py` now has hooks, and quest behavior is handled with `quest_post_step(...)` plus `QuestSpawnState`.

So the rewrite’s biggest remaining complexity is no longer the deterministic step itself. It is the orchestration around that step: how a tick is represented, where state is owned, and how live / LAN / rollback / replay all feed the same simulation.

## My read of the current architecture

What is already strong:

* `DeterministicSession` is the right center of gravity.
* `TickRunner` is small and clean.
* The plan/apply split is solid and explicitly tested in `tests/test_architecture_contracts.py`.
* Typed deterministic commands are a good move.
* Replay verification and headless execution are clearly first-class goals, which is the right call for parity and score validation.

What is still split-brained:

### 1) One deterministic tick is still represented as two separate streams

In `src/crimson/sim/input_providers.py`, the provider contract is still:

* `pull_tick_input(tick_index)`
* `pull_tick_commands(tick_index)`

Then `TickRunner` in `src/crimson/sim/tick_runner.py` pulls them separately and reconstructs the real tick on the fly.

That is the largest remaining structural problem.

You already decided at the replay format level that a tick is one thing: `dt + inputs + commands`. But the runtime API still treats it as two things and stitches them back together later. That means the codebase has two competing mental models of “what a tick is”.

That is classic split brain.

### 2) Mode state is mirrored in multiple places

This is the second major split brain.

Survival:

* `_SurvivalState` in `src/crimson/modes/survival_mode.py`
* `DeterministicSession.elapsed_ms`
* `SurvivalSpawnState`

Rush:

* `_RushState` in `src/crimson/modes/rush_mode.py`
* `DeterministicSession.elapsed_ms`
* `RushSpawnState`

Quest:

* `_QuestRunState`
* `QuestSpawnState`
* some quest-related metadata also echoed through `DeterministicSessionTick`

Quest is the clearest example. In `src/crimson/modes/quest_mode.py`:

* `_quest_prepare_lan_frame()` copies `_quest` into `_quest_spawn_state`
* `_quest_on_tick_applied()` copies `_quest_spawn_state` back into `_quest`
* resync restores `_quest`
* replay/output code reads `_quest`
* the actual deterministic post-step hook mutates `_quest_spawn_state`

That is too many owners for the same truth.

### 3) There are still multiple orchestration loops that do nearly the same thing

The deterministic “pump” is spread across:

* `BaseGameplayMode` in `src/crimson/modes/base_gameplay_mode.py`
* `WorldRuntime` tick harness in `src/crimson/world/runtime.py`
* replay playback in `src/crimson/modes/replay_playback_mode.py`
* replay stepping in `src/crimson/sim/driver/playback_driver.py`

They all do variants of:

* begin frame
* decide how many ticks to run
* step session
* apply metadata
* apply presentation outputs
* maybe record replay
* maybe checkpoint
* maybe sync network state

That duplication is a major reason the architecture still feels heavy.

### 4) Quest-only data still leaks into supposedly generic result types

`DeterministicSessionTick` in `src/crimson/sim/sessions.py` still carries quest-specific fields like:

* `spawn_timeline_ms`
* `no_creatures_timer_ms`
* `completion_transition_ms`
* `completed`
* `play_hit_sfx`
* `play_completion_music`

And `PlaybackTickOutcome` / `QuestPlaybackRuntime` continue the same pattern.

That is better than having a whole separate quest session class, but it is still a sign that the generic layer is compensating for the mode layer not having a single authoritative runtime state object.

### 5) Presentation-side reactions are still partly scattered

Examples:

* `_process_tick_batch_results()` in `BaseGameplayMode` manually plays the perk-pick SFX when it sees a `PerkPickCommand`.
* quest hit/completion music handling is done in mode-specific application code and again in replay playback logic.

You already have a good deterministic plan/apply split. These last pieces should also be centralized so live and replay do not need separate “oh, and also do this extra side effect” logic.

### 6) The docs are behind the code, which creates a human split brain

`docs/rewrite/deterministic-step-pipeline.md` still talks about:

* `SurvivalDeterministicSession`
* `RushDeterministicSession`
* `QuestDeterministicSession`
* `command_hash` as an active concept

But the code has already moved past that.

That mismatch matters. Contributors reading the docs get an obsolete architecture model, then read the code, then often preserve compatibility with both ideas instead of deleting the old one.

## What I think you are misunderstanding from the decompile

The biggest misunderstanding is not about individual gameplay rules. It is about **how much architectural special casing the original game actually needs**.

The native game likely has one gameplay timeline per mode. Your rewrite sometimes models the same thing as several interacting timelines:

* mode shadow state
* session state
* replay tick stream
* network tick frames
* side-band command queues

That extra indirection is useful for tooling, but it should live at the edges. Right now some of it leaked into the core representation of a tick and of mode state.

A second likely misunderstanding is around perk/menu events. Right now the code treats some UI-driven actions as special deterministic/network artifacts because that helped line up RNG history. That may be a correct temporary compatibility choice, but it is not a good permanent architecture boundary. The rewrite should distinguish much more clearly between:

* canonical deterministic commands
* purely local UI events
* presentation reactions

The more those stay mixed, the harder parity becomes to reason about.

## The architecture I would move toward

I would make the entire runtime revolve around a single canonical unit:

```python
@dataclass(frozen=True)
class ResolvedTick:
    tick_index: int
    dt_seconds: float
    inputs: list[PlayerInput]
    commands: list[GameCommand]
    source_meta: TickSourceMeta | None = None
```

Then build the whole system around four layers:

```text
Mode UI / menus / HUD
        |
ModeRuntimeAdapter   <- owns authoritative mode-specific sim state
        |
SimulationLoop       <- generic stepping / apply / record / checkpoint
        |
TickSource           <- local / replay / lockstep / rollback
        |
DeterministicSession <- one canonical sim step
```

### Concretely

* `DeterministicSession` stays the core.
* `TickSource` implementations produce `ResolvedTick`, not separate inputs and commands.
* `SimulationLoop` owns the shared “pump”.
* `ModeRuntimeAdapter` owns the authoritative per-mode state and snapshot logic.
* `BaseGameplayMode` becomes a UI shell, not a deterministic orchestration god object.

That keeps all your rewrite-only features:

* deterministic simulation
* replays
* score verification from replay
* lockstep multiplayer
* rollback multiplayer

But makes them all consumers/producers of the same canonical tick stream instead of parallel architectures.

## Specific recommendations

### 1) Collapse the provider contract to one atomic tick object

Replace the `InputProvider` split API with something like:

* `begin_frame(frame_ctx)`
* `pull_tick(tick_index) -> TickSupply`

Where `TickSupply` contains:

* status: ready / stalled / eos
* `ResolvedTick` when ready

That lets `TickRunner` consume exactly one object per step. No second call. No hidden queue. No chance of inputs and commands disagreeing.

This is the highest-leverage refactor in the whole repo.

It will simplify:

* `LocalInputProvider`
* `NetworkInputProvider`
* `TickRunner`
* replay recording
* lockstep adapters
* tests that currently have to reason about command propagation separately

It also makes replay verification stronger, because live and replay can use the same in-memory tick shape.

### 2) Make one object authoritative for mode runtime state

This is where a lot of accidental complexity disappears.

#### Survival

Delete `_SurvivalState` as an authority. Keep:

* `DeterministicSession.elapsed_ms`
* `SurvivalSpawnState`

UI/debug/HUD can read from those directly, or from a tiny read-only adapter.

#### Rush

Same idea:

* `DeterministicSession.elapsed_ms`
* `RushSpawnState`

No separate `_RushState` needed as the truth.

#### Quest

Quest needs two buckets:

* static run metadata: quest definition, level id, total spawn count, max trigger time
* dynamic sim state: `QuestSpawnState`

The dynamic truth should live in `QuestSpawnState`, not in both `_QuestRunState` and the session result payload.

`quest_name_timer_ms` is UI/transient state, so keeping that outside the deterministic state is fine.

This one change will make LAN resync, replay result extraction, and rollback snapshots much easier to reason about.

### 3) Introduce a `ModeRuntimeAdapter` and move deterministic mode logic there

Right now each mode class owns too much:

* session construction
* replay recorder setup
* LAN snapshot logic
* resync restore
* on-tick state copying
* outcome building

I would extract a non-UI adapter per mode, something like:

* `SurvivalRuntimeAdapter`
* `RushRuntimeAdapter`
* `QuestRuntimeAdapter`

Each adapter would own:

* the `DeterministicSession`
* the authoritative mode spawn/state object
* snapshot/restore logic
* mode-specific “tick applied” interpretation
* replay result/stat extraction

Then `SurvivalMode`, `RushMode`, and `QuestMode` mostly become:

* menu/UI input
* HUD rendering
* run transitions
* save-status integration

That is how you get `BaseGameplayMode` back under control.

### 4) Extract a shared `SimulationLoop` and make everyone use it

Right now the pump logic is duplicated in:

* `BaseGameplayMode`
* `WorldRuntime`
* `ReplayPlaybackMode`
* parts of `PlaybackDriver`

I would build one loop object that owns:

* frame clock
* tick runner
* runner tick index
* begin-frame / advance / stall behavior
* deterministic apply phase
* presentation output queue
* replay recording hook
* checkpoint hook
* LAN finalize hook

Then use that for:

* local live play
* lockstep play
* rollback committed playback
* replay playback
* headless replay verification

This does not mean the outer experiences have to look identical. It just means they should not each have their own near-duplicate stepping pipeline.

### 5) Stop pushing quest-only data through generic tick result types

Once mode state has one authoritative owner, shrink `DeterministicSessionTick` back to universal fields only:

* deterministic step result
* elapsed ms
* rng marks
* maybe creature count if it is broadly useful

Quest completion timing, spawn timeline, music flags, and similar fields should be read from the quest runtime adapter or a mode-specific state view, not bolted onto the generic tick type.

Same story for playback outcomes.

A good rule: generic tick results should describe the step, not re-express the mode state.

### 6) Make presentation reactions single-sourced

You are already close here.

I would move remaining scattered side effects into one place so live and replay share them:

* perk-pick UI SFX
* quest hit SFX
* quest completion music trigger
* other “read deterministic state and produce presentation reaction” behaviors

Whether you implement that as:

* one centralized presentation adapter, or
* per-mode presentation hooks

does not matter as much as making it single-sourced.

The key is that `ReplayPlaybackMode` should not need a separate set of special-case reactions that duplicate live mode behavior.

### 7) Treat rollback and lockstep as two `TickSource` strategies, not two architectures

This is especially important for your rewrite-only features.

Lockstep and rollback should differ below the deterministic loop, not above it.

The shared model should be:

* both eventually produce canonical ticks
* both rely on the same deterministic session
* both snapshot the same authoritative mode runtime state
* both record the same replay tick format
* both validate parity with the same checkpoint/state-hash tools

Rollback needs extra machinery for rewind/resim, but that should wrap the same authoritative runtime state object. It should not create a second gameplay architecture.

### 8) Update the docs to match the code you actually have

I would fix `docs/rewrite/deterministic-step-pipeline.md` immediately after the first refactor pass.

Right now it encodes an older architecture and will keep reintroducing conceptual dead code.

## What I would do first, in order

This is the safest sequence that preserves parity while steadily reducing complexity.

### Phase 1: unify tick representation

Introduce `ResolvedTick` / `TickSupply` and adapt:

* `LocalInputProvider`
* `NetworkInputProvider`
* `TickRunner`
* `TickResult`

Do this with behavior unchanged.

### Phase 2: eliminate mirrored mode runtime state

Remove `_SurvivalState`, `_RushState`, and most dynamic ownership from `_QuestRunState`. Snapshot/restore only the authoritative runtime state objects.

### Phase 3: extract `ModeRuntimeAdapter`

Move non-UI deterministic mode logic out of the UI mode classes.

### Phase 4: extract `SimulationLoop`

Use it from live gameplay and replay playback. Either delete the tick harness from `WorldRuntime` or reduce it to a thin wrapper around the same loop.

### Phase 5: shrink generic tick/outcome types

Once the adapter owns mode-specific state, remove quest fields from universal tick structures.

### Phase 6: rewrite the docs and tighten tests

Update docs and add tests that enforce the new invariants.

## Tests I would add or strengthen

Your existing contracts already point in the right direction. `tests/test_architecture_contracts.py` is basically telling you what the architecture wants to be.

I would add these invariants:

* local live run → replay file → replay verification must produce byte-for-byte identical per-tick `commands`
* lockstep host and join must consume identical canonical tick bundles
* rollback resim must produce the same canonical committed tick sequence as lockstep for the same session
* resync snapshot restore must not require copying state into shadow mode structs
* quest completion and perk selection tests should assert deterministic state ownership directly through the authoritative runtime adapter, not through duplicated fields

For parity-sensitive changes, especially anything around perk choice timing or quest completion timing, I would require original-vs-rewrite differential captures before deleting behavior.

## What I would not change

I would keep these as-is conceptually:

* `DeterministicSession` as the core unit
* hook-based mode specialization
* the deterministic plan/apply split
* typed `GameCommand`
* replay as a first-class product, not just debug output
* headless verification as a core architecture requirement

Those are good foundations.

## The single biggest simplification

If I had to pick one thing: **make “one tick” a single object everywhere**.

Right now replay already believes that.
The session API mostly believes that.
Rollback mostly wants that.

The input-provider layer is the last major holdout.

Once you unify that, most of the remaining complexity starts to look obviously removable:

* no separate command queues
* no mirrored tick reconstruction
* less replay/live divergence
* easier network parity tests
* cleaner rollback integration
* smaller mode classes
* fewer places for decompile misunderstanding to leak into runtime structure

The rewrite is already partway through that transition. I would finish it decisively instead of carrying both models forward.
