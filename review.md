You are correct to be suspicious. The separation between `QuestDeterministicSession` and `DeterministicSession` is an architectural failure. It is a classic case of an abstraction leaking because a specific use-case (Quest mode) didn't neatly fit into the initial design, leading to a parallel implementation rather than fixing the underlying abstraction.

Here is a breakdown of why this happened, why the assumptions driving it are wrong, and how to refactor it.

### The Differences (And Why They Happened)

If you look closely at `src/crimson/sim/sessions.py`, the differences between the two sessions boil down to three things:

1. **Spawn Timing**: 
   * `DeterministicSession` (used by Survival and Rush) delegates spawning to a `mid_step_hook` which is executed *inside* `run_deterministic_step`.
   * `QuestDeterministicSession` executes its spawn logic *after* `run_deterministic_step` completes. This is because Quest mode needs to know if `creatures_none_active` (which is only true after the step resolves deaths/damage) to trigger the next wave or finish the level.
2. **State Ownership**:
   * `DeterministicSession` is stateless regarding spawns. It takes `SurvivalSpawnState` or `RushSpawnState` via closure in the `mid_step_hook`.
   * `QuestDeterministicSession` hardcodes quest-specific state directly into the session (`spawn_entries`, `spawn_timeline_ms`, `completion_transition_ms`).
3. **Return Type Bifurcation**:
   * `QuestDeterministicSession` returns a custom `QuestDeterministicSessionTick` payload containing quest-specific flags (`completed`, `play_hit_sfx`, `play_completion_music`). This forces downstream consumers (like `PlaybackDriver`) to do ugly `isinstance` checks to unpack it.

### The Flawed Assumptions

1. **"Quest spawning is fundamentally different because it happens post-step."**
   *False.* It just means the simulation lifecycle is missing a `post_step_hook`. Hardcoding the quest logic into a separate session class instead of adding a standard hook was a band-aid.
2. **"The session needs to return custom payload fields so the outer Mode knows when the level is done."**
   *False.* The outer `QuestMode` *already* owns the state. Plumbing `completed` and `spawn_timeline_ms` through the engine's tick return type is redundant data passing. If the state is held in a mutable dataclass (like `SurvivalSpawnState`), the hook mutates it, and the Mode just reads the mutated state after the tick.
3. **"Audio triggers (`play_hit_sfx`, `play_completion_music`) must be returned in the tick payload."**
   *False.* Presentation commands are already handled by `PresentationStepCommands`. Alternatively, the `post_step_hook` could simply append these to the `GameplayState.sfx_queue`, keeping the tick payload generic.

### Refactoring Advice

You can completely eliminate `QuestDeterministicSession` and `QuestDeterministicSessionTick`. Here is the step-by-step refactoring plan:

#### 1. Add a `post_step_hook` to `DeterministicSession`
Update `DeterministicSession` to accept a `post_step_hook`. 

```python
class DeterministicSession(msgspec.Struct):
    # ... existing fields ...
    mid_step_hook: MidStepHook | None = None
    post_step_hook: Callable[[PostStepContext], None] | None = None
```

In `step_tick`, execute it right after `run_deterministic_step`:
```python
        step = run_deterministic_step(...)
        
        if self.post_step_hook is not None:
            ctx = PostStepContext(
                world=self.world,
                rng_marks=rng_marks,
                step_result=step,
            )
            self.post_step_hook(ctx)
```

#### 2. Extract Quest State into a Dataclass
Just like `SurvivalSpawnState` and `RushSpawnState`, define a `QuestSpawnState` in `sessions.py`:

```python
@dataclass
class QuestSpawnState:
    spawn_entries: tuple[SpawnEntry, ...] = ()
    spawn_timeline_ms: float = 0.0
    no_creatures_timer_ms: float = 0.0
    completion_transition_ms: float = -1.0
    completed: bool = False
```

#### 3. Create a `quest_post_step` hook
Move the logic currently hardcoded in `QuestDeterministicSession.step_tick` into a standalone hook:

```python
def quest_post_step(ctx: PostStepContext, spawn: QuestSpawnState) -> None:
    dt_ms = float(ctx.step_result.timing.dt_ms_i32)
    creatures_none_active = not any(c.active for c in ctx.world.creatures.entries)
    
    entries, timeline_ms, creatures_none_active, no_creatures_timer_ms, spawns = tick_quest_mode_spawns(
        spawn.spawn_entries,
        # ... pass args from ctx and spawn state
    )
    
    # Update mutable state
    spawn.spawn_entries = entries
    spawn.spawn_timeline_ms = timeline_ms
    spawn.no_creatures_timer_ms = no_creatures_timer_ms

    # Handle SFX by injecting them into the presentation step or world sfx_queue
    if any_alive_after:
        completion_ms, completed, play_hit, play_music = tick_quest_completion_transition(...)
        spawn.completion_transition_ms = completion_ms
        spawn.completed = completed
        if play_hit:
            ctx.world.state.sfx_queue.append("sfx_questhit")
        # ... handle music
```

#### 4. Delete the Quest Session Classes
Now you can safely delete `QuestDeterministicSession` and `QuestDeterministicSessionTick`. Update `QuestMode` and `PlaybackDriver` to use standard `DeterministicSession`.

Instead of checking `tick.completed` on the returned payload, `QuestMode` just checks `self._quest_spawn_state.completed` after `runner.advance_ticks()` returns.

#### 5. Clean up `PlaybackDriver`
In `src/crimson/sim/driver/playback_driver.py`, the `QuestPlaybackRuntime` currently does this:
```python
    def enrich_tick_outcome(self, outcome: PlaybackTickOutcome, *, tick: DeterministicSessionStepTick) -> None:
        if not isinstance(tick, QuestDeterministicSessionTick):
            raise ReplayRunnerError("quest playback session returned non-quest tick payload")
        outcome.spawn_timeline_ms = float(tick.spawn_timeline_ms)
        # ...
```
This is terrible polymorphism. Once you switch to `QuestSpawnState`, the `QuestPlaybackRuntime` class can just hold a reference to `self.quest_state` (which it passes to the `DeterministicSession`), and read from it directly:

```python
    def checkpoint_elapsed_ms(self, outcome: PlaybackTickOutcome) -> float:
        return float(self.quest_state.spawn_timeline_ms)
```
No `isinstance` checks, no custom tick payloads, and no data plumbing.

### Summary
The code drifted because whoever implemented Quest mode needed a post-tick hook and didn't want to touch the core `DeterministicSession` interface, opting instead to duplicate the class. By adding a standard `post_step_hook` and extracting the state into a closure-bound mutable object (`QuestSpawnState`), you can collapse these two parallel implementations back into one clean pipeline.