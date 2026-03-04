This branch makes massive, necessary strides. Killing `TickHookBus`, deleting the `GameWorld` monolith, introducing `InputStatus`, and making `TickRunner` a pure function are all huge wins that secure our deterministic core.

However, evaluated strictly against the *spirit* of `plan.md`, `refactor.md`, and the principles in `CONTRIBUTING.md`, **we have stopped short of the finish line.** We have replaced some of our old complexity with "structural illusions" and compatibility scaffolding rather than actually simplifying the boundaries.

Here is a rigorous breakdown of where the branch falls short and maintains a "split brain" or useless scaffolding:

### 1. The `PresentationLayer` Illusion (Split Brain)
`plan.md` explicitly dictates: *"Collapse world architecture to two meaningful components: `SimWorldState` + `PresentationLayer`."* 

You built `PresentationLayer` (in `src/crimson/world/presentation.py`), but **the core gameplay modes completely ignore it.**
In `BaseGameplayMode` and `ReplayPlaybackMode`, you manually define and manage the 4 split components:
```python
self.sim_world = SimWorldState(...)
self.render_resources = RenderResources(...)
self.audio_bridge = AudioBridge(...)
self.terrain_runtime = TerrainRuntime(...)
```
This is not a collapse; this is unrolling the old `GameWorld` into 4 properties on the mode classes. `BaseGameplayMode` is burdened with manually syncing these components (`_sync_world_size_ownership`, `_open_world_runtime`, `sync_ground_settings`), entirely defeating the point of a unified presentation layer.

### 2. Unfinished Stage 6: Duplicated Batch Apply & Clock Debt
In `refactor.md`, you left these boxes unchecked:
- `[ ] Add shared deterministic batch apply helper`
- `[ ] Refactor BaseGameplayMode and ReplayPlaybackMode stepping paths to use shared batch apply`

Because this was skipped, we now have **three distinct copy-pasted loops** iterating over `TickBatchResult.completed_results` (`BaseGameplayMode._process_tick_batch_results`, `ReplayPlaybackMode._advance_runner`, and `WorldRuntime._apply_tick_batch`). 

Worse, the logic for refunding unconsumed ticks to the accumulator on `STALLED` / `EOS` is copy-pasted verbatim in three files:
```python
if batch.batch_status in (InputStatus.STALLED, InputStatus.EOS):
    unconsumed_ticks = max(0, int(ticks_requested) - int(batch.ticks_completed))
    if unconsumed_ticks > 0:
        self._clock.accum += float(unconsumed_ticks) * float(self._clock.dt_tick) # (or dt_seconds)
```
This violates the mandate for a single shared apply/orchestration path.

### 3. The `WorldRenderHost` God-Object (Reincarnated `GameWorld`)
`CONTRIBUTING.md` demands: *"Fix schemas/types/contracts at boundaries rather than weakening the domain."*

Instead of fixing the renderer to accept a clean data object (like `RenderFrame`), you created `WorldRenderHost` in `renderer.py`:
```python
class WorldRenderHost(Protocol):
    assets_dir: Path
    world_size: float
    demo_mode_active: bool
    config: CrimsonConfig | None
    camera: Vec2
    render_resources: RenderResources
    sim_world: SimWorldState
    lan_player_rings_enabled: bool
    lan_local_aim_indicators_only: bool
    ...
```
This is literally just the ghost of `GameWorld`. You forced `BaseGameplayMode`, `ReplayPlaybackMode`, and `WorldRuntime` to implement this massive 12-property protocol so `WorldRenderer` can continue reaching across boundaries to grab `self._world.sim_world.players`. This is useless scaffolding that preserves the old spaghetti data access under the guise of a Python `Protocol`. 

### 4. Useless Scaffolding in Tests (`WorldRuntimeHost`)
`CONTRIBUTING.md`: *"Default posture: cutover refactors... Do not add long-lived compatibility wrappers."*

In `tests/world_runtime.py`, you created `WorldRuntimeHost` which does nothing but wrap `WorldRuntime` and delegate 20+ properties to it (`@property def sim_world(self): return self._runtime.sim_world`, etc.). 
This exists solely to appease old test code that expected `GameWorld`-like property access. It is a textbook compatibility facade. The tests should be updated to consume the new actual boundary, not a wrapper pretending to be the old one.

---

### The Verdict & Required Fixes

To get this code into a truly clean state and fulfill the PRD:

1. **Use `PresentationLayer`**: `BaseGameplayMode` and `ReplayPlaybackMode` must drop the 4 individual components and compose exactly two things: `self.sim_world` and `self.presentation`.
2. **Extract the Batch Apply Helper**: Fulfill the unchecked boxes in `refactor.md`. Extract a single function that takes a `TickBatchResult`, a `SimWorldState`, a `PresentationLayer`, and handles the apply loop, audio dispatch, and clock refunding.
3. **Kill `WorldRenderHost`**: `WorldRenderer.draw()` should take a `RenderFrame` (or similar simple context) directly. The renderer should not be passed a host object that it has to interrogate. 
4. **Delete `tests/world_runtime.py`'s `WorldRuntimeHost`**: Migrate the tests to interact directly with `WorldRuntime` or `SimWorldState`, and delete the property-delegating wrapper. 

The hard logic (determinism, hooks, pure runner) is perfectly executed. Now we just need to enforce the structural boundaries without cheating via protocols and wrappers.