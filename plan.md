I pulled your patch on top of the 2026‑02‑05 zip and walked the phase 1–3 implementation end-to-end (new `crimson/replay/*`, `crimson/sim/runners/*`, integration in `SurvivalMode`/`RushMode` + `PerkMenuController`, plus `ReplayPlaybackMode` + CLI hook).

What you have is a solid “spine” — but there are a few determinism killers / missing bits that will make real-world replays diverge (and therefore make headless verification flaky) unless you address them **inside phases 1–3**.

## What’s already good

* **Replay core** (`src/crimson/replay/codec.py`, `types.py`, `recorder.py`)

  * Stable gzipped JSON with `mtime=0` + sorted keys + compact separators.
  * Format versioning (`v=1`) and a structured header.
  * Input packing is compact and reasonable (`[mx,my,ax,ay,flags]`).
  * Quantization option (`input_quantization="f32"`) is a nice hook for “match original f32 input resolution” experiments later.

* **Headless runners** (`src/crimson/sim/runners/survival.py`, `rush.py`)

  * Correctly rebuild mode state, apply events, step world, then do spawns using the same spawn helpers as the in-game modes.
  * Returning a clean `RunResult` is exactly what you want for server verification later.

* **In-game recording** (`src/crimson/modes/survival_mode.py`, `rush_mode.py`)

  * Recording inputs only when sim advances (`dt_world > 0`) is correct.
  * Hooking perk picks via `PerkMenuController(on_pick=…)` is the right direction.

* **Playback mode** (`src/crimson/modes/replay_playback_mode.py`)

  * You already implemented a fixed-step accumulator pattern there (`_dt_accum` / `_tick_one()`), which becomes important below.

## Biggest missing pieces (these will break determinism)

### 1) Timebase mismatch: live run uses variable `dt`, replay assumes fixed `tick_rate`

Right now:

* Live game loop: `grim.app.run_view()` uses `rl.get_frame_time()` (variable dt).
* `BaseGameplayMode._tick_frame()` returns `dt_frame = dt` (no fixed step).
* `SurvivalMode` / `RushMode` record **one tick per rendered frame**.
* Replay header hardcodes `tick_rate=60`.
* Headless runner + playback mode simulate `dt_frame = 1 / tick_rate`.

That means: **your replay is not actually “inputs per tick”; it’s “inputs per rendered frame”, but your replayer interprets it as “inputs per 1/60 tick”.** Any run that isn’t exactly 60.000 FPS (and almost none are) will drift; and drift in this game will cascade into different RNG usage, different spawns, different hits → different score.

This is the single highest priority fix.

**Concrete fix options (pick one):**

**Option A (recommended): make gameplay sim fixed-step at 60 Hz (like your playback mode).**
You already wrote the pattern in `ReplayPlaybackMode`. Apply the same idea to real gameplay modes:

* Keep UI animation on real `dt`.
* Step simulation in a loop with `dt_tick = 1/60` (or header tick_rate).
* Record one input packet per sim tick.

This makes your recorded replays and headless runners consistent.

**Option B: record `dt` per tick in the replay.**
This preserves variable-dt behavior, but increases replay size and complexity, and makes server verification more expensive/less “canonical”.

Given your current design already encodes `tick_rate`, Option A is much more aligned with what you’ve built.

**Concrete plan for Option A:**

* Introduce a reusable clock (e.g. `crimson/sim/clock.py`):

  * `tick_rate`, `dt_tick`, `accum`
  * `advance(real_dt) -> number_of_ticks`
* In `SurvivalMode.update()` / `RushMode.update()`:

  * Run `_tick_frame(dt)` for UI/mouse only.
  * Accumulate real dt, then `for _ in range(ticks_to_run):`

    * build input snapshot (same code you already have)
    * **record tick** (recorder)
    * advance sim exactly one tick (`dt_world = dt_tick`)
* On pause/gameover/perk menu, clear the accumulator so you don’t “catch up” with a giant burst when unpausing.

Until this is fixed, any replay correctness is basically “it works on my machine at perfect FPS”.

---

### 2) Your “headless sim” is **not** executing the same RNG-consuming path as the live game

This is the other big determinism breaker.

Live modes call `self._world.update(dt_world, inputs=…)` (GameWorld.update).
Headless runners call `world.step(dt_sim, …)` (WorldState.step) directly.

That seems fine, except **`GameWorld.update()` consumes `state.rng` after the step**:

* It calls `AudioRouter.play_hit_sfx(..., rand=self.state.rng.rand)` for hits.
* It calls `AudioRouter.play_death_sfx(..., rand=self.state.rng.rand)` for deaths.
* It calls `_queue_projectile_decals(events.hits)` which in turn calls:

  * `FxQueue.add_random(..., rand=state.rng.rand)` (4 rand calls per decal attempt)
  * `effects.spawn_blood_splatter(..., rand=state.rng.rand, ...)` (more rand calls)

None of that happens in the headless runner today. So the first time you hit something (which is… basically immediately in any real run), the RNG stream diverges and the whole run diverges.

This is *not theoretical* — your current tests don’t catch it because the test replay never fires (no hits/deaths).

**You need to decide what belongs inside the deterministic “sim boundary”:**

* If decals/audio variations are **presentation-only**, they must not advance the sim RNG.
* If they are **part of the original RNG stream**, then headless replay must execute the same RNG-consuming logic even if it doesn’t actually render/play sound.

Right now you’re in the worst middle ground: they advance sim RNG in-game, but not in headless/playback → divergence.

**Concrete plan (two viable approaches):**

#### Approach 2A: Decouple presentation randomness from sim RNG

Goal: make `GameplayState.rng` a “simulation RNG only”.

* Change hit/death sfx selection to use `audio_rng` (or a dedicated `presentation_rng`), not `state.rng`.

  * In `GameWorld.update`, you currently pass `rand=self.state.rng.rand` into audio router. That’s the coupling. Break it.
* Change `_queue_projectile_decals` / blood splatter / `FxQueue.add_random` to use a presentation RNG too.

After this, headless runner doesn’t need to care about decals/audio at all — sim RNG stays consistent.

This best matches your “simulation is almost a pure function” direction.

#### Approach 2B: Make post-step RNG consumption deterministic and share it between live + headless

Goal: headless must consume the same RNG as live, without needing pyray/audio.

* Factor the RNG-consuming parts of:

  * hit/death sfx selection (but return “which sfx key” instead of playing it)
  * projectile hit decal/blood logic
    into a `crimson.sim.post_step` module **that does not import pyray**.
* Call it from:

  * `GameWorld.update()` (use outputs to play audio / enqueue decals)
  * headless runner (discard outputs but still consume RNG & update fx queues/effects as needed)

If you do this, also ensure **fx queues are cleared each tick** in headless, because:

* `FxQueue.add_random()` *does not consume RNG* if the queue is full (`if self._count >= self._max_count: return False`).
* In real game, `bake_fx_queues(..., clear=True)` clears queues every frame.
* In headless, your `FxQueue` will otherwise eventually fill → RNG consumption changes → divergence again.

---

### 3) Status snapshot is incomplete for deterministic weapon drops

You only snapshot:

* `quest_unlock_index`
* `quest_unlock_index_full`

…but gameplay uses persistent status **during the run** for weapon drop bias:

* `weapon_pick_random_available()` checks `status.weapon_usage_count(candidate)` and may reroll.

So two players with different `weapon_usage_counts` can get different drops from the same seed + inputs.

Your headless runner uses `status_from_snapshot()` which builds `default_status_data()` (weapon usage counts all zero). So any run where weapon drops happen can diverge purely because the player profile differed.

**Concrete fix:**
Extend `ReplayStatusSnapshot` to also carry:

* `weapon_usage_counts: list[int]` (or `tuple[int, ...]`)

Then in `status_from_snapshot()` apply it to the constructed `GameStatus`.

This is cheap in size (53 ints) and removes a major nondeterminism source.

If you *don’t* want leaderboard runs to depend on profile state, then you should instead enforce a “clean status” for recorded/verified runs (state.status=None or reset counts). But that’s a design decision — current code implies status matters, so replay must capture it.

---

### 4) Perk menu “open then cancel” is not recorded, but it can consume RNG

You record only `perk_pick` events.

However, `perk_selection_current_choices()` consumes RNG the first time it generates choices (when `choices_dirty` is set). That function is called by `PerkMenuController` when opening the menu (and every frame while open).

If the player:

1. has pending perks,
2. opens perk menu (choices are generated; RNG consumed),
3. closes/cancels without picking,
4. continues playing,
5. later opens again and picks,

…then in the real run the RNG consumption happened back at step (2), not at pick time.

Your replay runner, with only a later `perk_pick`, will generate choices later (at pick) and the run will diverge.

**Concrete fix:**
Add a new replay event kind, something like:

* `perk_menu_open` (tick_index, player_index)

Record it when the menu actually opens (or when choices generation actually happens). In the runner:

* on `perk_menu_open` at tick N, call `perk_selection_current_choices(state, player, game_mode=..., player_count=...)`
* on `perk_pick`, call `perk_selection_pick` as you do now

This reproduces RNG consumption timing for cancel/reopen flows.

If you want an even tighter spec: record an event specifically when `choices_dirty` flips false (i.e., “choices generated”), not merely when menu opens.

---

### 5) `crimson.__version__` currently breaks “run from source”

Your new `src/crimson/__init__.py` does:

```py
from importlib.metadata import version
__version__ = version("crimsonland")
```

If the package metadata isn’t installed (common in tests / running via `PYTHONPATH=src`), this raises `PackageNotFoundError` and `import crimson` fails. I hit this immediately when running your tests from the repo.

**Concrete fix:**
Wrap with a fallback:

```py
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("crimsonland")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"
```

This matters because `ReplayHeader` defaults `game_version` via `crimson.__version__`.

---

## Smaller correctness nits (worth fixing while you’re here)

* **ReplayPlaybackMode dt scaling order**

  * In `ReplayPlaybackMode._tick_one()`, `dt_sim = time_scale_reflex_boost_bonus(...)` is computed *before* applying tick events (`perk_pick`).
  * In your headless runner, you apply events first, *then* compute dt_sim.
  * If any event can affect `state.bonuses.reflex_boost` or similar time scaling, playback could diverge.
  * Fix: compute `dt_sim` after applying events for that tick.

* **Event ordering / validation**

  * You don’t currently validate that event tick indices are within `[0, len(inputs)]` or non-negative.
  * Fine for local files; for eventual verification you’ll want strict bounds. Even now it’s helpful to fail with a clean error.

* **Naming clarity**

  * `ReplayHeader.seed` is actually “RNG state at tick 0” (post `GameWorld.open()` terrain seed consumption), not “the initial seed used for reset”.
  * Not wrong, but I’d rename to `rng_state` (and optionally also store `reset_seed` later).

---

## Concrete “phase 1–3 hardening” plan

If I were sequencing this so you get a working, reliable replay loop **before** going to phase 4 (server), I’d do:

1. **Fix the timebase first** (fixed-step sim at 60 Hz in Survival/Rush)

   * This aligns recording ↔ playback ↔ headless.
   * Without it, nothing else is stable.

2. **Pick & implement a determinism boundary**

   * Either:

     * decouple decals/audio RNG from sim RNG (preferred for “pure function”),
     * or factor post-step RNG consumers into shared sim code and call it in headless too.
   * Add “clear fx queues per tick” to headless if you go with the latter.

3. **Expand replay snapshot to include status.weapon_usage_counts**

   * Otherwise weapon drops alone will invalidate replays for many players.

4. **Add `perk_menu_open` (or “choices_generated”) event**

   * Record it on menu open / choice generation, replay it in runners.

5. **Fix `__version__` fallback**

   * Unblocks tests + tooling.

6. **Add tests that actually exercise the problematic paths**

   * A minimal headless test that fires enough to generate:

     * projectile hits (to trigger decal/audio paths)
     * a weapon drop (to trigger status bias)
     * a perk menu open/cancel flow (to trigger choice generation timing)

Right now your tests validate the plumbing (codec, runner stepping), but they don’t hit the branches that will break real runs.

---

If you want, I can also point to the exact “RNG-coupling hotspots” you’ll want to audit beyond `GameWorld.update()` (anything that calls `state.rng.rand` but shouldn’t for sim purity), but the items above are the ones that will bite you immediately when you try to verify a real recorded run headlessly.
