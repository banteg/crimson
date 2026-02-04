Here’s what I see in your repo **right now**, and a concrete “next phase” plan that turns your replay + headless verification + Frida differential fuzzing idea into a real subsystem that fits your current architecture.

## What you already have that’s perfect groundwork

### 1) A clean “pure-ish” sim core

* The deterministic core is basically `WorldState.step()` in **`src/crimson/sim/world_state.py`**.
* The RNG is **MSVCRT-style and deterministic** (`grim.rand.Crand`), stored in `GameplayState.rng` (see **`src/crimson/gameplay.py`**).
* You already enforce “sim code must not import pyray” via import-linter (`pyproject.toml`).

This is exactly the separation you want for:

* deterministic replays
* server-side verification
* differential testing

### 2) Mode-specific gameplay logic exists, but is currently “UI/loop-bound”

Survival/Rush/Quest logic lives in **`src/crimson/modes/*`** and mixes:

* input polling (raylib)
* UI/perk menu behavior
* sim stepping (`self._world.update(...)`)
* mode-specific spawns (`tick_survival_wave_spawns`, etc.)

To make replays + headless runs real, the key gap is:

> There isn’t yet a *headless runner* for “real Survival/Rush/etc”, only a headless runner for the *micro-sim*.

### 3) You already have differential testing infrastructure

* `crimson.oracle` is a headless harness (**`src/crimson/oracle.py`**) that emits state per frame.
* Frida scripts already exist and emit structured logs (e.g. **`scripts/frida/weapon_switch_trace.js`**), reduced by **`scripts/weapon_switch_trace_reduce.py`**.
* You even have a test asserting reduced oracle output: **`tests/test_oracle_weapon_switch_summary.py`**.

That’s huge. You’re not starting from zero.

### Important reality check

Your current `crimson.oracle.run_headless()` **does not run mode spawns** (it only calls `WorldState.step()`), so it’s not yet suitable for verifying survival highscores. It’s a differential harness (as the docstring says), not a full gameplay runner.

So the “next phase” is mainly: **extract mode logic into headless runners** + **define a replay format** + **wire recording/playback**.

---

## The target shape of the system

You want one canonical artifact:

> **Replay = (initial conditions) + (tick inputs) + (discrete events like perk picks)**
> Compressed + versioned + replayable both in-game and headlessly.

Then everything falls out naturally:

* client can save replays
* server can replay and verify claims
* replays can be shared by ID
* Frida can emit the same format from the original
* fuzzing becomes “generate replays → run both → diff checkpoints”

---

## Phase 1: Define the replay format (MVP) + build the core library

### 1) Add `crimson/replay/` package

Create:

* `src/crimson/replay/types.py`
* `src/crimson/replay/codec.py`
* `src/crimson/replay/recorder.py`

#### Replay contents (MVP)

**Header**

* `format_version`
* `game_mode_id` (your `GameMode` enum values)
* `seed` (32-bit)
* `tick_rate` (usually 60)
* `difficulty_level`, `hardcore`, `preserve_bugs`
* `world_size`
* `player_count`
* **status snapshot** (at least `quest_unlock_index`, `quest_unlock_index_full`)
  because your sim calls `weapon_refresh_available()` / `perks_rebuild_available()` which depend on status.

**Tick inputs**
Per simulation tick, per player:

* `move_x, move_y`
* `aim_x, aim_y` (world coords)
* `fire_down, fire_pressed, reload_pressed`

**Events**
Discrete events with a `tick_index`:

* `perk_pick`: `{player_index, choice_index}`
  (optionally also record `choices` and `picked_perk_id` for debugging)

This is enough to reproduce a run *exactly* in your rewrite.

### 2) Serialization: use “JSON + gzip” first

You’ll get compression “for free” and it’s dead easy to:

* emit from Python
* emit from Frida (JSON)
* store/serve from a backend

Later you can add a binary `construct` codec once the pipeline works end-to-end.

**Key detail:** avoid per-frame dict verbosity. Use compact arrays.
Example shape:

```json
{
  "v": 1,
  "header": { ... },
  "inputs": [
    [[mx,my,ax,ay,flags], ...players],
    ...
  ],
  "events": [
    [tick, "perk_pick", player, choice_index]
  ]
}
```

### 3) Decide input precision at the sim boundary (do this deliberately)

Right now, live input is computed with Python floats (f64), but the original game uses f32-ish values.

You’ll get much stronger determinism if you define a single rule:

* **Option A (simplest):** record and replay *exact Python floats* you fed into sim.
* **Option B (recommended for long-term + original diffing):** quantize input at the boundary (e.g. cast through float32 or fixed-point) **before** it enters sim and **before** recording.

If you do Option B, “recorded replay” becomes more portable and it narrows f64/f32 divergences when comparing against the original.

---

## Phase 2: Build headless *mode runners* (this unlocks server verification)

This is the main “make it real” work.

### Why you need it

Your interactive modes currently do:

* compute dt + pause handling
* compute input
* call `GameWorld.update()` (which itself does time scaling + calls `WorldState.step()`)
* then do mode spawns (survival/rush/quest)
* then handle game over / highscores

Headless verification needs to do the same *without pyray*.

### 1) Create `src/crimson/sim/runners/`

Add:

* `src/crimson/sim/runners/common.py`
* `src/crimson/sim/runners/survival.py`
* `src/crimson/sim/runners/rush.py`

Define:

* `RunResult` (score, kills, elapsed_ms, etc.)
* `Checkpoint` output (optional but very useful)

### 2) Implement Survival runner by mirroring `SurvivalMode.update`

Look at **`src/crimson/modes/survival_mode.py`**:

* `_SurvivalState` tracks `elapsed_ms`, `stage`, `spawn_cooldown`
* after `world.update(...)` it calls:

  * `advance_survival_spawn_stage(...)`
  * `tick_survival_wave_spawns(...)`
  * then `creatures.spawn_template(...)` / `creatures.spawn_inits(...)`

Your headless runner should do the same, but using `WorldState` directly (not `GameWorld`, because `GameWorld` imports pyray).

Also, replicate the one piece of important sim logic currently in `GameWorld.update()`:

* **Reflex Boost time scaling**:

  * in `GameWorld.update()` it scales `dt` based on `state.bonuses.reflex_boost`
  * do the same in headless runner before calling `WorldState.step()`

Also replicate:

* `weapon_refresh_available(state)`
* `perks_rebuild_available(state)`

(these are called inside `GameWorld.update()` today, and they matter for perk/weapon availability)

### 3) Apply replay events in the runner

For each tick:

* before stepping sim, apply all events at that `tick_index`:

  * for perk picks, call your existing `perk_selection_pick(...)`

This is enough because:

* if choices are dirty, `perk_selection_pick` will generate them (consuming RNG)
* in the real game this happens during pause/UI, but simulation is paused so RNG state is the same

### 4) Rush runner is even easier

Mirror **`src/crimson/modes/rush_mode.py`**:

* enforce loadout every tick (`weapon_assign_player` + ammo top-up)
* call `tick_rush_mode_spawns(...)`
* spawn inits
* terminate on death

No perks, no menu.

### Output of runners

Make them produce:

* “final result” for verification:

  * experience (score)
  * kill_count
  * elapsed_ms
  * shots fired/hit (available in `GameplayState`)
* optionally a deterministic `final_hash` or periodic checkpoint hashes (excellent for diff tests + fuzz)

---

## Phase 3: Record replays in the live game + playback in-game

### Recording hook points (concrete, in your current code)

#### 1) Capture tick inputs

In SurvivalMode and RushMode, you already build one `PlayerInput` per frame:

* `input_state = self._build_input()`
* passed to world: `inputs=[input_state for _ in self._world.players]`

So for recording:

* right after `_build_input()` and before `_world.update(...)`, do `recorder.record_tick(...)`.

#### 2) Capture perk selections

Perk selection happens in **`PerkMenuController.handle_input()`** (see `src/crimson/modes/components/perk_menu_controller.py`):

* it calls `perk_selection_pick(...)` when user clicks/presses enter.

Add a minimal callback mechanism:

* `PerkMenuController(..., on_pick: callable | None = None)`
* when a pick happens, call `on_pick(tick_index, choice_index, picked_perk_id, choices_snapshot)`

SurvivalMode has access to the current tick count (your recorder can maintain it).

This avoids hacking gameplay.py and keeps recording logic in the UI layer where it belongs.

#### 3) Save on game over

SurvivalMode already builds a highscore record in `_enter_game_over()`.
At that moment:

* finalize replay
* write `replays/<timestamp>_<sha256>.crdemo.gz`

### Playback

Add a `ReplayPlaybackMode` that:

* loads replay
* drives the sim using the headless runner but renders with your existing `GameWorld` drawing (or directly uses `WorldState` + renderer)
* displays “REPLAY” overlay

MVP can be survival-only.

---

## Phase 4: Server verification + replay hosting

Once you have:

* replay format
* headless survival runner
* `RunResult`

Server is straightforward.

### Server verification contract

Client submits:

* replay blob
* claimed `{score, kill_count, elapsed_ms}` (or just score)

Server:

* decompress + parse replay
* run headless runner
* compare computed result to claim
* if match: accept, store replay by content hash
* return `submission_id = sha256(replay_bytes)`

### Storage model

Content addressed storage is perfect:

* key: `sha256(compressed_replay_bytes)`
* value: replay bytes + computed result + metadata (name/time/version)

Replay retrieval by ID is then trivial.

Even if you don’t build a web API immediately, you can start with:

* `crimson replay verify <file> --claim ...`
* then wrap it later in FastAPI.

---

## Phase 5: Differential testing and fuzzing vs the original using Frida

You already have the most important part: **Frida logging infrastructure + reduction scripts + test fixtures**.

Now you want two new capabilities:

1. **Emit the same replay format from original** (capture)
2. **Drive original from a replay** (injection) to fuzz

### 5.1 Capture from original (easy first step)

Write `scripts/frida/replay_capture.js` that logs per tick:

* input state (either high-level or low-level)
* perk applied events
* seed (if accessible)
* enough header info to reproduce in rewrite

If you want to match your replay schema:

* emit JSONL that your Python tool converts into `.crdemo.gz`

**Where to hook:**

* `gameplay_update_and_render` or a per-frame function (you already know these in docs)
* grim input functions (`grim_is_key_down`, mouse getters) to infer inputs

### 5.2 Drive original from a replay (harder, but you’re already close)

Create `scripts/frida/replay_driver.js`:

* loads a replay JSON (or inputs JSON) path from env var
* sets RNG seed by calling `crt_srand` (you have address in docs: `FUN_00461739`)
* overrides grim input APIs:

  * `grim_is_key_down`
  * `grim_was_key_pressed`
  * `grim_get_mouse_x/y`
  * mouse button pressed/down
* increments a `tick_index` by hooking a known “frame boundary” function

Perk selection:

* hook `perk_selection_screen_update` (probe already lists `0x00405be0`)
* force the selection index recorded in replay (simulate mouse/enter press or write the selection state directly)
* OR (first milestone) don’t inject perk selection, just run with auto-picks and compare perk_apply logs

### 5.3 Compare using checkpoint hashing, not full state

Because you’re f64 and original is f32, start with a **checkpoint schema** (like your oracle summary):

* score (experience)
* kills
* player pos/health/weapon/level
* bonus timers
* creature_count

Emit that from:

* your headless replay runner
* original frida script

Then diff (with tolerances for floats). This is much more stable than comparing “everything”.

### 5.4 Fuzzing harness

Once the runner + driver exist:

* generate random replay inputs/events
* run rewrite headless → checkpoint trace
* run original via frida driver → checkpoint trace
* compare
* on mismatch: delta-debug (minimize input stream), save as regression replay under `analysis/fuzz/`

This plugs directly into your existing “analysis/fixtures + tests” pattern.

---

## The fastest “next phase” path I’d execute in this repo

If you want the shortest path to “this is real and useful” (replays + server verification):

1. **Implement replay types + JSON+gzip codec** (`crimson/replay/*`)
2. **Implement `crimson.sim.runners.survival`** (mirror survival spawns + reflex dt scaling)
3. **Add CLI: `crimson replay run/verify`** (headless)
4. **Wire recording into SurvivalMode** (tick inputs + perk picks)
5. Save replay on game over; verify locally by running `crimson replay verify`

Only after that:
6) Playback mode (nice UX)
7) Frida replay capture/driver + fuzz harness

That sequencing avoids getting stuck in Frida complexity before you’ve nailed the replay contract and headless sim.

---

## Gotchas to proactively design around

* **Status/unlocks affect perk/weapon availability**
  If you don’t include a status snapshot (or enforce “all unlocked”), server verification and diff testing will be unstable.

* **Variable dt vs fixed tick**
  Decide if ranked/verified runs use fixed tick dt (recommended).
  If not, you must record dt-per-tick and then you’re trusting client timing.

* **Perk pick timing matters**
  Not just “which perks” but “when picked” affects survival outcome.
  That’s why perk picks must be events with tick indices.

* **Float64 vs float32** (original diffing)
  Start by diffing checkpoint summaries with tolerances; only then expand.

---

If you want one deliverable spec out of this: I’d write a `docs/replay-format.md` that locks:

* header fields
* tick input representation
* event types
* versioning rules

…and then implement the headless Survival runner as the first “proof the format is sufficient” milestone. That’s the moment you can verify highscores and everything else becomes iteration, not invention.
