Below is a refactor plan that’s meant to work **while the codebase is moving fast**: it prioritizes guardrails + high‑ROI consolidation first, then larger structural moves in small, reversible slices.

I’m tailoring this to the snapshot you shared (Python + raylib, `src/grim` engine vs `src/crimson` game). A few concrete observations from the tree:

* There is at least one clear **layering violation**: `src/grim/fx_queue.py` imports `crimson.effects` and `crimson.effects_atlas` (so `grim -> crimson` exists today).
* There’s repeated **asset resolution + texture loading** logic across multiple places (`crimson/ui/{perk_menu,hud,game_over}.py`, `crimson/game_world.py`, several views) via repeated `_resolve_asset`, `_load_from_cache`, `_load_from_path`.
* There’s duplicated **MSVCRT rand() LCG** logic (`crimson/crand.py` vs `CrtRand` inside `grim/terrain_render.py`).
* Biggest churn/hotspot files by size are `crimson/game.py` (~3.8k LOC) and `crimson/game_world.py` (~1.7k LOC), which are likely where “code lives where it’s not supposed to” will keep reappearing unless boundaries are enforced.

Tracking: use `[ ]` for pending and `[x]` for done (update the markers in the headers/items below).

---

## North-star architecture rules (make these explicit) [ ]

You already have the intent in `docs/rewrite/module-map.md`. Turn it into hard rules:

1. **`grim` must never import `crimson`.**
   `grim` is engine/platform; `crimson` is game.
2. **Simulation code should be importable without raylib.**
   Concretely: anything that’s “update/step/resolve/apply” should not `import pyray as rl`.
3. **Rendering and UI can depend on both** (`pyray` + `grim` + `crimson`), but:

   * UI shouldn’t contain game rules; it should produce *intent* (“selected perk X”, “clicked play again”) and let a mode/controller apply it.

These three rules will eliminate most “wrong place” drift.

---

## Phase 0: Add safety rails before you move anything [x]

This is what lets you refactor *in tiny PRs* without breaking the rewrite.

### 0.1 Add a cheap boundary checker (CI + local) [x]

You can use `import-linter`. The goal is binary:

* Fail CI if any file under `src/grim/` imports `crimson`.

Add a second rule that will matter later:

* Fail CI if any file under `src/crimson/sim/` (once you create it) imports `pyray`.

### 0.2 Add a duplication report you can run on demand [x]

Don’t try to “zero duplicates” overnight. Start by measuring.

* Run a duplication tool (pylint `R0801`, `jscpd`, or similar)
* Produce a report artifact
* Establish a **baseline** (current duplication) and a simple policy:

  * “No new duplicated blocks above N lines” (start permissive, tighten later)

### 0.3 Create a “refactor compatibility” pattern [x]

When moving modules, do not preserve old imports temporarily or re-export.

This keeps the codebase clean when paths change. We haven't released, so we don't need any backwards compatibility or api stability.

---

## Phase 1: Fix the biggest “wrong place” problem first (grim → crimson) [x]

### 1.1 Fix `grim.fx_queue` importing `crimson.*` (currently a hard boundary violation) [x]

Right now:

* `grim/fx_queue.py` imports `crimson.effects` and `crimson.effects_atlas`.

You have a good option. Pick the one that matches your intent for “what is engine vs game”.

#### cleanest separation: move game-specific baking to `crimson`

* Keep in `grim`:

  * `GroundRenderer`
  * `GroundDecal`, `GroundCorpseDecal`
  * any raylib-only rendering primitives
* Move to `crimson`:

  * the function that converts *game effect IDs* to atlas rects and decals, i.e. `bake_fx_queues`

Result:

* `grim` becomes truly reusable engine code.
* `crimson` owns “effect_id means sprite frame X”.

A reasonable landing spot would be:

* `crimson/render/terrain_fx.py` (or `crimson/render/fx_bake.py`)

**Either option eliminates the architectural footgun** and will prevent future “engine depends on game” creep.

### 1.2 Lock it in with the boundary test [x]

Once fixed, the boundary checker from Phase 0 ensures it doesn’t regress during fast iteration.

---

## Phase 2: Kill the highest-ROI duplication: asset locating + texture loading [ ]

You have the same trio of helpers repeated in multiple files:

* `_resolve_asset(assets_root, rel_path)`
* `_load_from_cache(cache, name, rel_path, missing)`
* `_load_from_path(assets_root, rel_path, missing)`

…and repeated “own/unload textures vs cache ownership” patterns.

### 2.1 Create one canonical loader in `grim.assets` [x]

Add something like:

* `resolve_asset_path(assets_root, rel_path) -> Path|None`
* `TextureProvider` / `TextureLoader` that:

  * optionally wraps `PaqTextureCache`
  * optionally falls back to filesystem (including legacy `assets_root/crimson/...`)
  * crash on missing assets! we want to catch this early. the game shouldn't boot without assets.
  * owns unload responsibilities in one place

A sketch:

```py
@dataclass
class TextureLoader:
    assets_root: Path
    cache: PaqTextureCache|None
    missing: list[str]
    owned_textures: list[rl.Texture]

    def get(self, name: str, paq_rel: str, fs_rel: str) -> rl.Texture|None: ...
    def unload(self) -> None: ...
```

### 2.2 Refactor callsites in this order (low risk → high churn) [x]

1. `crimson/ui/perk_menu.py`
2. `crimson/ui/hud.py`
3. `crimson/ui/game_over.py`
4. debug views with private `_resolve_asset` methods
5. `crimson/game_world.py`

Why this order:

* UI modules have localized impact and a clean “assets object” pattern already.
* `game_world.py` is central and riskier; do it after the loader is proven.

### 2.3 Optional but valuable: pass a shared loader/cache down [ ]

Right now, multiple modules may create separate `PaqTextureCache` instances. If you centralize:

* Game boot creates a single `entries` dict + `PaqTextureCache`
* UI/world components receive a loader/provider

You reduce:

* duplicate decompression
* texture duplication in GPU memory
* “different module loads different version of the same asset” bugs

---

## Phase 3: Consolidate “tiny but everywhere” core utilities (without making a god-module) [x]

You have repeated `_clamp` and a duplicated MSVCRT LCG.

### 3.1 Unify the MSVCRT rand() implementation [x]

Right now:

* `crimson/crand.py` has `Crand`
* `grim/terrain_render.py` defines `CrtRand` with the same algorithm

Create `grim/rand.py`:

* `class CrtRand`
* pure Python, no `pyray`

Then:

* replace the copy in `grim/terrain_render.py` with an import
* delete `crimson/crand.py`, don't re-export for compatibility

### 3.2 Add a small, pure `grim.math` (or `grim.util.math`) [x]

Move every `_clamp` there. Do it opportunistically:

* Add `clamp`, `clamp01`, `lerp`
* Each time you touch a module with local `_clamp`, replace it with the shared one

---

## Phase 4: Make “where code belongs” obvious inside `crimson` [ ]

This is where you stop the constant re-introduction of mixed concerns.

### 4.1 Introduce internal subpackages by *responsibility* [x]

You don’t have to move everything at once. Start by **creating the directories** and moving a couple of modules per PR.

Suggested layout (matches your docs + what already exists):

* `crimson/sim/`
  Pure gameplay/simulation logic. No `pyray`.
* `crimson/render/`
  Rendering helpers that interpret sim state and draw via raylib/grim.
* `crimson/modes/`
  Survival, demo, quests/rush/etc controllers.
* `crimson/persistence/`
  `save_status`, `highscores`, config-ish stuff that is game-layer.
* `crimson/ui/` stays as-is.
* `crimson/views/` stays as tooling/debug, but should depend on `modes` and `ui`, not reinvent them.

### 4.2 Split `GameWorld` into “state + renderer + services” (keep a façade) [x]

`crimson/game_world.py` currently mixes:

* state ownership (players/creatures/projectiles/bonuses)
* sim updates
* rendering (textures, sprite selection, drawing)
* audio triggering
* asset loading

Refactor pattern that works well during rewrites:

1. [x] **Extract `WorldState`** (pure, no `pyray`):

   * holds pools, timers, RNG
   * `step(dt, input) -> events` (events are plain dataclasses)
2. [x] **Extract `WorldRenderer`** (raylib):

   * owns textures
   * `draw(state, camera, ...)`
3. [x] **Extract `AudioRouter`**:

   * maps events → `grim.audio.play_sfx/trigger_game_tune`

Keep `GameWorld` as the public façade for now so callsites don’t churn:

* `GameWorld.update()` delegates to `WorldState.step()` and routes events
* `GameWorld.draw()` delegates to renderer

This immediately prevents future “random rendering code inserted into simulation” and makes duplication easier to see.

---

## Phase 5: Break up `crimson/game.py` without losing parity mapping [ ]

`crimson/game.py` is large enough that duplicates and “wrong place” logic will accumulate there by default.

### 5.1 Extract by *screen / subsystem*, not by “utility” [ ]

To avoid creating a junk-drawer module, extract cohesive chunks:

* [x] `crimson/frontend/boot.py` (boot stages, resource pack init, logo flow)
* [x] `crimson/frontend/menu.py` (main menu buttons + transitions)
* [x] `crimson/frontend/panels/base.py` (shared panel shell + layout)
* [x] `crimson/frontend/panels/play_game.py`
* [x] `crimson/frontend/panels/options.py`
* [x] `crimson/frontend/panels/stats.py`
* [x] `crimson/frontend/transitions.py` (screen fade, timeline helpers)
* [ ] `crimson/frontend/assets.py` (menu textures, panels; uses the shared TextureLoader)

Keep:

* `GameState` dataclass and top-level `run_game(...)` style entrypoints in `game.py`
* This preserves “searchability” for parity work, while still shrinking the file.

### 5.2 Enforce “frontend doesn’t own gameplay rules” [ ]

Rule of thumb:

* menu/panel code can set “desired mode”, “selected quest”, “hardcore toggle”
* only mode/controller code mutates simulation state

---

## Phase 6: Consolidate mode logic so debug views don’t fork behavior [x]

You currently have:

* “main game flow” in `crimson/game.py`
* “playable survival” in `crimson/views/survival.py` using `GameWorld`

To prevent duplication drift:

### 6.1 Create `crimson/modes/survival_mode.py` [x]

It should expose something like:

* `SurvivalMode.update(dt) -> ModeAction/events`
* `SurvivalMode.draw(...)`
* or split update/draw like the WorldState/WorldRenderer pattern

Then:

* `crimson/game.py` uses the same mode class
* `crimson/views/survival.py` becomes a thin wrapper that hosts the mode in the view runner

This keeps “debug tooling” from becoming a second implementation.

---

## Phase 7: Systematic duplicate removal (after boundaries + structure) [ ]

Once the big rocks above land, duplication work becomes much cheaper.

### 7.1 Triage duplicates into buckets [ ]

Run your duplicate report and classify each hit:

1. **Infrastructure duplicates** (fix immediately):

   * asset loading, file locating, texture ownership/unload
2. **Math / small helpers** (fix opportunistically):

   * clamp/lerp/angle conversions
3. **UI widget patterns** (fix by making real widgets):

   * button behavior, text input, hover timers, layout calculation
4. **Content-ish repetition** (often keep as data, not code):

   * spawn tables, quest tiers, weapon/perk/bonus tables

### 7.2 Add a “no new duplicates” rule for the top bucket [ ]

Once asset loading is centralized, make it policy:

* new code **must** use the loader/provider
* no new `_resolve_asset` clones

---

## Phase 8: Keep it tidy while the rewrite continues [ ]

### 8.1 Encode the architecture in tooling [ ]

* Boundary checker (grim ↛ crimson)
* “sim ↛ pyray” checker
* Optional: “views should not be imported by runtime” checker

### 8.2 Make “what is stable API” explicit [ ]

* Everything can move freely for now.


### 8.3 Set refactor-friendly PR conventions [ ]

For a fast-moving rewrite, this matters more than perfect architecture:

* Small PRs (single theme)
* Mechanical moves + behavior changes separated where possible
* Always keep `uv run crimson ...` entrypoints green
* When moving modules, leave re-export stubs for one cycle

---

## A pragmatic “do these next” shortlist [ ]

If you want the fastest impact on “duplicates + wrong place code”, do these in order:

1. [x] **Fix `grim.fx_queue` importing `crimson.*`** (hard boundary violation).
2. [x] **Centralize asset resolve/load** (kills repeated `_resolve_asset` patterns everywhere).
3. [x] **Unify MSVCRT rand() implementation** (easy win, removes cross-package duplication pressure).
4. [x] **Split `GameWorld` into state/renderer/audio-router** (stops future tangling).
5. [x] **Extract survival mode controller** so `game.py` and `views/survival.py` don’t diverge.
6. [ ] **Start shrinking `game.py`** by extracting screens/panels into modules.

If you want, I can also turn this into a concrete **refactor backlog** (ordered, PR-sized chunks with “touch files A/B/C, expected diffs, and rollback strategy”) using the exact module names you already have.
