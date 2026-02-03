Here’s what jumped out when scanning `src/` (especially for duplicated logic and “too-big-to-reason-about” modules), plus a concrete, incremental refactor + testing plan that matches the “quest builders / spawn templates” style (data-driven, isolated, testable pieces).

I’ll reference files/functions directly so you can turn this into issues.

---

## 1) High-value duplicate code to delete by introducing shared components

### A. Perk menu logic is copied across modes

**Where:**

* `src/crimson/modes/survival_mode.py`: `_open_perk_menu`, `_perk_menu_handle_input`, `_draw_perk_menu`, `_perk_prompt_rect`, plus a big perk prompt block in `update()`.
* `src/crimson/modes/quest_mode.py`: same structure, with `GameMode.QUESTS` instead.
* `src/crimson/modes/tutorial_mode.py`: same again with slightly different behavior (and it even has a small accidental duplication: `slide_x = ...` is assigned twice).

**Why it’s hurting you:**

* It’s ~the same UI state machine + input processing three times.
* Fixes and UX changes will drift.
* Tests like `tests/test_perk_menu_sfx.py` are forced to target one mode, but the same bug could exist in others.

**Refactor shape (idiomatic + testable):**
Create a controller that owns the perk menu UI state and returns “actions” instead of directly mutating the mode beyond what it must.

Suggested new module:

* `src/crimson/modes/components/perk_menu_controller.py` (or `src/crimson/ui/perk_menu_controller.py` if you want it “UI-level”, but it currently needs mode/gameplay calls)

Core API idea:

```py
@dataclass(slots=True)
class PerkMenuAction:
    kind: Literal["picked", "cancelled", "noop"]
    picked_index: int | None = None

@dataclass(slots=True)
class PerkMenuConfig:
    game_mode: int
    player_count: int
    play_sfx: bool = True
    reset_prompt_on_close: bool = False  # quests currently does this

class PerkMenuController:
    def __init__(...):
        # holds open/timeline/selected/cancel_button/etc

    def open_if_available(...) -> bool:
        # checks pending_count + choices; optionally plays sfx

    def update(...) -> PerkMenuAction:
        # consumes input, updates selected, returns action

    def draw(...) -> None:
        # uses crimson.ui.perk_menu primitives
```

Then each mode does:

* Build `PerkMenuConfig(game_mode=..., player_count=len(players), reset_prompt_on_close=...)`
* Call controller’s `update()` and interpret returned `picked`/`cancelled` action (apply perk, play `sfx_ui_bonus`, etc).
* The “perk prompt” can either live in this controller too, or in a tiny `PerkPromptController` used by both quest/survival.

**Test win:**
You can turn the existing `tests/test_perk_menu_sfx.py` into tests for the controller (one codepath), and add a couple of thin “mode wires controller correctly” tests for each mode.

---

### B. Game-over handling block duplicated across modes

**Where:**

* `survival_mode.update`, `rush_mode.update`, `typo_mode.update` have nearly identical:

  * `if self._game_over_active:` block
  * `record = self._game_over_record; if None: self._enter_game_over()`
  * `action = self._game_over_ui.update(...)`
  * action routing: play again / high scores / main menu

**Refactor:**
Make `BaseGameplayMode` own the orchestration of “game over UI update → action decision”, and let derived modes only:

* Provide `build_highscore_record()` implementation.
* Decide what “play_again” means (often `self.open()`).

Suggested:

* `src/crimson/modes/components/game_over_controller.py`
* Or just fold into `BaseGameplayMode` as `_update_game_over(dt) -> str | None`.

Also extract the record-building duplication:

* `rush_mode._enter_game_over`
* `survival_mode._enter_game_over`
* `typo_mode._enter_game_over`

into one helper:

* `crimson/persistence/highscores_helpers.py` (or `modes/components/highscore_record_builder.py`)

**Test win:**

* Add “record builder” tests (pure, no `pyray`) for each mode, or parameterize by mode id.
* Add “game over controller routes actions” test (monkeypatch sfx, mouse, RNG).

---

### C. Menu/panel drawing boilerplate duplicated in several panel views

**Where:**
`ControlsMenuView.draw`, `ModsMenuView.draw`, `PlayGameMenuView.draw` are structurally identical:

* draw background
* fade
* check assets/entry
* draw panel
* draw entry
* draw sign
* draw contents
* cursor

But `PanelMenuView.draw()` already does most of this — it just calls `_draw_title_text()` instead of allowing custom content.

**Refactor:**
Change `PanelMenuView.draw()` to call a hook:

* `self._draw_contents()` (default implementation calls `_draw_title_text()`)

Then remove the repeated `draw()` overrides in those panels.

**Test win:**

* Add one test for `PanelMenuView.draw()` to ensure it calls `_draw_contents` (monkeypatch to record calls), not per-panel.

---

### D. UI “name entry” / “ordinal formatting” duplicated in results screens

**Where:**

* `src/crimson/ui/game_over.py`: `_poll_text_input`, `_format_ordinal`, `ui_scale`, `ui_origin`, etc.
* `src/crimson/ui/quest_results.py`: same `_poll_text_input`, `_format_ordinal`, plus time formatting.

**Refactor:**
Create small shared helpers:

* `src/crimson/ui/text_input.py`: `poll_text_input(max_len, allow_space=True) -> str`
* `src/crimson/ui/formatting.py`: `format_ordinal(n)`, `format_time_mm_ss(ms)`
* `src/crimson/ui/layout.py`: `UI_BASE_WIDTH/HEIGHT`, `_menu_widescreen_y_shift`, `ui_scale`, `ui_origin`

Then both screens import them.

**Test win:**

* Unit tests for `format_ordinal` edge cases (11/12/13).
* Unit tests for `poll_text_input` behavior can monkeypatch `rl.get_char_pressed` once.

---

### E. Debug views share the same helpers everywhere

**Where:**
Many files under `src/crimson/views/` re-define identical utilities:

* `_draw_ui_text` is identical across **17** view modules.
* `_clamp` is redefined in tons of places.
* Several views repeat similar “world init + small font + mouse tracking + close on ESC”.

**Refactor options:**

1. Small, low-risk:

   * Create `src/crimson/views/_ui_helpers.py`:

     * `draw_ui_text(font, text, x, y, *, scale, color)`
     * `ui_line_height(font, *, scale)`
     * `clamp_mouse_to_screen(pos)`
   * Replace the copy/paste helpers with imports.

2. Bigger, but cleaner:

   * Create `BaseDebugView` mixin/base class that provides:

     * `_ensure_small_font()`
     * `_update_ui_mouse()`
     * `_draw_ui_text()`

**Coverage reality check:**
`src/crimson/views/` is ~9k LOC. If those are dev tools, you can either:

* Add **one** parametrized smoke test that instantiates each view and runs one `update/draw` with raylib functions monkeypatched to no-ops (quick coverage bump + ensures they don’t crash), **or**
* If they’re intentionally non-production tooling, exclude them from coverage and track coverage separately for shipped code. (This isn’t “cheating” if you explicitly decide they’re out-of-scope for production correctness.)

---

### F. Small math helpers are duplicated all over the place

**Where:**
Many modules define their own `_clamp` and `_distance_sq`, even though you already have `grim.math.clamp`.

Files with `def _clamp(` include (non-exhaustive):
`creatures/runtime.py`, `demo.py`, `effects.py`, `gameplay.py`, `modes/base_gameplay_mode.py`, `ui/perk_menu.py`, `views/*`, `typo/spawns.py`, etc.

**Refactor:**

* Use `from grim.math import clamp` everywhere.
* Add `distance_sq`, `distance`, maybe `clamp_int` to `grim.math` if needed.
* Delete the local copies.

This is a classic “reduce noise” refactor that makes future diffs easier.

---

## 2) “Poorly organized” hotspots: split the giant functions/modules the same way you did quests/spawns

The biggest maintainability issue in this repo is not “bad code”; it’s that some game systems are still implemented as single massive functions.

Top offenders by function size:

* `crimson/projectiles.py:update` (~657 LOC)
* `crimson/render/world_renderer.py:_draw_projectile` (~606 LOC)
* `crimson/ui/hud.py:draw_hud_overlay` (~550 LOC)
* `crimson/creatures/runtime.py:update` (~413 LOC)
* `crimson/sim/world_state.py:step` (~312 LOC)

These are exactly the places where “registry + small handlers” shines (your quest builder refactor pattern).

### A. Refactor `ProjectilePool.update` into per-type behaviors (registry)

**Goal:** Replace big switchy logic with a table of handlers.

Structure:

* `src/crimson/projectiles/behaviors.py`

  * `ProjectileUpdateContext` (dt, world size, state refs, callbacks)
  * `ProjectileBehavior` protocol: `update(projectile, ctx) -> None`
  * `BEHAVIORS: dict[ProjectileTypeId, ProjectileBehavior]`

Then in `ProjectilePool.update`:

* Keep the outer loop, ordering, and shared collision helpers (for fidelity).
* Dispatch to the behavior function for that projectile type.

**Tests:**

* “Registry completeness” test: every `ProjectileTypeId` has a handler (or is explicitly in `UNIMPLEMENTED` with a comment).
* Per-projectile unit tests: small dt, known initial state → expected movement/damage/effects.

This will also make it much easier to validate against your `analysis/` traces for specific projectile types.

---

### B. Refactor `_draw_projectile` into a renderer registry

Mirror the same approach as projectile updates:

* `src/crimson/render/projectile_renderers.py`

  * `draw(projectile, ctx)` per projectile type

Even if the draw logic has to remain imperative (because raylib), you can:

* Extract “which sprite/atlas frame, which rotation, which scale” into pure functions.
* Unit test those pure selectors without raylib.

---

### C. HUD: eliminate module-level state and split into “layout” vs “draw”

`ui/hud.py` currently has:

* a module global `_SURVIVAL_XP_SMOOTHED` (hard to test, hostile to multiple game instances, etc.)
* a monolithic `draw_hud_overlay`

Refactor:

* `HudState` dataclass containing smoothed values
* `HudLayout` pure computation:

  * input: screen size, scale, number of players, flags
  * output: rectangles/positions
* `HudRenderer.draw(layout, state, inputs…)` does drawing

**Tests:**

* Smoothing behavior (given xp jumps, ensure the smoothing curve matches).
* Layout invariants (positions stay within screen bounds; multiplayer spacing, etc.)

---

### D. World step: turn `WorldState.step` into explicit phases

Even if you keep it in one file for ordering/fidelity, extract phase helpers:

Example:

* `_step_players(...)`
* `_step_projectiles(...)`
* `_step_creatures(...)`
* `_step_spawns(...)`
* `_apply_deaths_and_cleanup(...)`

…and keep the orchestration ordering in `step()`.

This makes it readable without changing behavior.

---

## 3) Concrete plan to improve the codebase (refactor + tests + guardrails)

### Phase 1 — Quick wins (high impact, low risk)

1. **Delete “utility duplication”**

   * Replace local `_clamp` / `_distance_sq` with `grim.math`.
   * Extract `ui/text_input.py`, `ui/formatting.py`, `ui/layout.py`.
   * Extract `views/_ui_helpers.py` and use it across debug views.

2. **Remove duplicated overrides that are purely structural**

   * Add `PanelMenuView._draw_contents()` hook so panels stop duplicating `draw()`.

3. **Fix obvious copy/paste issues while you’re here**

   * `tutorial_mode._perk_menu_handle_input` assigns `slide_x` twice — clean that up during the perk-menu refactor.

**Coverage bump:** Small, but you’ll gain meaningful unit tests for the new helper modules.

---

### Phase 2 — Shared controllers for mode UI flows

4. **Introduce `PerkMenuController`**

   * Remove perk menu duplication across quest/survival/tutorial modes.
   * Convert existing perk-menu tests to controller tests + a couple of mode wiring tests.

5. **Introduce `GameOverController` + record builder**

   * Deduplicate game-over update flow across survival/rush/typo.
   * Add tests for record building + action routing.

**Coverage bump:** Medium/high. Modes are fat and controller extraction tends to create pure/testable code.

---

### Phase 3 — Registry refactors for the big “switch” systems

6. **Projectiles: behavior registry**

   * Split `ProjectilePool.update` into per-type handlers.
   * Add “registry completeness” tests and per-type behavior tests.

7. **Rendering: projectile renderer registry**

   * Extract per-type renderer functions.
   * Prefer extracting pure “sprite selection” helpers first (testable without raylib).

8. **HUD: stateful renderer**

   * Move module global into `HudState`.
   * Split layout computation from drawing.

**Coverage bump:** High if you extract selection/layout into pure functions and test them.

---

### Phase 4 — Keep it clean (prevent regressions)

9. **Guardrails**

   * Add a CI job that fails if:

     * A registry is missing an enum handler (projectiles, bonuses, etc).
     * Any function exceeds a “maximum” threshold (or at least warn) for core modules.
   * You already use `import-linter`; keep expanding boundaries as you split modules (e.g., prevent `render/` from importing simulation internals directly).

10. **Make coverage targets meaningful**

* Track coverage per package area:

  * `crimson/sim`, `crimson/creatures`, `crimson/gameplay` (core correctness) should be held to a high standard.
  * `crimson/views` (debug tools) can be either excluded or covered by smoke tests.
* Add a “new code must be tested” rule: e.g., require coverage to not decrease, or require a minimum for changed files.

---

## 4) One extra “developer experience” suggestion

Right now `src/crimson/__init__.py` tries to do:

```py
__version__ = importlib.metadata.version("crimsonland")
```

which crashes if the package metadata isn’t installed (i.e., running `pytest` without an editable install). In your environment you probably use `uv run` so it’s fine, but contributors (and tooling) often run `pytest` directly.

Easy improvement:

```py
try:
    __version__ = importlib.metadata.version("crimsonland")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0"
```

Small change, less friction.

---

## If you want the biggest ROI shortlist

If you only do 3 things first, I’d do:

1. **PerkMenuController** (kills a lot of duplication + improves tests)
2. **GameOverController/record builder** (same)
3. **Projectile behavior registry** (turns a 657-line hotspot into testable pieces)

Those are the most aligned with your “quest builders / spawn templates” standard: explicit, composable, and easy to unit test.

Also: once the controllers exist, you can cleanly move shared mode code upward (or compose shared components) without creating a “god base class”.
