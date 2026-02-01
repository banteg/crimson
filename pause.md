Here’s what the original EXE does for “pause”, what our port currently does, and a concrete, low-risk plan to bring us to parity.

## Status (2026-02-01)

Implemented:

* ESC in gameplay opens the pause menu (Options/Quit/Back) and freezes simulation.
* Pause menu renders over the paused world (`state.pause_background`).
* Options back returns to pause menu when in-game (and to main menu otherwise).
* Panels render over paused world when `state.pause_background` is set.

Remaining parity item:

* F1 “key info pause” overlay (separate from ESC pause menu).

## What the original game does (authoritative behavior)

### 1) **ESC does not quit gameplay — it enters a pause menu (state 5)**

In the original main loop, `ESC` (DirectInput `DIK_ESCAPE == 1`) is checked **while in gameplay states**. If pressed, it transitions into **game state 5** (pause menu) with `ui_transition_direction = 0` and `game_state_pending = 5`. If a plugin/mod interface exists, it also sets `onPause = 1`.

You can see this in the IDA decompile around the main loop (search hit around line ~8415 in `analysis/ida/raw/crimsonland.exe/crimsonland.exe_decompiled.c`).

**Implication for us:** `ESC` should open an in-game pause menu overlay and freeze simulation, not return to main menu immediately.

---

### 2) **Pause menu (state 5) has exactly three menu items**

The pause menu is built from the same “big menu item” widgets as the main menu, reusing the same label art/UV rows:

* **Options** (reuses main menu “Options” item and callback)
* **Quit** (reuses main menu “Quit” item art, but the callback returns to main menu / shuts down mod)
* **Back** (reuses the “Back” item art; resumes the game)

In the IDA decompile of `ui_menu_layout_init` (search hit around line ~58540), the pause items are positioned at:

* Options: **(-60, 210)**
* Quit: **(-80, 270)**
* Back: **(-100, 330)**

…which matches our existing `MenuView` slot logic (x shifts by -20 per slot, y by +60 per slot).

---

### 3) **What each button actually does (from the original callbacks)**

**Back / Resume** (`sub_447490` in IDA decompile, around line ~52517):

* Clears plugin `onPause` if present
* Transitions back to gameplay:

  * generally to state **9**, but
  * to state **0x12 (18)** when the active mode is survival (it branches on `config_game_mode == 4`)

**Quit** (`sub_4474E0`, around line ~52544):

* Clears plugin pause, shuts down and unloads plugin if one is active
* Sets `render_pass_mode = 0` and returns to **main menu state 0**
* Stops/mutes in-game music and starts the menu theme

**Options back behavior** (`FUN_00447420`, around line ~52477):

* Back from Options goes to **pause menu (state 5)** if you were in-game (`render_pass_mode != 0`)
* Otherwise goes to **main menu (state 0)**

**Implication for us:** Options must behave differently depending on whether it was opened from gameplay (pause context) or from main menu.

---

## What our port does today (current behavior)

* ESC: opens pause menu (and does **not** quit to main menu).
* TAB: toggles per-mode `_paused` (dev pause); original uses F1 for the “key info pause” overlay.

---

## Concrete plan to reach parity (minimal churn, matches original architecture)

Implemented in `src/` as of **2026-02-01** (Phase 1 + Phase 2), except Phase 3.

### Phase 1 — Add the pause menu view and wire ESC to open it

#### 1) Add a “pause background provider” to state

Add to `GameState` (in `src/crimson/game.py` `class GameState`):

* `pause_background: object | None = None`

This will hold a reference to the currently paused gameplay view (or mode) that can draw the world without gameplay UI/cursor.

#### 2) Teach gameplay views to draw “world only” (no cursor/HUD)

Add a method to each gameplay wrapper in `game.py` (e.g. `SurvivalGameView`, `QuestGameView`, etc.):

* `def draw_pause_background(self) -> None:`

  * call into the mode:

    * `self._mode.draw_pause_background()`

Then implement in `BaseGameplayMode` (`src/crimson/modes/base_gameplay_mode.py`):

* `def draw_pause_background(self) -> None:`

  * `self._world.draw(draw_aim_indicators=False)` (or `True` if you want it)

This mirrors the EXE’s `gameplay_render_world()` usage for menu states (render world, not simulate).

#### 3) Implement `PauseMenuView`

Create `src/crimson/frontend/pause_menu.py` (or under `frontend/panels/` if you prefer), implementing the standard `FrontView` methods.

UI spec (matches original):

* Menu sign (Crimsonland sign)
* 3 menu entries:

  * `Options` → action `"open_options"`
  * `Quit` → action `"back_to_menu"`
  * `Back` → action `"back_to_previous"` (resume gameplay)

Rendering:

* Background:

  * if `state.pause_background` is set: call `state.pause_background.draw_pause_background()`
  * else: clear black
* Then draw screen fade overlay (same helper as menus use)
* Then draw the sign + menu items (reuse `frontend/menu.py` animation helpers if possible)
* Draw menu cursor

Input:

* mouse hover + click selects
* `TAB` cycles selection (we already do this in `MenuView`, and original menus support keyboard selection)
* `ENTER` activates selected
* `ESC` should behave like selecting **Back** (resume)

Positions/rows:

* Reuse the same rows we already have:

  * `MENU_LABEL_ROW_OPTIONS`
  * `MENU_LABEL_ROW_QUIT`
  * `MENU_LABEL_ROW_BACK`
* Slots 0/1/2 automatically give x = -60/-80/-100 and y = 210/270/330 via our existing menu math.

#### 4) Wire it into the front-view router

In `GameLoopView.__init__`, add:

* `"open_pause_menu": PauseMenuView(self._state)`

In `GameLoopView.update()`, handle `"open_pause_menu"` specially:

* If current active is a gameplay view:

  * set `state.pause_background = self._front_active`
  * push gameplay view onto `self._front_stack` (so resume can use existing `back_to_previous`)
  * switch to PauseMenuView **without closing gameplay**
* If current active is NOT a gameplay view:

  * only open PauseMenuView if `state.pause_background is not None` (we’re already in “paused session”)
  * otherwise treat it like `back_to_menu` (this is how we can reuse `"open_pause_menu"` as the “Options back” target too — see Phase 2)

#### 5) Change gameplay modes: ESC should request pause menu, not close

Replace the “ESC closes gameplay” lines listed above with something like:

* if perk menu is open: keep existing behavior (close perk menu)
* else: set mode action `"open_pause_menu"`

In each wrapper (`SurvivalGameView.update`, etc.), add:

* if `mode_action == "open_pause_menu"`: set wrapper `_action = "open_pause_menu"`

That’s it for Phase 1: ESC now opens pause menu and simulation stops because the gameplay view is not being updated while paused.

---

### Phase 2 — Make Options/Controls behave correctly when opened from pause

This is the piece most ports miss, and the EXE is explicit about it (`FUN_00447420`).

#### 6) Make Options “Back” return to pause menu when in-game

Change `OptionsMenuView` to use:

* `back_action="open_pause_menu"`

That matches the original logic: “back goes to pause menu if game is running, otherwise to main menu”.
We implement that by **teaching `GameLoopView`**: when handling `"open_pause_menu"` and there is no `state.pause_background`, just go to main menu.

So the same action string works in both contexts.

#### 7) Options/Controls need to draw paused-world background instead of menu ground

Implemented (Option B): `PanelMenuView` renders the paused world when `state.pause_background` is set (and skips menu ground generation). Panel subclasses that override `draw()` use the same background helper so this works consistently.

#### 8) Ensure quitting clears the pause context

When pause menu chooses Quit (`"back_to_menu"`):

* Clear `state.pause_background = None`
* Close the paused gameplay view stored in the stack (it will be closed by existing stack cleanup if we keep using `back_to_menu`)
* Then open menu as we do today (menu theme restarts, matching original)

When resuming (`"back_to_previous"`):

* After popping gameplay view:

  * clear `state.pause_background = None`

---

### Phase 3 — (Optional but real parity) Add F1 “key info pause”

Not required for your immediate “ESC pause menu” goal, but the EXE clearly has it:

* F1 toggles a `game_paused_flag`
* While paused, it fades in/out the “key info” overlay and freezes simulation
* It says “Press F1 to return to game” and lists bindings

We can do this later by:

* moving our TAB pause to F1 (or keep TAB as dev-only)
* rendering a simple overlay using our existing font/text utilities
* listing bindings from config (we already have keybind data in ControlsMenuView)

---

## Acceptance checklist (parity-focused)

1. In any gameplay mode, press **ESC**:

* world freezes
* pause menu appears over gameplay background
* menu cursor appears

2. Pause menu buttons:

* **Back** resumes gameplay exactly where it left off
* **Options** opens options panel **over paused world**
* **Quit** returns to main menu (and the current run is abandoned)

3. Options → Controls → back:

* Controls returns to Options
* Options back returns to pause menu (in-game) / main menu (out-of-game)

4. No lingering pause context:

* After resuming or quitting, `state.pause_background` is cleared
* No stale stack entries remain

---

## “Do this first” sequence for fastest progress

Completed on **2026-02-01** (Phase 1 + Phase 2).

Next parity item:

1. Implement F1 “key info pause” overlay (Phase 3).
