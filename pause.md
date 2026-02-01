Here’s what the original EXE does for “pause”, what our port currently does, and a concrete, low-risk plan to bring us to parity.

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

## What our port does today (gaps)

### A) ESC exits gameplay immediately

In every gameplay mode, ESC sets `close_requested = True`, which results in `back_to_menu`:

* `src/crimson/modes/quest_mode.py` lines **308–309**
* `src/crimson/modes/survival_mode.py` lines **188–189**
* `src/crimson/modes/rush_mode.py` lines **79–80**
* `src/crimson/modes/tutorial_mode.py` lines **134–135**
* `src/crimson/modes/typo_mode.py` lines **103–104**

So we’re missing the pause menu state entirely.

### B) We don’t have the in-game pause menu UI (Options/Quit/Back)

No view/panel currently renders the pause overlay with those three menu items over the frozen world.

### C) Options/Controls panels are “main-menu flavored”

Even if we open options from pause later, our current panels:

* draw the **menu ground** background (not the paused world)
* and the Options back button is currently configured to return to menu flow, not pause flow

(Also: `OptionsMenuView` and several panels override `draw()` and always draw the ground.)

### D) Our “pause” key is TAB, but original uses ESC menu + F1 “key info pause”

We currently toggle `_paused` with `TAB` in modes. The original has:

* ESC: pause menu (state 5)
* F1: toggles `game_paused_flag` and fades in the “key info” overlay (“Press F1 to return to game”)

Your request is specifically about the **ESC pause menu**, so treat the F1 overlay as a follow-up parity item.

---

## Concrete plan to reach parity (minimal churn, matches original architecture)

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
  * `self._draw_screen_fade()`

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

We have two options; pick one:

**Option A (localized, safest):** Update only the views we need.

* In `OptionsMenuView.draw()`:

  * if `state.pause_background` exists: draw that background instead of ground
* In `ControlsMenuView.draw()`:

  * same idea

**Option B (more general, closer to EXE “render_pass_mode”):** Teach `PanelMenuView` to draw the paused world when present.

* Update `PanelMenuView._init_ground()` to **skip ground** when `state.pause_background` is set.
* Update `PanelMenuView.draw()` to:

  * if `state.pause_background`: call it
  * else draw ground

Then only fix the panel subclasses that override `draw()` and hardcode ground drawing (Options/Controls/Stats/etc).

Given we’re aiming for parity and this behavior likely applies to other panels later, **Option B is probably the right long-term direction**, but Option A is a quick, bounded change.

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

1. Implement `BaseGameplayMode.draw_pause_background()` + wrappers exposing it
2. Implement `PauseMenuView` with Options/Quit/Back
3. Wire `"open_pause_menu"` from gameplay ESC instead of `close_requested`
4. Make Options back_action `"open_pause_menu"` and implement the handler logic (“if not paused, go to menu”)
5. Make Options/Controls draw paused background when available

That gets us very close to the EXE behavior with minimal refactors, and it sets us up to replicate the EXE’s “menus render gameplay when a game is running” model cleanly across other panels later.
