---
tags:
  - rewrite
  - ui
  - screens
  - panels
  - architecture
---

# Screens and panels architecture (rewrite)

This document captures the current shape of the Python front-end screen code in
`src/crimson/screens/`, the main problems with that shape, and a proposed
rewrite architecture for making it more idiomatic without changing user-visible
behavior.

Scope:

- the shared screen-chrome surface under `src/crimson/screens/menu.py`,
  `src/crimson/screens/pause_menu.py`, and `src/crimson/screens/panels/*`
- closely related panel-like screens that already duplicate the same shell
  (`StatisticsMenuView`, `CreditsView`, `AlienZooKeeperView`,
  `_DatabaseBaseView`)

Implementation-wave scope:

- the first code migration should prove the chrome against panel-like adopters
  first:
  - `PanelMenuView` and its direct subclasses
  - `StatisticsMenuView`
  - `_DatabaseBaseView`
  - `CreditsView`
  - `AlienZooKeeperView`
- `MenuView` and `PauseMenuView` stay in architecture scope, but get their own
  dedicated migration phase after the panel-like screens because they carry
  extra behaviors that are central to validating the final shell:
  - menu music policy
  - idle-demo triggering
  - sign lock/unlock behavior on quit
  - pause-background entity alpha rules

Out of scope for the first implementation wave:

- result/game-over/quest-result screens
- quest select / quest failed / end note screens
- `HighScoresView`
- changing action names or `GameLoopView` routing
- changing visible timing, audio, or layout behavior unless explicitly called
  out and reviewed

## Intent

The current code works, but much of the screens/panels layer still looks like a
direct port of decompiled control flow:

- each view owns a slightly different copy of the same lifecycle shell
- layout and animation math is repeated inside concrete views
- generic chrome concerns are mixed with screen-specific behavior
- some views reconstruct gameplay/query state inline instead of consuming a
  named helper

The rewrite goal is not to make the UI generic. The rewrite goal is to isolate
the shared screen chrome so that each screen class only owns the logic that is
actually specific to that screen.

## Current screen families

Today the front-end screens fall into a few clear families.

| Family | Current files | Notes |
| --- | --- | --- |
| Main menu shell | `src/crimson/screens/menu.py` | Multi-entry animated main menu with menu terrain, sign animation, cursor, idle demo trigger, and back-to-front action routing. |
| Pause menu shell | `src/crimson/screens/pause_menu.py` | Small sibling of the main menu with a shorter entry set and pause-background-specific behavior. |
| `PanelMenuView` family | `src/crimson/screens/panels/base.py`, `play_game.py`, `options.py`, `controls.py`, `mods.py`, `network_session.py`, `network_lobby.py` | One-panel screens that share panel/back/sign chrome, but diverge on content interaction and back-control behavior. |
| Standalone panel-like screens | `stats.py`, `credits.py`, `alien_zookeeper.py`, `databases_base.py` | These reimplement nearly the same shell instead of using `PanelMenuView` because that abstraction is too opinionated. |
| Adjacent adopter | `src/crimson/screens/high_scores_view/view.py` | Not part of the first implementation slice, but it already duplicates the same lifecycle and close-transition shell. |

## Current findings

### 1. The lifecycle shell is duplicated across many screens

The following concerns are repeated with only minor variations:

- `_is_open` / `_closing` / `_close_action` / `_pending_action` state
- `open()` reset logic
- `close()` teardown logic
- `update()` stepping of a `300ms`-style panel timeline
- close-transition countdown that converts `_close_action` into a pending action
- `take_action()` handoff
- `_assert_open()`
- cursor pulse stepping
- `update_audio(...)`
- menu-ground or pause-background setup
- shared `draw()` shape: clear background, draw ground or pause background, draw
  fade, draw panels, draw sign, draw cursor

This pattern exists in:

- `MenuView`
- `PauseMenuView`
- `PanelMenuView`
- `StatisticsMenuView`
- `CreditsView`
- `AlienZooKeeperView`
- `_DatabaseBaseView`
- `HighScoresView`

The duplication is large enough that changing transition semantics or backdrop
rules currently means touching several unrelated view classes.

### 2. `PanelMenuView` hard-codes one very specific interaction model

`PanelMenuView` is not really “generic panel chrome”. It is “single panel with a
single atlas-backed Back menu entry and title/body text”.

That assumption leaks into:

- `_entry` always being a single `MenuEntry`
- `_draw_entry(...)` always rendering the atlas-backed Back item
- `_draw_contents()` defaulting to title/body text
- `update()` assuming `Escape`, `Enter`, and left click on the Back entry all
  mean the same thing

This makes the abstraction brittle:

- `PlayGameMenuView` has to clone most of `update()` because `Enter` must not
  auto-back there
- `NetworkSessionPanelView` and `NetworkLobbyPanelView` replace the back label
  with a `UiButtonState`, then override `_draw_entry(...)` with a no-op and
  reimplement back-button handling themselves
- panel subclasses repeatedly recalculate the same animated panel anchors for
  their content because `PanelMenuView` does not expose a reusable frame/layout
  object

The result is that `PanelMenuView` is both too strong and too weak:

- too strong about back-control behavior
- too weak about shared geometry and lifecycle support

### 3. Geometry and animation are not owned in one place

`PanelMenuView` already depends on `MenuView` statics for:

- `_ui_element_anim(...)`
- `_draw_ui_quad(...)`
- `_draw_ui_quad_shadow(...)`
- `_sign_layout_scale(...)`
- `_menu_widescreen_y_shift(...)`

But concrete panel subclasses still recompute:

- panel scale
- animated slide offset
- top-left panel origin
- derived content anchors
- button anchor positions

That is why multiple files have their own `_content_layout()` or `_layout()`
functions that all begin with the same sequence:

1. derive `panel_scale`
2. compute `panel_w`
3. call `MenuView._ui_element_anim(...)`
4. reconstruct `panel_top_left`
5. derive screen-specific anchors from that point

This is a clear sign that animated panel geometry should be a shared service,
not hand-rebuilt per screen.

### 4. Backdrop, fade, sign, and cursor are chrome concerns, not screen logic

Most screen `draw()` implementations do roughly this:

1. clear to black
2. draw pause background or menu ground
3. draw screen fade
4. draw one or more panels
5. draw screen contents
6. draw the Crimson sign
7. draw the menu cursor

Those steps are nearly invariant, yet they currently live inside many concrete
view classes. The content logic is much smaller than the surrounding chrome.

### 5. “Save dirty config on close” is repeated instead of modeled

At least these views duplicate the same concern:

- `OptionsMenuView`
- `ControlsMenuView`
- `PlayGameMenuView`
- `HighScoresView`

Each one tracks `_dirty`, tries `self.state.config.save()` in
`_begin_close_transition(...)`, logs failures, and clears `_dirty` on success.

This is not panel-specific behavior. It is a reusable close hook.

### 6. Some UI views still own gameplay/query reconstruction

The UI layer currently contains logic that is not really view logic:

- `UnlockedWeaponsDatabaseView` reconstructs weapon availability and contains an
  inline stub adapter for `weapon_refresh_available`
- `UnlockedPerksDatabaseView` reconstructs perk availability in the view module

That code is decompile-shaped because it was ported in place to get the feature
working. It should move behind named helpers so the views only ask for
“available weapons” or “available perks”.

### 7. The shared shell is wider than `screens/panels`

The same lifecycle pattern already appears in `HighScoresView`, and similar
patterns exist in quest/result views. This matters for the architecture: the
right abstraction boundary is below `PanelMenuView`, not inside it.

For the first implementation pass we should still limit the code migration to
`screens/panels` and the shared shell below it, but the design should expect
later adopters.

## Problems with the current organization

The current shape has a few concrete costs.

### Change amplification

If we want to change how close transitions work, how the sign is drawn, or how
menu ground is selected, we currently have to patch several view classes.

### Blurred ownership

Concrete views mix:

- lifecycle shell
- geometry computation
- generic control behavior
- content-specific update/draw logic
- sometimes even gameplay/query reconstruction

This makes the files long and hard to navigate because the interesting
screen-specific logic is buried under framework plumbing.

### Inconsistent reuse

The codebase already knows some things are shared:

- `MenuView` owns animation and quad-draw helpers
- `PanelMenuView` owns one panel shell
- `_DatabaseBaseView` owns a split-panel shell

But those reuse boundaries do not line up cleanly, so each new screen either:

- forks an existing abstraction, or
- creates yet another local mini-framework

### Poor fit for idiomatic Python

Idiomatic Python here should mean:

- small view classes with named responsibilities
- pure layout helpers for geometry
- reusable controllers for generic interaction patterns
- `msgspec.Struct` for structured config/layout/frame carriers where that helps

The current code often reads as “procedural port glued into methods” instead.

## Rewrite principles

The rewrite should follow these rules.

1. Preserve external behavior.
   - Existing screen routing, action strings, timings, cursor/sign behavior, and
     audio semantics should stay the same unless explicitly reviewed.
2. Keep game-specific behavior local.
   - Credits secret rules, Alien Zoo Keeper board logic, stats easter egg
     handling, and weapon/perk text formatting should remain in their own
     screens.
3. Factor shared chrome below screen classes.
   - Do not solve this by merging everything into a giant generic screen class.
4. Prefer `msgspec.Struct` for structured internal carriers.
   - Use it for specs, frame/layout values, and other structured UI data instead
     of dataclasses.
5. Separate chrome from controls, and controls from content.
   - A screen should declare what generic controls it uses instead of embedding
     their internals directly into its frame loop.

## Proposed architecture

The recommended target architecture is a layered one:

1. shared chrome runtime
2. geometry/layout helpers
3. reusable control adapters
4. optional reusable content widgets
5. concrete screen bodies

### 1. Shared chrome runtime

Add a shared internal screen-chrome layer under `src/crimson/screens/`.

Suggested module shape:

- `src/crimson/screens/chrome/runtime.py`
- `src/crimson/screens/chrome/geometry.py`
- `src/crimson/screens/chrome/controls.py`
- `src/crimson/screens/chrome/widgets.py`

The core runtime should own the repeated shell:

- open/close bookkeeping
- timeline stepping
- close-transition handoff
- action dispatch state
- cursor pulse stepping
- audio update hook plus music policy evaluation where the screen needs it
- menu-ground / pause-background selection
- pause-background entity alpha policy
- fade/sign/cursor drawing
- sign lock / unlock / animation policy

It should not know the details of any specific panel body.

### 2. Structured specs and frame values with `msgspec.Struct`

Use `msgspec.Struct` for structured internal carriers.

Suggested internal types:

- `ChromeSpec`
  - static configuration for a screen shell
  - `BackdropPolicy`
  - `MusicPolicy`
  - `SignPolicy`
  - `ActionDispatchPolicy`
  - open/close SFX
  - fade-to-game action set
  - layout kind
- `ChromeState`
  - shared mutable runtime state for the shell
  - `_timeline_ms`, `_closing`, action-buffer fields, idle timer fields, and
    related state
- `ChromeFrame`
  - per-frame resolved values passed into body/control code
  - `resources`, `scale`, `interactive`, `mouse_pos`, panel origins, sign
    geometry, and timing
- `BackdropPolicy`
  - background source
  - whether pause background is allowed
  - entity alpha mode for pause-background-backed screens
- `MusicPolicy`
  - track selection
  - whether the track is refreshed while open
  - whether close transitions keep or stop music
- `SignPolicy`
  - static vs animated sign behavior
  - lock-on-fully-open behavior
  - unlock-on-actions behavior for quit or other exceptional flows
- `ActionDispatchPolicy`
  - how a close transition result is surfaced from the shell
- `SinglePanelLayout`
- `SplitPanelLayout`
- `BackLabelLayout`
- `ButtonLayout`
- dropdown/list layout structs currently duplicated in several files

`ChromeState` can be a mutable `msgspec.Struct` or a small class if that proves
clearer in implementation. The important point is that the framework should own
this state in one place instead of every screen spelling it out manually.

The policy structs matter because current screens already need them:

- `MenuView` chooses music dynamically and unlocks the sign before quitting
- `PauseMenuView` computes pause-background entity alpha during one close path
- `StatisticsMenuView` chooses a different music policy from `MenuView`
- `PanelMenuView` and siblings need a simpler static-sign policy

If those behaviors are not modeled explicitly in the chrome contract, the
abstraction will leak back into every adopter.

### 2.5. Action dispatch modes are part of the contract

The current screens do not all deliver actions the same way, so the shared
chrome must model this intentionally instead of assuming a single
`_pending_action` convention.

Recommended `ActionDispatchPolicy` modes:

- `pending_once`
  - close transition writes to a pending slot
  - `take_action()` drains it once
  - used by `MenuView`, `PauseMenuView`, and the current `PanelMenuView` shape
- `pending_rearm`
  - close transition writes to a pending slot
  - `take_action()` drains it and re-arms the shell to a fully-open state
  - used by hub screens that remain mounted while a child screen is shown, such
    as `StatisticsMenuView` and `_DatabaseBaseView`
- `direct_action`
  - close transition writes directly to the action slot consumed by
    `take_action()`
  - matches the current `HighScoresView` shape

The chrome runtime should implement these modes directly so that adopters do not
need to fork `take_action()` or the close-transition state machine just to get a
different delivery contract.

### 3. Pure geometry helpers

All repeated geometry should move into pure helpers driven by `ChromeSpec` and
screen width:

- widescreen Y shift
- small-screen scale rules
- sign placement and scaling
- single-panel animated origin
- split-panel animated origins
- standard content anchors for common panel shapes

Concrete screens should not recompute the “panel scale + slide + top-left”
sequence themselves.

Instead, each frame should hand the screen body already-resolved anchors such as:

- `frame.single_panel.top_left`
- `frame.split_panel.left_top_left`
- `frame.split_panel.right_top_left`
- `frame.sign`

### 4. Reusable control adapters

The rewrite should treat controls as composable adapters rather than baking them
into the view shell.

Suggested adapters:

- `MenuListController`
  - shared multi-entry navigation model for menu-style screens
  - owns list-level state and flow:
    - current selected index
    - focus timer
    - hovered index
    - Tab / Shift+Tab cycling
    - Enter activation
    - click-to-focus and click-to-activate behavior
    - optional idle timer support for menu-specific flows such as demo trigger
- `MenuEntryController`
  - atlas-backed entry behavior used by the main menu and the default Back label
  - owns hover timers, ready timers, alpha, hit-testing, and draw logic
- `BackButtonController`
  - `UiButtonState`-backed alternative used by network screens and other panels
  - owns `Escape` handling when appropriate
- `DropdownController`
  - shared open/select/close behavior for the small dropdown widgets already
    used in Play Game, Controls, and High Scores
- `ListViewportController`
  - visible window management for framed lists
  - row window math plus wheel or keyboard scroll
- `ListSelectionController`
  - hovered-row and selected-row semantics
  - supports screens that only need hover-driven selection as well as screens
    that keep a separate selected row
- `ScrollbarController`
  - track/thumb geometry and drag behavior
- `ListDetailWidget`
  - optional thin composition of the three smaller list primitives for screens
    that really use the whole stack

These adapters should update and draw against `ChromeFrame` plus a screen-local
state object.

The split between `MenuListController` and `MenuEntryController` is deliberate:

- `MenuEntryController` owns per-entry state and rendering
- `MenuListController` owns list-level selection/focus/activation flow

That matches the current duplication between `MenuView` and `PauseMenuView`,
which share both:

- per-entry hover/ready/draw behavior
- list-level `_selected_index` / `_focus_timer_ms` / `_hovered_index` state and
  the Tab / Enter / click activation loop

This split matters for the current database screens:

- `UnlockedWeaponsDatabaseView` only needs viewport math plus hover selection
- `UnlockedPerksDatabaseView` additionally needs keyboard focus, distinct
  selected vs hovered rows, and drag-scrollbar behavior

### 5. Concrete screen bodies

Concrete screen classes should remain normal Python classes that own their
screen-specific behavior and state.

Examples:

- `PlayGameMenuView` should own mode-entry construction, tooltip timers,
  player-count behavior, and config writes
- `OptionsMenuView` should own slider values and option application
- `ControlsMenuView` should own dropdown/rebind state
- `CreditsView` should own credit lines, scroll progression, and secret unlock
- `AlienZooKeeperView` should own the board state and puzzle rules

What changes is that they no longer own the generic shell.

## Proposed adapters for existing classes

The rewrite does not need to rename or remove the existing public view classes.

Recommended shape:

- `MenuView`
  - keep as the main menu class
  - rebuild on top of shared chrome plus `MenuListController` and
    `MenuEntryController`
- `PauseMenuView`
  - keep as a separate adopter class
  - migrate in the dedicated menu/pause phase with a pause-background-specific
    `BackdropPolicy`
  - reuse the same `MenuListController` with a pause-specific action map
- `PanelMenuView`
  - shrink into a thin adapter over shared chrome
  - default body is title/body text
  - default back control is one atlas-backed Back entry
- `StatisticsMenuView`
  - stop owning its own shell
  - use shared chrome directly with a simple single-panel spec
- `_DatabaseBaseView`
  - become the split-panel adapter over shared chrome
  - keep only database-specific hooks and widget composition
- `CreditsView`
  - adopt shared chrome directly
- `AlienZooKeeperView`
  - adopt shared chrome directly
- `HighScoresView`
  - not part of the first migration, but should target the same chrome in a
    follow-up

## Close hooks and side effects

The chrome runtime should support optional close hooks instead of forcing each
screen to override `_begin_close_transition(...)`.

Examples:

- save dirty config before closing
- clear or tear down network runtime when backing out of a network lobby
- trigger fade-to-game state changes before gameplay actions

This keeps side effects explicit without requiring every screen to fork the
close-transition state machine.

## Data/query helpers that should leave the UI layer

The rewrite should move these out of view modules into named helper modules:

- weapon database availability reconstruction
- perk database availability reconstruction
- any inline adapter/stub logic whose only purpose is to answer “what should
  this screen show?”

Suggested destination shape:

- `src/crimson/screens/panels/queries.py`, or
- domain-owned helpers under `src/crimson/weapons/` and `src/crimson/perks/`

The exact home is less important than keeping view files focused on view logic.

## Suggested implementation phases

### Phase 0: document and review

- land this doc
- tighten the proposed module layout and naming
- settle any scope questions before code motion starts

### Phase 1: shared chrome runtime and geometry helpers

- introduce the shared chrome modules
- add tests for lifecycle, timeline stepping, close transitions, sign/backdrop
  behavior, and geometry
- do not migrate all screens yet

### Phase 2: migrate `PanelMenuView` and its direct subclasses

- `PanelMenuView`
- `PlayGameMenuView`
- `OptionsMenuView`
- `ControlsMenuView`
- `ModsMenuView`
- `NetworkSessionPanelView`
- `NetworkLobbyPanelView`

### Phase 3: migrate standalone panel-like screens

- `StatisticsMenuView`
- `_DatabaseBaseView`
- `CreditsView`
- `AlienZooKeeperView`

### Phase 4: migrate `MenuView` and `PauseMenuView`

- `MenuView`
- `PauseMenuView`
- validate the menu-specific behaviors that the chrome contract must support:
  - menu music selection/refresh
  - idle-demo triggering
  - sign lock/unlock semantics
  - pause-background entity alpha behavior

### Phase 5: optional adjacent adopters

- `HighScoresView`
- later, evaluate whether quest/result screens should share the same shell or a
  sibling shell

## Test guardrails

Before refactoring, the current screen-focused baseline passes:

```bash
uv run pytest \
  tests/modes/test_menu_idle_demo.py \
  tests/screens/test_pause_menu_view.py \
  tests/screens/test_credits_view.py \
  tests/screens/test_stats_easter_egg.py \
  tests/perks/test_perk_database_view.py \
  tests/net/test_net_ui_flow.py \
  tests/net/test_lan_ui_flow.py \
  tests/modes/test_game_start_routes_smoke.py
```

That baseline should remain green through the migration.

The rewrite should add dedicated tests for:

- shared chrome lifecycle and `take_action()` handoff
- open/close SFX behavior
- fade-to-game actions
- menu-ground vs pause-background selection
- music policy selection and refresh behavior
- sign lock/unlock semantics
- pause-background entity alpha policy
- idle-demo trigger behavior for `MenuView`
- single-panel and split-panel geometry at `640` and `1024`
- menu-entry controller hover/ready/alpha behavior
- menu-list controller selection, focus, and activation behavior
- button-backed back control
- dropdown open/select/close behavior
- list viewport, selection, and scrollbar primitives
- dirty-config close hook behavior

## Questions to tighten in review

These are the main design questions worth resolving before code motion starts:

1. Should `HighScoresView` stay explicitly out of the first migration even if
   the new chrome makes it easy to adopt?
2. Where should weapon/perk database availability helpers live long term:
   panel-owned query helpers or domain-owned helpers?
3. Should `ChromeState` be a `msgspec.Struct` or a small imperative helper
   class with a `msgspec.Struct` only for immutable frame/spec values?

## Bottom line

The right abstraction boundary is not “make `PanelMenuView` more generic”.

The right abstraction boundary is:

- shared screen chrome below all panel-like screens
- pure geometry/layout helpers
- reusable control adapters
- small concrete screen bodies that keep only their own logic

That structure keeps the Python port behaviorally faithful while making the
screen code read like deliberate Python instead of a collection of decompile
shapes.
