---
tags:
  - rewrite
  - ui
  - screens
  - panels
  - architecture
---

# Screens and panels architecture (rewrite)

This document describes the current front-end screen architecture in
`src/crimson/screens/` after the chrome/panel cutover.

## Intent

The screen layer now follows the repo’s typed-domain rules:

- parse and validate at boundaries
- keep typed objects inside the domain
- fail fast on impossible states
- migrate callers, then delete legacy APIs

The main goal of the cutover was to stop treating screen chrome as a pile of
stringly runtime switches and duplicated wrappers. The code now has one public
chrome seam, one private single-panel helper, and typed policy objects that
select behavior by shape instead of raw strings.

## Current structure

### Shared chrome runtime

`src/crimson/screens/chrome/runtime.py` owns the shared lifecycle shell:

- open/close bookkeeping
- timeline stepping
- close-transition dispatch
- menu-ground / pause-background selection
- sign/fade/cursor drawing hooks
- music/open-SFX/close-SFX behavior

`ChromeSpec` is the static contract for a screen shell. It is built from typed
policy objects:

- dispatch policies:
  - `PendingOnceDispatch`
  - `DirectActionDispatch`
- backdrop entity-alpha policies:
  - `OpaqueEntityAlpha`
  - `CloseTimelineEntityAlpha`
- open-SFX policies:
  - `NoOpenSfx`
  - `PlayOpenSfxOnOpen`
  - `PlayOpenSfxOnFullyOpen`

These are real domain objects, not mode strings. `ChromeSpec` and
`BackdropPolicy` validate their nested policy objects up front, and the runtime
branches exhaustively on concrete variants. There are no silent fallback paths.

Close transitions are single-shot at the runtime boundary:

- the first close request wins
- `closing` and `close_action` are set immediately
- `before_close(...)` hooks run once
- later close requests in the same or later frames are ignored

### Public screen seam

`src/crimson/screens/chrome/view.py` provides `ChromeScreenView`, the single
public base class for chrome-backed screens.

It exposes protected helpers for:

- chrome state access
- lifecycle forwarding
- update/draw helpers
- common panel-frame resolution
- child-resume handling via `resume_from_child()`

Concrete screens should use these helpers instead of reaching through
`self._chrome.chrome` directly.

### Private single-panel helper

`src/crimson/screens/panels/base.py` now contains `_PanelMenuScreenView`, a
private helper for the narrow “single panel with shared back control” shape.

It is intentionally not the public extension seam. Screens that match the
single-panel shell can reuse it; screens that do not should subclass
`ChromeScreenView` directly.

The back-control path now resolves at most one close action per frame instead
of independently firing Escape, Enter, and click handlers.

### Private quest helper

`src/crimson/screens/quest_views/base.py` contains `_QuestChromeViewBase`, a
quest-private thin wrapper on `ChromeScreenView`.

It is not a second public seam. It only centralizes the shared quest-family
outer shell:

- menu-ground / pause-background ownership
- fade drawing
- runtime-owned close dispatch
- optional sign / cursor drawing

Quest-specific layout, buttons, and result-state logic stay in the concrete
quest views.

### Geometry, controls, and widgets

The shared support modules remain split by responsibility:

- `chrome/geometry.py`: animation and panel/sign layout math
- `chrome/controls.py`: shared menu-list / menu-entry control logic
- `chrome/widgets.py`: shared dropdown and list-window helpers

Shared control code should stay generic. Engine-specific side effects that are
not broadly reusable belong in concrete screens.

## Current adopters

### `ChromeScreenView` direct adopters

- `MenuView`
- `PauseMenuView`
- `HighScoresView`
- `StatisticsMenuView`
- `CreditsView`
- `AlienZooKeeperView`
- `_DatabaseBaseView`
- `QuestsMenuView`
- `EndNoteView`
- `QuestFailedView`
- `QuestResultsView`

### `_PanelMenuScreenView` adopters

- `PlayGameMenuView`
- `OptionsMenuView`
- `ControlsMenuView`
- `ModsMenuView`
- `NetworkSessionPanelView`
- `NetworkLobbyPanelView`

This split is deliberate:

- `ChromeScreenView` is the reusable architectural seam
- `_PanelMenuScreenView` is only a convenience layer for one narrow family

## Behavioral rules captured by structure

### Menu idle timer stays local to `MenuView`

The queue-draining idle-timer behavior is a `MenuView` concern only. It is not
part of `MenuListController`, and shared menu infrastructure does not consume
input queue state just because a screen uses list navigation.

### Close hooks stay explicit

Views with close-time side effects keep them in `_before_close_transition(...)`,
for example:

- saving config in options/high-scores-related flows
- tearing down the network runtime when leaving the lobby

Those hooks rely on the runtime’s single-shot close semantics instead of
forking their own transition state machine.

### Child navigation stays stack-based

Child chrome screens use `back_to_previous`, and `GameLoopView` preserves the
parent on the front stack instead of reinterpreting action names later.

When a chrome-backed parent resurfaces, `resume_from_child()` is the explicit
hook for replaying any needed shell animation or state reset. The router no
longer special-cases one concrete screen class to get that behavior.

### Weapon-availability size comes from the weapon table

`src/crimson/weapons.py` is the canonical source of `WEAPON_COUNT_SIZE`.
Gameplay, fire, and availability logic all consume that shared constant, and
`weapon_refresh_available()` rebuilds the full live availability buffer instead
of only copying a smaller helper-sized prefix.

## Removed legacy surfaces

The cutover deleted the old duplicated and vestigial APIs:

- `_ChromePanelView` as a separate public wrapper
- `PanelMenuView` as a public abstraction
- `ChromeFrame`
- `ChromeRuntime.frame()`
- `PendingRearmDispatch`
- broad `screens.chrome` package re-exports as the primary import surface

Internal callers now import the concrete submodules they use.

## Verification focus

The current regression coverage should keep protecting these invariants:

- invalid chrome policy shapes fail during construction
- each dispatch/entity-alpha/open-SFX policy variant behaves explicitly
- close hooks are single-shot
- child-screen return flow stays stack-based and screen-local
- menu idle demo behavior remains specific to `MenuView`
- weapon availability tracks `WEAPON_COUNT_SIZE` and clears the full live buffer

This architecture is intentionally narrower than the earlier phased rewrite
plan. The migration is complete for the main chrome-backed screen families, and
future work should extend this shape only when a new screen truly shares the
same shell.
