# UI and menus

**Status:** Draft

This page groups UI element logic, menu loops, and transition helpers.

## UI element timeline (ui_elements_update_and_render / FUN_0041a530)

Responsibilities:

- Updates the global transition timeline `ui_elements_timeline` (`DAT_00487248`) using `DAT_00480844`.
  Direction is controlled by `ui_transition_direction` (`DAT_0048724c`) (0 = countdown, nonzero = count up).
- When the timeline goes below zero, it calls `FUN_004461c0` with `game_state_pending` (`DAT_00487274`) to
  switch state and then sets `game_state_pending` (`DAT_00487274`) = `0x19` (idle).
- Clamps the timeline to the maximum active element value
  (`ui_elements_max_timeline`).
- Iterates the UI element table `DAT_0048f208`..`DAT_0048f168`, calling
  `FUN_00446900` and `ui_element_render` for each entry.

Helpers:

- `ui_elements_reset_state` (`FUN_00446170`) clears element active flags and
  hover timers.
- `ui_elements_max_timeline` (`FUN_00446190`) returns the max timeline value
  among active elements.

## Menu UI loop (perk_selection_screen_update)

A common menu loop that:

1) Calls the gameplay render pass (`FUN_00405960`).
2) Runs `ui_elements_update_and_render`.
3) Draws menu content and buttons (`ui_button_update`).

## UI element render (FUN_00446c40)

`ui_element_render` updates focus/click handling and draws a UI element's quads,
colors, and textures. See [UI elements](../ui-elements.md) for struct details.

## Button helpers

High-confidence button helpers are tracked in
[Detangling notes](../detangling.md) under UI button helpers.
