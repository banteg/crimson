# `quest_failed_screen_update`

High-value recovery for the 1,261-byte quest-failure screen at `0x004107e0`.
The current scratch reconstructs the native screen flow and remains an honest
work in progress rather than an exact match.

## Recovered source shape

- clears the reflex-boost timer and conditionally starts Shortie Monk on entry;
- renders the gameplay world, UI elements, perk prompt, and reaper banner;
- recovers the native chained-vector anchor
  `position + vertex + (180, 40)`, including VC6's hidden first-addition
  temporary;
- loads the high-score table on phase `-1`, snapshots the rank, copies the game
  mode into the active record, and flushes stale input;
- selects all six retry messages, including the native `rewared` typo;
- renders high-score text input with the active record and one-based rank;
- advances the evolved layout cursor by 98 pixels for the button stack instead
  of incorrectly resetting it from the initial panel origin;
- lazily constructs the Play Again, Play Another, and Main Menu buttons;
- implements all three native transition/audio action paths; and
- always renders the cursor after the phase-gated body.

## Static-object evidence

The native constructor blocks initialize `quest_failed_play_again_button`
(`0x00482680`), `quest_failed_play_another_button` (`0x00482698`), and
`quest_failed_main_menu_button` (`0x004824f0`) under bits 1, 2, and 4 of
`quest_failed_screen_flags` (`0x004825d8`). Live Binary Ninja xrefs show their
`atexit` callbacks at `0x00410d10`, `0x00410d00`, and `0x00410cf0`.

The VC6 object relocation table proves the corresponding local symbols:
`$E2` is adjacent to `play_again_button`, `$E3` to `play_another_button`, and
`$E4` to `main_menu_button`. `REFERENCE_ALIASES` therefore scopes all three
button objects, the function-local guard, and the three empty destructor thunks
to those proven native identities.

## Remaining mismatch

The recovered cumulative `xy.y += 98.0f` update makes the panel slot naturally
available for the text-input vector, collapsing the candidate from a 32-byte
frame to the native 24-byte frame. Together with the chained-vector expression,
the function now has the native 292 instructions and all 151 references, at
99.32%.

Only two instructions differ: VC6 stores and reloads the hidden first-addition
Y temporary at `[esp+0x20]` in the target and `[esp+0x10]` in the candidate.
Equivalent declaration and initialization forms retained that stack-coloring
choice or worsened scheduling. The residual is recorded instead of forcing a
register or stack slot.
