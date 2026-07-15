# `quest_failed_screen_update`

High-value recovery for the 1,261-byte quest-failure screen at `0x004107e0`.
The current scratch reconstructs the native screen flow and remains an honest
work in progress rather than an exact match.

## Recovered source shape

- clears the reflex-boost timer and conditionally starts Shortie Monk on entry;
- renders the gameplay world, UI elements, perk prompt, and reaper banner;
- preserves the native operand order for panel position (`pos_x + vertex.x`,
  `vertex.y + pos_y`), as proven by the four corresponding data references;
- loads the high-score table on phase `-1`, snapshots the rank, copies the game
  mode into the active record, and flushes stale input;
- selects all six retry messages, including the native `rewared` typo;
- renders high-score text input with the active record and one-based rank;
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

The native function has a 24-byte local frame and keeps the banner coordinates
in `esi`/`edi`; this natural reconstruction has a 32-byte frame because VC6
assigns separate slots to the panel, mutable text/button position, preserved
banner position, and text-input position. Scalar, copied-vector, scoped-lifetime,
and reuse variants either retained that delta or made register allocation and
instruction order worse. The residual is recorded here instead of using unions,
fake references, register hints, or other byte-shaping constructs.
