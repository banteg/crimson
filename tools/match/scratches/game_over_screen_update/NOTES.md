# `game_over_screen_update`

Native target: `crimsonland.exe` at `0x0040ffc0` (1,998 bytes).

Live Binary Ninja evidence recovers the complete non-quest game-over flow:
function-local name-entry and button widgets, Shortie Monk entry audio, world and
UI rendering, top-100 rank detection, editable-name validation and submission,
score summary rendering, and Play Again / High scores / Main Menu transitions.

## Recovered source shape

- lazily constructs the name-submit button and name-input state before ordinary
  frame work, then constructs the three result buttons only on the result path;
- restores the result phase after returning from High scores and starts Shortie
  Monk only on the native game-over transition edge;
- renders the gameplay world, UI transition elements, perk prompt, reaper
  banner, editable name prompt, result row, and cursor in their native phases;
- copies the active record name into a 20-character editor for top-100 scores,
  rejects empty and all-space submissions, saves accepted names, and reloads
  the high-score table;
- preserves the native operand order for the panel X and Y pairs, as proven by
  all four corresponding data references;
- routes Play Again to ordinary or Typo gameplay, snapshots the complete return
  context for High scores, and restores Main Menu audio/focus state; and
- identifies the shared five-bit static guard, all five widget objects, and all
  five `atexit` destructor thunks with scoped object-symbol aliases.

The natural VC6 `msvc6.5 /O2 /GB` reconstruction has the native 24-byte local
frame and currently matches 76.96% of the 471 target instructions with
`177/0/4` audited references. The four residual reference mismatches are in the
aligned audio-action tail where equivalent source calls receive different live
registers; the source operands themselves name the proven native tracks.
`msvc6.5pp` falls to 71.00%, so there is no compiler override.

The remaining instruction delta is dominated by vector-temporary scheduling,
name-buffer register allocation, and phase-branch layout. It is recorded as an
honest work in progress rather than forced with register hints, fake aliases,
or dead expressions.
