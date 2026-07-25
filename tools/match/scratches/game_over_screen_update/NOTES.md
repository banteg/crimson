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
- recovers the chained banner-position expression and the two inlined
  `Vector2::set` calls used to position the editable high-score rows;
- keeps the name-buffer pointer live across the complete entry phase and uses
  the native shared cursor-rendering tail for ranked and unranked scores;
- routes Play Again to ordinary or Typo gameplay, snapshots the complete return
  context for High scores, and restores Main Menu audio/focus state; and
- identifies the shared five-bit static guard, all five widget objects, and all
  five `atexit` destructor thunks with scoped object-symbol aliases.

The natural VC6 `msvc6.5 /O2 /GB` reconstruction has the native 24-byte local
frame and matches all 471 target instructions exactly, with all 215 audited
references aligned. No compiler override, register hint, fake alias, or dead
expression is required.

The banner expression now names the recovered UI element and vertex position
aggregates and remains exact at 471/471 instructions with 215 resolved
references.

The name editor's storage is now imported as the evidenced 32-byte character
array, and the compiler-generated zero-based scan variable at `0x0041030f` is
persisted as the integer `first_non_space`. Binary Ninja consequently renders
the validation loop as `game_over_name_input_buffer[first_non_space]` instead
of an untyped absolute base plus a `void *` offset. This presentation cleanup
does not change the exact matching source.
