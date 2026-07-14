# mod_api_cl_enter_menu

Native target: `crimsonland.exe` at `0x40e690` (97 bytes).

The mod API accepts only the literal `"game_pause"`. On a match it marks byte
`0x09` (`parms.onPause`) when a plugin object exists, clears the UI transition
direction, and requests game state `5`. A null or different menu is ignored.
Literal-first `strcmp` preserves VC6's native inlined comparison order and
matches all 37 instructions and all 4 references exactly.
