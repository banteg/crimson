# `ui_menu_item_update`

Native target: `crimsonland.exe` at `0x0043e5e0` (548 bytes).

Live Binary Ninja evidence identifies the complete menu-item lifecycle: static
idle and hover colors, keyboard focus decoration, text-width hover bounds,
label and underline rendering, keyboard or pointer activation, and the UI click
sound.

The recovered C++ shape reproduces all 153 native instructions and all 38
masked references. Two ordinary function-local static color objects explain
the shared guard byte and empty exit-time destructor callbacks. The
scratch-scoped `$E2`/`$E3` mappings disambiguate those compiler-local names by
their proven native callback addresses; they do not relax reference auditing.
No inline assembly, volatile state, dummy references, or dead expressions are
used.
