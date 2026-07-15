# `ui_checkbox_update`

Native target: `crimsonland.exe` at `0x0043dc80` (622 bytes).

Live Binary Ninja shows the complete checkbox widget lifecycle: register and
draw keyboard focus, calculate label-aware hover bounds, toggle from Enter or
the primary pointer action, draw the selected checkbox texture, and render the
optional label with hover-dependent alpha.

The recovered C++ `bool` values reproduce the native byte-sized stack locals
and AL return for both this function and `ui_focus_update`. Keeping the hit-test
helpers as integer-returning functions while consuming their low byte, plus
expressing the texture choice as ordinary control flow, reproduces all 188
native instructions exactly. No inline assembly, volatile state, dummy
references, or dead expressions are used.
