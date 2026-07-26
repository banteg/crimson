# `controls_menu_update`

Native target: `crimsonland.exe` at `0x00448cd0` (21,289 bytes).

Live Binary Ninja disassembly and the Ghidra export recover the complete
controls-screen callback. It constructs the two buttons, three dropdowns,
direction-arrow checkbox, and 15 rebind rows; builds the configure-for,
aiming, and movement label arrays; renders both panels; and updates the three
dropdowns without losing their mutually exclusive open-state policy.

The callback copies two configured players' 13 input bindings into the live
`player_state_t::input` blocks every frame. Native code advances the config
cursor by `0x40` bytes and the player cursor by `0x360` bytes, while swapping
the stored X/Y axis order into the runtime field order. The right panel then
selects action rows from the active aim and movement schemes: keyboard torso
aim, dual-axis aim, relative/static/digital movement, point-and-click
movement, fire, and Player 1's level-up/reload bindings.

The persisted side of that copy is now a recovered
`player_input_config_t` record rather than a 64-dword array plus negative
indices. Its 13 named bindings, Y/X analog-axis storage order, and three-dword
tail account for the native 0x40-byte row stride; the destination remains the
distinct X/Y-ordered `player_input_t`.

The native loop initially materializes `config_p1_move_forward + 0x30`, the
`axis_move_x` field of the first persisted row, before incrementing the cursor
and reading the preceding row through negative displacements. Binary Ninja
therefore records the instruction-defined value at `0x004492a1` honestly as
an `int *` named `binding_axis_move_x_cursor`, rather than mis-typing that
interior cursor as the owning `crimson_cfg_t *`.

The point-and-click movement gate now uses the shared `cvar_float_t::value`
field. The matching map and live Binary Ninja database carry the same cvar
pointer type, replacing the former provisional byte-pointer-plus-`0x0c`
access without changing code generation.

Live Binary Ninja also shows that widget construction uses a 15-entry
countdown/pointer walk, followed by a separate pointer reset walk. Keeping
those cursors distinct from the 13-row key-label index restores the native
local lifetimes. The configured-binding lookup now advances its own index
alongside the row index instead of recomputing their sum, and the right-panel
base is constructed before the two-player runtime copy as in the native
schedule. The active rebinding row displays the native `"???"` placeholder.

Key rebinding waits for all input to be released, accepts keyboard, mouse,
joystick, and raw-input codes, and uses a separate analog-axis capture path
for the four axis rows. That path records absolute peaks for Grim IDs
`0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, and `0x155`, then commits the
first peak above `0.5`. Escape cancels either capture path and releases the UI
input lock.

The native function inlines the complete `input_key_name` policy four times:
once inside the 13-row player-binding loop, once for the generic configured
binding at row 13, once for Level Up, and once for Reload. Live Binary Ninja
places the extra body after the loop at `0x0044a2c2`, assigns its label at
`0x0044b02d`, and only then enters the Level Up body at `0x0044b045`. The
scratch shares that policy through
`tools/match/include/input_key_name_impl.h`; defining
`CONTROLS_INLINE_KEY_NAME` gives VC6 the same force-inlined source body while
the standalone scratch continues to compile it as `input_key_name`.

The remaining tail now follows the native dataflow rather than helper-level
equivalences: rebind capture writes the selected regular, Level Up, or Reload
configuration field directly; the analog peak scan walks seven contiguous
float slots with a pointer, mapping the first six and routing the cleared
seventh slot through the native switch default; dropdown selection returns the
selected index; and list enable flags are reset and then cleared in native
open-list order. The two capture prompts share one base Y value, as in the
native branch join.

Current MSVC 6.5 `/O2 /GB /W3 /GR-` result: **73.85%**, with a fuzzy gap of
5,567.95 bytes, 4 exact prefix instructions, 5,421 native instructions versus
5,388 candidate instructions, and reference audit **1,448 resolved /
4 unresolved / 17 mismatched**. This improves the prior **64.72%** result
(7,511.49-byte gap, 4,493 candidate instructions, and 1,121 / 3 / 33
references). Both functions retain the native `0x74`-byte frame. The remaining
gap is dominated by register allocation inside the four enormous equivalent
inlined key-label bodies and early UI/x87 lowering. All observed widgets,
labels, scheme branches, runtime binding copies, row updates, capture rules,
and dropdown writes are present; no fake dependency, padding, volatile
coercion, or inline assembly is used.
