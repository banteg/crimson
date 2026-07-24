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

The point-and-click movement gate now uses the shared `cvar_float_t::value`
field. The matching map and live Binary Ninja database carry the same cvar
pointer type, replacing the former provisional byte-pointer-plus-`0x0c`
access without changing code generation.

Key rebinding waits for all input to be released, accepts keyboard, mouse,
joystick, and raw-input codes, and uses a separate analog-axis capture path
for the four axis rows. That path records absolute peaks for Grim IDs
`0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, and `0x155`, then commits the
first peak above `0.5`. Escape cancels either capture path and releases the UI
input lock.

The native function inlines the complete `input_key_name` policy three times:
once inside the 13-row player-binding loop, once for Level Up, and once for
Reload. The scratch shares that policy through
`tools/match/include/input_key_name_impl.h`; defining
`CONTROLS_INLINE_KEY_NAME` gives VC6 the same force-inlined source body while
the standalone scratch continues to compile it as `input_key_name`.

Current MSVC 6.5 `/O2 /GB` result: **50.80%**, with 4 exact prefix
instructions, 5,421 native instructions versus 4,488 candidate instructions,
and reference audit **863 resolved / 2 unresolved / 34 mismatched**. Both
functions use the native `0x74`-byte frame. The remaining gap is dominated by
register allocation across the enormous inlined key-label bodies and by the
recovered row-render helpers versus the native repeated lowering. All
observed widgets, labels, scheme branches, runtime binding copies, row
updates, capture rules, and dropdown writes are present; no fake dependency,
padding, volatile coercion, or inline assembly is used.
