# `ui_element_render`

Native target: `crimsonland.exe` at `0x00446c40` (1,801 bytes).

Current reconstruction: **91.17%**, exactly 521 candidate and native
instructions, a 145-instruction exact prefix, and all 65 emitted references
resolved.

Live Binary Ninja and IDA evidence recovers the game-owned UI element render
state machine: optional point-filter setup, keyboard-focus activation, panel
texture rendering, offset animation, counter/overlay texture rendering, and
the final update callback. The base panel uses three overlapping four-vertex
windows starting at element vertices 0, 2, and 4 when `quad_mode == 8`.

Both primary render modes retain the detail-gated seven-pixel shadow pass.
Mode zero transforms vertices through the element's 2x2 matrix; mode one adds
the timeline offset without rotation. The counter texture is intentionally
drawn once through the active render mode and a second time, transformed,
while the element is enabled and has an activation callback.

The two native alpha loops update four 0x1c-stride vertex colors. Focus maps
the 0..1000 counter to alpha 100..255, callback-less counters use alpha 200,
and the enabled overlay uses `255 - counter_timer / 2` for timer values below
256. These details and the repeated matrix/position calculations are retained
as observed rather than consolidated.

The two 0xe0-byte overlay banks at `ui_element_t+0x124` and `+0x20c` are now
canonical arrays of eight `ui_element_vertex_t` records rather than anonymous
byte padding. This function consumes the first four records of each bank.
Their 0x1c stride, color alpha at vertex offset `0x13`, submission base,
following texture handles, and the main-menu UV writes all independently
establish the layout. This type recovery preserves the current instruction,
fuzzy-byte, and reference results.

The shared `ui_menu_item_subtemplate_slot_t` layer view now also carries the
same recovered `z`, `rhw`, `color`, `u`, and `v` fields into Binary Ninja.
The map importer deliberately refreshes this authoritative record instead of
preserving an older complete-but-anonymous database definition, so the two
alpha cursors begin at named `color` fields rather than `field_0x10`.

Packed vertex colors now expose their little-endian BGRA bytes alongside the
existing dword alias, so all three source cursors begin at a named `color_a`
field rather than casting `color + 3`. The enabled-overlay loop's remaining
back-reference is expressed as one subtemplate block plus one vertex stride,
which is the native single-cursor lowering. A direct indexed two-array loop
compiled to 510 instructions and regressed to 82.25%, so it is not retained.
The typed post-increment form now follows the native increment-then-store
cursor schedule. Splitting each shadow position into the evidenced
`position + 7` intermediate followed by the render-offset additions preserves
the float-store order across the base window and both extra windows in
eight-vertex mode. The enabled-alpha loop likewise keeps the native overlay
bank write before the enabled-overlay bank write. Together these recover
521/521 instructions, a 145-instruction prefix, 91.1708%, and `65/0/0`
references.

The same union-free Binary Ninja presentation record now exposes all three
physical vertex banks, their texture handles, and the trailing render state
directly. Live analysis verifies its `0x318` size and converts the former layer
alias into `vertices`, `overlay_vertices`, `enabled_overlay_vertices`, and
`overlay_texture_handle` accesses. The callback-less alpha walk now has a
shifted `ui_element_vertex_alpha_cursor_t` presentation view: its live HLIL
uses the named `color_a` field and preserves the native 0x1c stride. One
`__offset` expression remains in the adjacent hover walk because native
preincrements that same interior cursor before storing through the prior
record; it is an optimizer cursor artifact rather than an anonymous structure
field.

The remaining residual is code-generation shape: VC6 schedules otherwise
equivalent vertex-call arguments and cursor registers differently.
Introducing artificial volatility or extra aggregates changes the native
frame and lowers the match, so the plausible expression form is retained.
