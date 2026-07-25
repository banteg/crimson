# `ui_element_render`

Native target: `crimsonland.exe` at `0x00446c40` (1,801 bytes).

Current reconstruction: **83.40%**, 515 candidate instructions versus 521
native instructions, with all 59 emitted references resolved.

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
The typed form preserves 515/521 instructions, 83.3977%, and `59/0/0`
references exactly.

The small residual is code-generation shape: VC6 keeps a temporary for the
seven-pixel Y coordinate in each offset-shadow submission and schedules
otherwise equivalent vertex-call arguments differently. Introducing an
artificial volatile or extra aggregate reproduces the missing instruction
count only by changing the native 0x20-byte frame and lowering the match, so
the plausible expression form is retained.
