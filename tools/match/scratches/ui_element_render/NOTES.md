# `ui_element_render`

Native target: `crimsonland.exe` at `0x00446c40` (1,801 bytes).

Current reconstruction: **97.50%**, exactly 521 candidate and native
instructions, a 332-instruction exact prefix, and all 65 emitted references
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

The original 2003 mod SDK establishes the local vector house style: an empty
default constructor, a two-float constructor that assigns `x` and `y` in its
body, and direct construction at the declaration site. Applying that style to
the first transform-shadow position, the first offset-shadow position, and
the first offset-render position raises the result from **91.17%** to
**92.71%** and extends the exact prefix from 145 to 165 instructions without
changing instruction count or references. Applying it to the later repeated
counter position is byte-neutral; assigning a temporary into the existing
shadow variable or introducing separate block-local shadows regresses, so
those variants are not retained.

The exact `ui_draw_progress_bar`, `ui_render_loading`, and UI widget methods
also establish the complementary reuse style: construct the first vector,
then publish later coordinate pairs through an inline two-float `set` method.
Using that method for the six repeated transform-shadow, offset-shadow, and
offset-render positions raises the result from **92.71%** to **95.78%** and
extends the exact prefix from 165 to 258 instructions. Instruction count and
references remain 521/521 and `65/0/0`; the complete transformed-shadow path
now matches native.

The remaining residual is code-generation shape: VC6 schedules otherwise
equivalent vertex-call arguments and cursor registers differently.
Introducing artificial volatility or extra aggregates changes the native
frame and lowers the match, so the plausible expression form is retained.

## Recovery classification audit

The focused `--regions` run after the SDK-style recovery reported
**95.78%**, 521/521 instructions, prefix 258, and `65/0/0` references. Every
remaining localized region preserves the same call, vertex window,
offset/matrix input, constants, and control-flow edge; the differences are
argument-push, x87-store, and temporary-slot scheduling. The existing live
Binary Ninja recovery accounts for both render modes, all three base-panel
windows, both overlay banks, both alpha loops, focus activation, and the final
update callback.

The full compiler/flag sweep found no exact profile flip, with stock VC6.5
`/O2 /GB` remaining best. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## Recorded submit-scheduling sweeps

The earlier sweep anchored the first residual at
`0x00446e19..0x00446ec7`; the recovered `set` reuse style made that
transformed-shadow span exact. Before the shared ownership recovery below,
live Binary Ninja disassembly placed the first residual at `0x00446faf`, where
native and candidate computed the same offset-shadow position but chose
different temporary stack slots. The later
regions at `0x00446faf..0x00447079` and
`0x004470b9..0x004471d7` repeat that exact scheduler pattern for offset
submits.

Three exhaustive mutation sweeps record 74 additional variants with no
winner:

- `render-position-mutations.json` evaluates 24 panel/counter aggregate,
  record-type, assignment-order, and array spellings. Natural compiling
  forms are byte-neutral; reversing the panel component assignments loses
  17.284 weighted bytes. Five variants that changed only the first panel use
  to an array are rejected because later uses in that deliberately bounded
  span still require record members.
- `local-lifetime-mutations.json` evaluates all 31 combinations of moving
  vector declarations across render-state and mode scopes. All useful forms
  are byte-neutral except widening the transform-shadow lifetime, which loses
  20.741 weighted bytes.
- `quad-pointer-mutations.json` evaluates all 19 record-cast, named-position,
  base-plus-stride, and force-inline helper combinations. Every variant is
  byte-identical to baseline.

The retained SDK-style construction and setter recovery superseded that
earlier baseline and produced **95.78%**, 521/521 instructions, prefix 258,
and references `65/0/0` before the ownership recovery below.

## Shared offset-position ownership (2026-08-11)

Fresh native disassembly exposed a semantic boundary hidden by the equivalent
arithmetic. The offset-shadow calls publish their final position through the
same stack slot later used by the three plain offset panel submits. Native
also preserves the `position + 7` pair separately while adding the render
offset: the final vector occupies the first two-float slot, while the other
slot carries the intermediate y component. The retained source now names
those roles as `shadow_offset` and `render_pos` and reuses `render_pos` for
the following panel calls.

That two-vector dataflow raises the weighted result from 1725/1801
(**95.78%**) to 1756/1801 (**97.50%**), advances the exact prefix from 258 to
332 instructions, and keeps the exact 521/521 extent and `65/0/0` reference
audit. The retained source SHA-256 is
`a507817bc4b8056c8c3853a67b94e5c28ddb474dcc18769df1521954a3e44927`.
It makes all three offset-shadow submissions byte exact. A one-object
version shrinks the native 0x20-byte frame to 0x18 and regresses to 94.82%; a
two-object version with the opposite ownership keeps the frame but regresses
to 95.20% with a 250-instruction prefix. The retained boundary is therefore
not a score-only arithmetic rewrite.

Six current-source plans bound the nearby spelling-only alternatives:

- `current-counter-component-order-mutations.json` (SHA-256
  `532700c5bd61bebc499f82f3c208ecab4189c5fec4ced96e035e53b1c0cde28e`);
- `current-offset-shadow-opening-mutations.json` (SHA-256
  `0daa7530474095acfe644950358bc3752b4fc1f52bf0ec63be3dd1521aec1970`);
- `current-offset-shadow-lifetime-mutations.json` (SHA-256
  `2ac4d9a01193de009339a683a4020f3ea0ec84b6cf18d07f5dbf4191bf87a64d`);
- `current-panel-render-opening-mutations.json` (SHA-256
  `85a08fa9adadf358939eafb296b7af4ff9d3405bb741254b76c2c2080f5915e0`);
- `current-counter-position-style-mutations.json` (SHA-256
  `9c51c8efb70f3d4154961521db37d040ad9c883dca195e0eee3ab0a94f44587e`);
  and
- `current-counter-lifetime-mutations.json` (SHA-256
  `2da0c78d33df38b816f6fe588d10c65faec86fa3063102f63f46bf85e7058379`).

Component order, constructor/setter spelling, declaration widening, and the
natural counter record types are neutral or regressive on the retained
source. The remaining 45 weighted bytes are three commutative y-add operand
orders in the panel path plus the later counter position's stack-slot and
argument schedule; no semantic operation or reference remains missing.
