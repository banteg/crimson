# `ui_segmented_slider_update`

Native target: `crimsonland.exe` at `0x0043d9b0` (720 bytes).

Live Binary Ninja evidence identifies a focusable segmented slider with
keyboard and held-pointer input, min/max clamping, lazy texture lookup, and
separate empty/filled rendering passes.

The recovered C++ source reproduces all 213 native instructions and all 35
masked references. A block-scoped focus/hover vector and a copied draw position
explain the native 16-byte frame and long-lived Y coordinate. Each render pass
uses a zero-based counter plus an eight-pixel offset in a guarded `do` loop,
which reproduces the native bound test and update order without dead control
flow. The native EAX value is merely whatever the final Grim2D call leaves
behind, so the corrected function return is `void`.

No inline assembly, volatile state, dummy references, or dead expressions are
used.

## 1.9.8 (C2 9044) code-generation guard (2026-10-16)

1.9.8 stores `draw_position` at `esp+0x14` and the hover `position` at
`esp+0x1c`; the canonical source (hover position inside the nested block)
makes 9044 swap the two 8-byte slots. 9044 is exact whenever `position` is in
function scope (declared before or after `draw_position`), while 8966 is exact
only with `position` scoped to the block. Shared spellings tried: position
declared first or second in function scope, declared first and assigned with
`set` inside the block, `draw_position` declared without initializer and
assigned before/after the position inside the block, `draw_position` moved
before `ui_focus_update`, after `hovered`, after `slider_width`, after the
block, and before the loops. None is exact for both builds, so a guard moves
only the `position` declaration for `CL_BUILD == 10908`.
