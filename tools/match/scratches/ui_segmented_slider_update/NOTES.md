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
