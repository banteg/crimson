# `ui_element_layout_calc`

Native target: `crimsonland.exe` at `0x0044fb50` (288 bytes).

The routine skips dedicated element slots 26 and 27. For every other element
it translates both hover bounds, derives a tightened hit box from vertices zero
and two, and optionally swaps U coordinates in vertex pairs. The leading edge
uses 54% and 28% insets; the trailing edge uses 5% and 10% insets.

The recovered 28-byte vertex layout is `x, y, z, rhw, color, u, v`. Eight
vertices fill the element payload and `vertex_count` follows at `+0x120`.
`direction_flag` is at `+0x314`.

## Publication ownership

The native maximum-bound aggregate publishes X, loads `direction_flag`, then
finishes the pending Y publication. Naming the authoritative aggregate field
as the assignment destination reproduces that schedule:

```cpp
*(ui_layout_vec2_t *)&element->hover_max = position + vertex_2;
```

This is the same explicit aggregate-field ownership used by the exact adjacent
UI initialization helpers. It removes one of the two residual scheduler swaps
without affecting the already-exact vector arithmetic, loop, or references.

The retained result is **98.84%**: 86/86 instructions, 284.6512/288 weighted
bytes, prefix 32, and references `6/0/0`.

## Remaining residual

One instruction-order difference remains in the minimum-bound publication.
Native copies the completed X component to `hover_min.x` before storing the
pending Y component to its aggregate temporary; VC6 emits that X copy four
instructions later. The calculations, stores, constants, and references are
otherwise identical.

Bounded tests of native POD destinations, assignment-result ownership, comma
expressions, inline copy helpers, and explicit aggregate declaration orders
were neutral or worse. No alias trick, volatile state, dummy operation, or
register forcing is retained. The honest classification remains
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
