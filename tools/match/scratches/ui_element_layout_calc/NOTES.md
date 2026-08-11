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

## Exact component publication

The remaining target sequence publishes the completed X component of the
minimum aggregate, begins the independent width calculation, and then
publishes Y. Two `sizeof(float)` `memcpy` operations express those observed
bitwise aggregate-component transfers without aliasing a `float` as an
integer, using volatility, or adding a dummy dependency. VC6 inlines them to
the target's existing integer moves while preserving the x87 temporary.

The resulting source matches all **288/288 bytes**, all **86/86
instructions**, and references **6/0/0**. Aggregate-before-width and
aggregate-after-width forms bracketed the native schedule by moving both
component stores together; direct scalar assignments changed the arithmetic
lifetime. `minimum-component-publication-mutations.json` records those
boundaries and the equivalent integer-bit form. No recovery or residual
override remains.
