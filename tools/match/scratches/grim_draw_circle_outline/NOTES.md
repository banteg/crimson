# grim_draw_circle_outline

## Plausibility pass (2026-09-27)

The guarded `do`/`while` with a hoisted `double` divisor became the same plain `for` loop as `grim_draw_circle_filled`; loop inversion supplies the guard and C2 hoists the conversion. The per-vertex `memcpy` became a struct assignment. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

Emits paired inner/outer vertices into the dynamic vertex buffer and draws the
ring as a triangle strip. The native outer radius is `radius + 2.0f` and the
inclusive loop uses `int(radius * 0.2f + 14.0f)` segments.
