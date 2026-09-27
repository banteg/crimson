# grim_draw_circle_filled

## Plausibility pass (2026-09-27)

The per-vertex `memcpy(..., 0x1c)` became a struct assignment (`*grim_vertex_write_ptr = vertex`). VC6 lowers both to the same `rep movsd` copy. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

Emits a center vertex plus an inclusive perimeter loop into the dynamic vertex
buffer and draws the result as a triangle fan. The native segment count is
`int(radius * 0.125f + 12.0f)`.
