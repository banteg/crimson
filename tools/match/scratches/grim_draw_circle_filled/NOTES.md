# grim_draw_circle_filled

Emits a center vertex plus an inclusive perimeter loop into the dynamic vertex
buffer and draws the result as a triangle fan. The native segment count is
`int(radius * 0.125f + 12.0f)`.
