# grim_draw_line

Builds a function-static endpoint delta, normalizes it through
`D3DXVec2Normalize`, applies the native two-step thickness transform, and
forwards the resulting vector to `grim_draw_line_quad`. The second component's
dependence on the already-scaled first component is preserved as observed; it
is not rewritten into a conventional perpendicular-vector formula.
