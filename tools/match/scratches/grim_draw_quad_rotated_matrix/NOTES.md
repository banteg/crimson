# grim_draw_quad_rotated_matrix

## Plausibility pass (2026-09-27)

The `float points[5][2]` staging and its `*(GrimPoint *)` copies are retained for the same reason as `grim_draw_quad`: point-struct arrays align the frame, and per-field copies change the allocation (42.62%). See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md).

Emits the current colored and textured quad after transforming its four
center-relative corners by the cached 2x2 rotation matrix.

The matrix transform and the subsequent center translation remain distinct
source operations. That natural vector-operation shape reproduces the native
x87 spill schedule and parameter-slot reuse; combining them into one formula
changes code generation. The reconstruction matches all 236 instructions and
all 81 masked references without volatile locals or artificial dependencies.
