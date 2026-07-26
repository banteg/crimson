# grim_draw_quad_rotated_matrix

Emits the current colored and textured quad after transforming its four
center-relative corners by the cached 2x2 rotation matrix.

The matrix transform and the subsequent center translation remain distinct
source operations. That natural vector-operation shape reproduces the native
x87 spill schedule and parameter-slot reuse; combining them into one formula
changes code generation. The reconstruction matches all 236 instructions and
all 81 masked references without volatile locals or artificial dependencies.
