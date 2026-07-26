#include "grim2d_cpp.h"

void IGrim2D_cpp::grim_draw_line_quad(
    float *p0, float *p1, float *half_vector)
{
    grim_draw_quad_points(
        p0[0] - half_vector[0],
        p0[1] - half_vector[1],
        p0[0] + half_vector[0],
        p0[1] + half_vector[1],
        p1[0] + half_vector[0],
        p1[1] + half_vector[1],
        p1[0] - half_vector[0],
        p1[1] - half_vector[1]);
}
