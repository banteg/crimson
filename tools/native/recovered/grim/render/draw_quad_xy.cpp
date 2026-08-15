#include "grim2d_cpp.h"

void IGrim2D_cpp::grim_draw_quad_xy(float *xy, float w, float h)
{
    grim_draw_quad(xy[0], xy[1], w, h);
}
