#include "grim2d_cpp.h"

struct GrimUV {
    float u;
    float v;
};

extern GrimUV grim_uv_u0[4];

void IGrim2D_cpp::grim_set_uv_point(int index, float u, float v)
{
    grim_uv_u0[index].u = u;
    grim_uv_u0[index].v = v;
}
