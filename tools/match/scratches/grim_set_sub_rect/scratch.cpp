#include "grim2d_cpp.h"

struct GrimUV {
    float u;
    float v;
};

extern GrimUV *grim_subrect_ptr_table[];
extern GrimUV grim_uv_u0[4];

void IGrim2D_cpp::grim_set_sub_rect(
    int atlas_size, int width, int height, int frame)
{
    float unit = 1.0f / (float)atlas_size;
    GrimUV uv = grim_subrect_ptr_table[atlas_size][frame];

    grim_uv_u0[0] = grim_uv_u0[1] = grim_uv_u0[2] = grim_uv_u0[3] = uv;
    grim_uv_u0[2].u = grim_uv_u0[1].u = uv.u + (float)width * unit;
    grim_uv_u0[2].v += (float)height * unit;
    grim_uv_u0[3].v += (float)height * unit;
}
