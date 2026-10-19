#include "grim2d_cpp.h"

struct GrimUV {
    float u;
    float v;
#if CL_BUILD < 10900
    GrimUV() {}
    GrimUV(float u_val, float v_val) { u = u_val; v = v_val; }
#endif
};

extern GrimUV grim_uv_u0[4];

void IGrim2D_cpp::grim_set_uv(float u0, float v0, float u1, float v1)
{
#if CL_BUILD < 10900
    grim_uv_u0[0] = GrimUV(u0, v0);
    grim_uv_u0[1] = GrimUV(u1, v0);
    grim_uv_u0[2] = GrimUV(u1, v1);
    grim_uv_u0[3] = GrimUV(u0, v1);
#else
    grim_uv_u0[0].u = u0;
    grim_uv_u0[0].v = v0;
    grim_uv_u0[1].u = u1;
    grim_uv_u0[1].v = v0;
    grim_uv_u0[2].u = u1;
    grim_uv_u0[2].v = v1;
    grim_uv_u0[3].u = u0;
    grim_uv_u0[3].v = v1;
#endif
}
