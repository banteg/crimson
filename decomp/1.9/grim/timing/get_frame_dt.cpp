#include "grim2d_cpp.h"

extern float grim_frame_dt;

float IGrim2D_cpp::grim_get_frame_dt(void)
{
    if (grim_frame_dt > 0.1f) {
        return 0.1f;
    }
    return grim_frame_dt;
}
