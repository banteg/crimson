#include "grim2d_cpp.h"

extern float grim_mouse_x_cached;

float IGrim2D_cpp::grim_get_mouse_x(void)
{
    return grim_mouse_x_cached;
}
