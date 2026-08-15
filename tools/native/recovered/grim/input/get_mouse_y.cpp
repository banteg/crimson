#include "grim2d_cpp.h"

extern float grim_mouse_y_cached;

float IGrim2D_cpp::grim_get_mouse_y(void)
{
    return grim_mouse_y_cached;
}
