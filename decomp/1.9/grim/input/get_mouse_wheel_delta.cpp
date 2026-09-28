#include "grim2d_cpp.h"

extern unsigned char grim_input_cached;
extern float grim_mouse_wheel_delta;
extern float grim_mouse_wheel_delta_cached;

float IGrim2D_cpp::grim_get_mouse_wheel_delta(void)
{
    if (grim_input_cached) {
        return grim_mouse_wheel_delta_cached;
    }
    return grim_mouse_wheel_delta;
}
