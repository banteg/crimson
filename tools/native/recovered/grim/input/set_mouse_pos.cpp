#include "grim2d_cpp.h"

extern float grim_mouse_x;
extern float grim_mouse_y;
extern float grim_mouse_x_cached;
extern float grim_mouse_y_cached;

void IGrim2D_cpp::grim_set_mouse_pos(float x, float y)
{
    grim_mouse_x = x;
    grim_mouse_y = y;
    grim_mouse_x_cached = x;
    grim_mouse_y_cached = y;
}
