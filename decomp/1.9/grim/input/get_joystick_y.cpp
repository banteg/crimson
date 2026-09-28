#include "grim2d_cpp.h"
#include "grim_joystick_state.h"

int IGrim2D_cpp::grim_get_joystick_y(void)
{
    return grim_joystick_state.lY;
}
