#include "grim2d_cpp.h"
#include "grim_joystick_state.h"

int IGrim2D_cpp::grim_get_joystick_pov(int index)
{
    return grim_joystick_state.rgdwPOV[index];
}
