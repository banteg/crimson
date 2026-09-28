#include "grim2d_cpp.h"

extern float grim_joystick_deadzone;
extern float grim_joystick_center_y;
extern IGrim2D_cpp *grim_interface_instance;

int grim_joystick_down_active(void)
{
    float deadzone = grim_joystick_deadzone;
    float center = grim_joystick_center_y;
    int position = grim_interface_instance->grim_get_joystick_y();
    return (float)position - center > deadzone;
}
