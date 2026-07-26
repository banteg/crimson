#include "grim2d_cpp.h"

extern float grim_joystick_deadzone;
extern float grim_joystick_center_x;
extern IGrim2D_cpp *grim_interface_instance;

int grim_joystick_right_active(void)
{
    float deadzone = grim_joystick_deadzone;
    float center = grim_joystick_center_x;
    int position = grim_interface_instance->grim_get_joystick_x();
    return (float)position - center > deadzone;
}
