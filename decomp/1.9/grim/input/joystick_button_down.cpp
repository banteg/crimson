#include "grim_joystick_state.h"

unsigned char grim_joystick_button_down(unsigned int button)
{
    unsigned char result =
        grim_joystick_state.rgbButtons[(unsigned char)button];
    result >>= 7;
    return result;
}
