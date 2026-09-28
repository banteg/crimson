#include "grim2d_cpp.h"

extern unsigned char grim_joystick_button_down(unsigned int button);

unsigned char IGrim2D_cpp::grim_is_joystick_button_down(int button)
{
    return grim_joystick_button_down(button);
}
