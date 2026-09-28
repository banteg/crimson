#include "grim_joystick_input.h"

void grim_joystick_shutdown(void)
{
    if (grim_joystick_device != 0) {
        grim_joystick_device->vtable->Unacquire(grim_joystick_device);
        grim_joystick_device->vtable->Release(grim_joystick_device);
        grim_joystick_device = 0;
    }
    if (grim_dinput_joystick != 0) {
        grim_dinput_joystick->vtable->Release(grim_dinput_joystick);
        grim_dinput_joystick = 0;
    }
}
