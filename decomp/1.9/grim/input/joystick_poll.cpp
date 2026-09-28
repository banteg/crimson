#include "grim_joystick_input.h"

#define DIERR_INPUTLOST 0x8007001eL

bool grim_joystick_poll(void)
{
    if (grim_dinput_joystick != 0 && grim_joystick_device != 0) {
        long result =
            grim_joystick_device->vtable->Poll(grim_joystick_device);
        if (result < 0) {
            result = grim_joystick_device->vtable->Acquire(grim_joystick_device);
            while (result == DIERR_INPUTLOST) {
                result =
                    grim_joystick_device->vtable->Acquire(grim_joystick_device);
            }
            return 0;
        }
        result = grim_joystick_device->vtable->GetDeviceState(
            grim_joystick_device,
            sizeof(GrimJoystickState),
            &grim_joystick_state);
        if (result < 0) {
            return 0;
        }
        return 1;
    }
    return 0;
}
