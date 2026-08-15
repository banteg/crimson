#include "grim_joystick_input.h"

int __stdcall grim_joystick_enum_device(
    const GrimDeviceInstance *instance, void *)
{
    long result = grim_dinput_joystick->vtable->CreateDevice(
        grim_dinput_joystick,
        &instance->guid_instance,
        &grim_joystick_device,
        0);
    if (result < 0) {
        return 1;
    }
    grim_joystick_found = true;
    return 0;
}
