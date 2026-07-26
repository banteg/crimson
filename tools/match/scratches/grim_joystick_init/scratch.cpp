#include <windows.h>

#include "grim_joystick_input.h"

extern "C" const GrimGuid IID_IDirectInput8A;
extern "C" const GrimDataFormat c_dfDIJoystick2;
extern "C" long __stdcall DirectInput8Create(
    HINSTANCE instance,
    unsigned long version,
    const GrimGuid *iid,
    void **output,
    void *outer);

bool grim_joystick_init(HWND hwnd)
{
    if (hwnd == 0 && GetForegroundWindow() == 0) {
        GetDesktopWindow();
    }

    if (grim_dinput_joystick == 0) {
        HRESULT result = DirectInput8Create(
            GetModuleHandleA(0),
            0x800,
            &IID_IDirectInput8A,
            (void **)&grim_dinput_joystick,
            0);
        if (result < 0) {
            grim_dinput_joystick = 0;
            return false;
        }
    }

    if (grim_joystick_device == 0) {
        HRESULT result = grim_dinput_joystick->vtable->EnumDevices(
            grim_dinput_joystick,
            4,
            grim_joystick_enum_device,
            0,
            1);
        if (result < 0) {
            return false;
        }
        if (!grim_joystick_found) {
            return false;
        }

        result = grim_joystick_device->vtable->SetDataFormat(
            grim_joystick_device, &c_dfDIJoystick2);
        if (result < 0) {
            return false;
        }
        result = grim_joystick_device->vtable->SetCooperativeLevel(
            grim_joystick_device, hwnd, 5);
        if (result < 0) {
            return false;
        }
        result = grim_joystick_device->vtable->EnumObjects(
            grim_joystick_device, grim_joystick_configure_axis, hwnd, 0);
        if (result < 0) {
            return false;
        }

        if (grim_joystick_device != 0) {
            grim_joystick_device->vtable->Acquire(grim_joystick_device);
        }
    }

    grim_joystick_poll();
    return true;
}
