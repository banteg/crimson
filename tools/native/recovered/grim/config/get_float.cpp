#include "grim2d_cpp.h"
#include "grim_joystick_state.h"

float IGrim2D_cpp::grim_get_config_float(int id)
{
    if (id > 0xff) {
        if (id == 0x13f) {
            return (float)grim_joystick_state.lX * 0.001f;
        }
        if (id == 0x140) {
            return (float)grim_joystick_state.lY * 0.001f;
        }
        if (id == 0x141) {
            return (float)grim_joystick_state.lZ * 0.001f;
        }
        if (id == 0x153) {
            return (float)grim_joystick_state.lRx * 0.001f;
        }
        if (id == 0x154) {
            return (float)grim_joystick_state.lRy * 0.001f;
        }
        if (id == 0x155) {
            return (float)grim_joystick_state.lRz * 0.001f;
        }
        if (id == 0x15f) {
            return grim_get_mouse_dx();
        }
        if (id == 0x160) {
            return grim_get_mouse_dy();
        }

        int index = 0;
        for (int code = 0x168; code < 0x16b; ++index, ++code) {
            if (id == code - 5) {
                return grim_get_mouse_dx_indexed(index);
            }
            if (id == code) {
                return grim_get_mouse_dy_indexed(index);
            }
        }
    }
    return 0.0f;
}
