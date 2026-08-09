#include <math.h>

#include "grim2d_cpp.h"
#include "grim_joystick_state.h"

class GrimInputProvider {
public:
    virtual void unused_0(void) = 0;
    virtual void unused_1(void) = 0;
    virtual void unused_2(void) = 0;
    virtual unsigned char is_active(int player, int action) = 0;
};

extern int grim_joystick_up_active(void);
extern int grim_joystick_down_active(void);
extern int grim_joystick_left_active(void);
extern int grim_joystick_right_active(void);
extern GrimInputProvider *grim_input_provider;

unsigned char IGrim2D_cpp::grim_is_key_active(int key)
{
    int button;
    int player;
    int action;
    GrimInputProvider *provider;

    if (key > 0xff) {
        if (key == 0x100) {
            return grim_is_mouse_button_down(0);
        }
        if (key == 0x101) {
            return grim_is_mouse_button_down(1);
        }
        if (key == 0x102) {
            return grim_is_mouse_button_down(2);
        }
        if (key == 0x103) {
            return grim_is_mouse_button_down(3);
        }
        if (key == 0x104) {
            return grim_is_mouse_button_down(4);
        }

        for (button = 1; button <= 12; ++button) {
            if (key == button + 0x11e) {
                return grim_is_joystick_button_down(button - 1);
            }
        }

        if (key == 0x131) {
            return grim_joystick_up_active();
        }
        if (key == 0x132) {
            return grim_joystick_down_active();
        }
        if (key == 0x133) {
            return grim_joystick_left_active();
        }
        if (key == 0x134) {
            return grim_joystick_right_active();
        }

        if (key == 0x13f) {
            goto axis_x_active;
        }
        if (key == 0x140) {
            goto axis_y_active;
        }
        if (key == 0x141) {
            goto axis_z_active;
        }
        if (key == 0x153) {
            goto axis_rx_active;
        }
        if (key == 0x154) {
            goto axis_ry_active;
        }
        if (key == 0x155) {
            return fabs((float)grim_joystick_state.lRz * 0.001f) > 0.5;
        }
        goto check_provider;
axis_ry_active:
        return fabs((float)grim_joystick_state.lRy * 0.001f) > 0.5;
axis_rx_active:
        return fabs((float)grim_joystick_state.lRx * 0.001f) > 0.5;
axis_z_active:
        return fabs((float)grim_joystick_state.lZ * 0.001f) > 0.5;
axis_y_active:
        return fabs((float)grim_joystick_state.lY * 0.001f) > 0.5;
axis_x_active:
        return fabs((float)grim_joystick_state.lX * 0.001f) > 0.5;
check_provider:

        provider = grim_input_provider;
        if (provider == 0) {
            return 0;
        }

        for (player = 0; player < 3; ++player) {
            for (action = 0; action < 5; ++action) {
                if (key == 0x16d + player * 5 + action) {
                    return provider->is_active(player, action);
                }
            }
        }
        return 0;
    }
    return grim_is_key_down(key);
}
