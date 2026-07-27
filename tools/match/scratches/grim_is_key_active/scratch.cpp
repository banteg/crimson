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
    int base;
    int action;
    int mapped;
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
            return fabs((float)grim_joystick_state.lX * 0.001f) > 0.5;
        }
        if (key == 0x140) {
            return fabs((float)grim_joystick_state.lY * 0.001f) > 0.5;
        }
        if (key == 0x141) {
            return fabs((float)grim_joystick_state.lZ * 0.001f) > 0.5;
        }
        if (key == 0x153) {
            return fabs((float)grim_joystick_state.lRx * 0.001f) > 0.5;
        }
        if (key == 0x154) {
            return fabs((float)grim_joystick_state.lRy * 0.001f) > 0.5;
        }
        if (key == 0x155) {
            return fabs((float)grim_joystick_state.lRz * 0.001f) > 0.5;
        }

        provider = grim_input_provider;
        if (provider == 0) {
            return 0;
        }

        player = 0;
        base = 0x16d;
        while (base < 0x17c) {
            int mapped_end = base + 5;
            for (action = 0, mapped = base;
                 mapped < mapped_end;
                 ++action, ++mapped) {
                if (key == mapped) {
                    return provider->is_active(player, action);
                }
            }
            base = mapped;
            ++player;
        }
        return 0;
    }
    return grim_is_key_down(key);
}
