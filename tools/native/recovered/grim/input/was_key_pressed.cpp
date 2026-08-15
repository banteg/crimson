#include "grim2d_cpp.h"

extern unsigned char grim_keyboard_key_down(unsigned int key);
extern float grim_key_repeat_timers[256];
extern unsigned char grim_key_repeat_first_press[256];
extern float grim_key_repeat_delay;

bool IGrim2D_cpp::grim_was_key_pressed(unsigned int key)
{
    if (grim_keyboard_key_down(key)) {
        if (grim_key_repeat_timers[(unsigned char)key] == 0.0f) {
            float delay = grim_key_repeat_delay;
            if (!grim_key_repeat_first_press[(unsigned char)key]) {
                delay *= 0.2f;
            }
            grim_key_repeat_timers[(unsigned char)key] = delay;
            grim_key_repeat_first_press[(unsigned char)key] = 0;
            return true;
        }
    } else {
        grim_key_repeat_timers[(unsigned char)key] = 0.0f;
        grim_key_repeat_first_press[(unsigned char)key] = 1;
    }
    return false;
}
