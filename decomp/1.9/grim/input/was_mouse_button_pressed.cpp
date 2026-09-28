#include "grim2d_cpp.h"

extern unsigned char grim_input_cached;
extern unsigned char grim_mouse_button_cache[16];
extern unsigned char grim_mouse_button_latch[16];

bool IGrim2D_cpp::grim_was_mouse_button_pressed(int button)
{
    bool pressed;
    if (grim_input_cached) {
        pressed = grim_mouse_button_cache[button] &&
            grim_mouse_button_latch[button];
        grim_mouse_button_latch[button] = !grim_mouse_button_cache[button];
    } else {
        pressed = grim_is_mouse_button_down(button) &&
            grim_mouse_button_latch[button];
        grim_mouse_button_latch[button] = !grim_is_mouse_button_down(button);
    }
    return pressed;
}
