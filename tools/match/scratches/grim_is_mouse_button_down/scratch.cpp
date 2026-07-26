#include "grim2d_cpp.h"

extern bool grim_input_cached;
extern bool grim_mouse_button_cache[];
extern unsigned char grim_mouse_button_down(int button);

unsigned char IGrim2D_cpp::grim_is_mouse_button_down(int button)
{
    if (grim_input_cached) {
        return grim_mouse_button_cache[button];
    }
    return grim_mouse_button_down(button);
}
