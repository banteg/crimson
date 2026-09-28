#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" unsigned char input_any_key_pressed(void)
{
    int key = 2;
    unsigned char result;

    while (key < 0x17f) {
        result = grim_interface_ptr->grim_is_key_active(key);
        if (result) {
            return 1;
        }
        ++key;
    }

    return result;
}
