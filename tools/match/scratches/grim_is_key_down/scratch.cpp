#include "grim2d_cpp.h"

extern unsigned char grim_keyboard_key_down(unsigned int key);

unsigned char IGrim2D_cpp::grim_is_key_down(unsigned int key)
{
    return grim_keyboard_key_down(key);
}
