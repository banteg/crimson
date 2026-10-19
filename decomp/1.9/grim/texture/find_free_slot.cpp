#include "grim_texture.h"

extern "C" int grim_find_free_texture_slot(void)
{
    for (int i = 0; i < GRIM_TEXTURE_SLOT_CAPACITY; ++i) {
        if (grim_texture_slots[i] == 0) {
            return i;
        }
    }
    return -1;
}
