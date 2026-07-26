#include "grim_texture.h"

extern "C" int grim_find_texture_by_name(char *name)
{
    for (int i = 0; i < grim_texture_slot_max_index + 1; ++i) {
        GrimTexture *texture = grim_texture_slots[i];
        if (texture != 0 && texture->grim_texture_name_equals(name)) {
            return i;
        }
    }
    return -1;
}
