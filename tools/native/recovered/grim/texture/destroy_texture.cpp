#include "grim2d_cpp.h"
#include "grim_texture.h"

void IGrim2D_cpp::grim_destroy_texture(int handle)
{
    GrimTexture *texture = grim_texture_slots[handle];
    if (texture != 0) {
        delete texture;

        int last = grim_texture_slot_max_index;
        grim_texture_slots[handle] = 0;
        if (handle == last) {
            grim_texture_slot_max_index = last - 1;
        }
    }
}
