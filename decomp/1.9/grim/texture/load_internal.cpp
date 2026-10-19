#include "grim_texture.h"

bool grim_load_texture_internal(char *name, char *path)
{
#if CL_BUILD >= 10300
    int handle = grim_find_free_texture_slot();
    if (handle == -1) {
        grim_error_text = "All texture slots are used.";
        return false;
    }
#endif

    if (grim_find_texture_by_name(name) != -1) {
        grim_error_text = "D3D: Texture slot not free.";
        return false;
    }

    GrimTexture *texture;
    texture = new GrimTexture(name);
    if (!texture->grim_texture_load_file(path)) {
        grim_error_text = "D3D: Could not load a texture.";
        delete texture;
        return false;
    }

#if CL_BUILD < 10300
    int handle = grim_find_free_texture_slot();
#endif
    grim_texture_slots[handle] = texture;
    if (handle > grim_texture_slot_max_index) {
        grim_texture_slot_max_index = handle;
    }
    return true;
}
