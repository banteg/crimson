#include "grim2d_cpp.h"
#include "grim_texture.h"

bool IGrim2D_cpp::grim_create_texture(char *name, int width, int height)
{
    int handle = grim_find_free_texture_slot();
    if (handle < 0) {
        return false;
    }

    IDirect3DTexture8 *d3d_texture;
    if (grim_d3d_device->CreateTexture(
            width,
            height,
            1,
            D3DUSAGE_RENDERTARGET,
            grim_texture_format,
            D3DPOOL_DEFAULT,
            &d3d_texture) < 0) {
        grim_error_text = "D3D: Could not create a texture.";
        return false;
    }

    grim_texture_slots[handle] = new GrimTexture(name);
    grim_texture_slots[handle]->texture = d3d_texture;
    grim_texture_slots[handle]->owns_texture = 1;
    grim_texture_slots[handle]->width = width;
    grim_texture_slots[handle]->height = height;

    int last_handle = grim_texture_slot_max_index;
    if (handle > last_handle) {
        grim_texture_slot_max_index = handle;
    }
    return true;
}
