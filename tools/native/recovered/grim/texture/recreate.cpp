#include "grim2d_cpp.h"
#include "grim_texture.h"

bool IGrim2D_cpp::grim_recreate_texture(int handle)
{
    if (grim_texture_slots[handle] == 0) {
        return false;
    }

    IDirect3DTexture8 *replacement;
    if (D3DXCreateTexture(
            grim_d3d_device,
            grim_texture_slots[handle]->width,
            grim_texture_slots[handle]->height,
            1,
            0,
            grim_preferred_texture_format,
            D3DPOOL_MANAGED,
            &replacement) < 0) {
        return false;
    }

    if (d3dx_copy_texture_filtered(
            replacement,
            grim_texture_slots[handle]->texture,
            0,
            0,
            0x10,
            1.0f) < 0) {
        replacement->Release();
        return false;
    }

    grim_texture_slots[handle]->texture->Release();
    grim_texture_slots[handle]->texture = replacement;
    return true;
}
