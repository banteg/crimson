#include "grim2d_cpp.h"
#include "grim_texture.h"

extern int grim_bound_texture_handle;

void IGrim2D_cpp::grim_bind_texture(int handle, int stage)
{
    if (handle < 0) {
        return;
    }

    GrimTexture *slot = grim_texture_slots[handle];
    if (slot == 0 || slot->texture == 0) {
        return;
    }

    grim_d3d_device->SetTexture(stage, slot->texture);
    grim_bound_texture_handle = handle;
}
