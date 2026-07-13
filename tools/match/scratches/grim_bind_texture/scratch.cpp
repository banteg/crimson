#include "grim_d3d8.h"
#include "grim2d_cpp.h"

struct GrimTextureSlot {
    unsigned long unknown_0;
    IDirect3DBaseTexture8 *texture;
};

extern IDirect3DDevice8 *grim_d3d_device;
extern GrimTextureSlot *grim_texture_slots[];
extern int grim_bound_texture_handle;

void IGrim2D_cpp::grim_bind_texture(int handle, int stage)
{
    if (handle < 0) {
        return;
    }

    GrimTextureSlot *slot = grim_texture_slots[handle];
    if (slot == 0 || slot->texture == 0) {
        return;
    }

    grim_d3d_device->SetTexture(stage, slot->texture);
    grim_bound_texture_handle = handle;
}
