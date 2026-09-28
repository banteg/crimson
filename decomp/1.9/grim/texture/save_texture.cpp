#include "grim2d_cpp.h"
#include "grim_texture.h"

bool IGrim2D_cpp::grim_save_texture(int handle, char *path)
{
    GrimTexture *texture = grim_texture_slots[handle];
    if (texture == 0) {
        return false;
    }
    return D3DXSaveTextureToFileA(path, 2, texture->texture, 0) >= 0;
}
