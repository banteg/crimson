#include "grim_texture.h"

GrimTexture::~GrimTexture(void)
{
    if (texture != 0) {
        texture->Release();
    }
    texture = 0;

    if (backup != 0) {
        backup->Release();
    }
    backup = 0;

    if (name != 0) {
        delete[] name;
    }
    name = 0;
}
