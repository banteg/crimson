#include "grim_texture.h"

GrimTexture::~GrimTexture(void)
{
    if (texture != 0) {
        texture->Release();
    }
#if CL_BUILD >= 10900
    texture = 0;
#endif

    if (backup != 0) {
        backup->Release();
    }
#if CL_BUILD >= 10900
    backup = 0;
#endif

    if (name != 0) {
        delete[] name;
    }
#if CL_BUILD >= 10900
    name = 0;
#endif
}
