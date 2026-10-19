#include <string.h>

#include "grim_texture.h"

bool GrimTexture::grim_texture_name_equals(char *name)
{
#if CL_BUILD < 10900
    return strcmp(this->name, name) == 0;
#else
    if (this->name != 0 && name != 0) {
        return strcmp(this->name, name) == 0;
    }
    return false;
#endif
}
