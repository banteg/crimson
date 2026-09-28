#include <string.h>

#include "grim_texture.h"

bool GrimTexture::grim_texture_name_equals(char *name)
{
    if (this->name != 0 && name != 0) {
        return strcmp(this->name, name) == 0;
    }
    return false;
}
