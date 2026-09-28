#include <string.h>

#include "grim_texture.h"

GrimTexture::GrimTexture(char *source_name)
{
    name = new char[strlen(source_name) + 1];
    strcpy(name, source_name);
    texture = 0;
    owns_texture = 0;
    backup = 0;
}
