#include "grim2d_cpp.h"
#include "grim_texture.h"

bool IGrim2D_cpp::grim_load_texture(char *name, char *path)
{
    return grim_load_texture_internal(name, (unsigned short *)path);
}
