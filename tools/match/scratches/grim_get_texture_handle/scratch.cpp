#include "grim2d_cpp.h"
#include "grim_texture.h"

int IGrim2D_cpp::grim_get_texture_handle(char *name)
{
    return grim_find_texture_by_name(name);
}
