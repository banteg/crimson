#include "grim2d_cpp.h"

extern int grim_find_texture_by_name(char *name);

int IGrim2D_cpp::grim_get_texture_handle(char *name)
{
    return grim_find_texture_by_name(name);
}
