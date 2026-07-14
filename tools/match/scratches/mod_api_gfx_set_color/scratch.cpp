#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

void mod_api_cpp_t::mod_api_gfx_set_color(float r, float g, float b, float a)
{
    grim_interface_ptr->grim_set_color(r, g, b, a);
}
