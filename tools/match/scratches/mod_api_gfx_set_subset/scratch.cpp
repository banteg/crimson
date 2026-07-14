#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

void mod_api_cpp_t::mod_api_gfx_set_subset(float x1, float y1, float x2, float y2)
{
    grim_interface_ptr->grim_set_uv(x1, y1, x2, y2);
}
