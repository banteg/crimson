#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

void mod_api_cpp_t::mod_api_gfx_set_blend_mode(int src, int dst)
{
    grim_interface_ptr->grim_set_config_var(0x14, (unsigned int)dst);
    grim_interface_ptr->grim_set_config_var(0x13, (unsigned int)src);
}
