#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

void mod_api_cpp_t::mod_api_gfx_set_texture_filter(int filter)
{
    grim_interface_ptr->grim_set_config_var(0x15, (unsigned int)filter);
}
