#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

void mod_api_cpp_t::mod_api_gfx_set_texture(int texture_id)
{
    grim_interface_ptr->grim_bind_texture(texture_id, 0);
}
