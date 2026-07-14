#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

unsigned char mod_api_cpp_t::mod_api_gfx_free_texture(int texture_id)
{
    grim_interface_ptr->grim_destroy_texture(texture_id);
    return 1;
}
