#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" unsigned char mod_api_gfx_batch_open;

void mod_api_cpp_t::mod_api_gfx_begin(void)
{
    grim_interface_ptr->grim_begin_batch();
    mod_api_gfx_batch_open = 1;
}
