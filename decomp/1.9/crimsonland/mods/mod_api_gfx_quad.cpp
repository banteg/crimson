#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" unsigned char mod_api_gfx_batch_open;

void mod_api_cpp_t::mod_api_gfx_quad(float x, float y, float w, float h)
{
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_draw_quad(x, y, w, h);
    if (!mod_api_gfx_batch_open) {
        grim_interface_ptr->grim_end_batch();
    }
}
