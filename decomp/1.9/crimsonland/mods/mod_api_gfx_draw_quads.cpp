#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" unsigned char mod_api_gfx_batch_open;

void mod_api_cpp_t::mod_api_gfx_draw_quads(
    mod_vertex2_t *vertices, int quad_count)
{
    float offset[2];

    if (!mod_api_gfx_batch_open) {
        grim_interface_ptr->grim_begin_batch();
    }
    offset[0] = 0.0f;
    offset[1] = 0.0f;
    grim_interface_ptr->grim_submit_vertices_offset(
        (float *)vertices, quad_count, offset);
    if (!mod_api_gfx_batch_open) {
        grim_interface_ptr->grim_end_batch();
    }
}
