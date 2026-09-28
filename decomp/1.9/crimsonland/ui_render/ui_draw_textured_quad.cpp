#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" void ui_draw_textured_quad(
    int x, int y, int width, int height, int texture_id)
{
    grim_interface_ptr->grim_bind_texture(texture_id, 0);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_draw_quad(
        (float)x, (float)y, (float)width, (float)height);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x15, 2u);
}
