#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern int ui_clock_table_texture;
extern int ui_clock_pointer_texture;
}

extern "C" void ui_draw_clock_gauge(
    int x,
    int y,
    int time_ms,
    float alpha)
{
    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_bind_texture(ui_clock_table_texture, 0);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(
        (float)x, (float)y, 32.0f, 32.0f);
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_set_config_var(0x15, 2u);
    grim_interface_ptr->grim_bind_texture(ui_clock_pointer_texture, 0);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_set_rotation(
        (time_ms / 1000) * 0.104719758f);
    grim_interface_ptr->grim_draw_quad(
        (float)x, (float)y, 32.0f, 32.0f);
    grim_interface_ptr->grim_end_batch();
}
