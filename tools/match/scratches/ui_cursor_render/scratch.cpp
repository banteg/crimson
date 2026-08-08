#include <math.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern float ui_cursor_anim_timer;
extern float ui_cursor_pulse_phase;
extern int particles_texture;
extern int ui_cursor_texture;

void effect_select_texture(int effect_id);
}

extern "C" void ui_cursor_render(void)
{
    ui_cursor_anim_timer += frame_dt;
    ui_cursor_pulse_phase += frame_dt * 1.1f;

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 2u);
    grim_interface_ptr->grim_bind_texture(particles_texture, 0);
    effect_select_texture(13);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_begin_batch();

    float pulse = (float)sin(ui_cursor_pulse_phase);
    float pulse_power = (float)pow((double)pulse, 2.0);
    grim_interface_ptr->grim_set_color(
        1.0f,
        1.0f,
        1.0f,
        (pulse_power + 2.0f) * 0.32f);
    grim_interface_ptr->grim_draw_quad(
        ui_mouse_x - 28.0f, ui_mouse_y - 28.0f, 64.0f, 64.0f);
    grim_interface_ptr->grim_draw_quad(
        ui_mouse_x - 10.0f, ui_mouse_y - 18.0f, 64.0f, 64.0f);
    grim_interface_ptr->grim_draw_quad(
        ui_mouse_x - 18.0f, ui_mouse_y - 10.0f, 64.0f, 64.0f);
    grim_interface_ptr->grim_draw_quad(
        ui_mouse_x - 64.0f + 16.0f,
        ui_mouse_y - 64.0f + 16.0f,
        128.0f,
        128.0f);
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_bind_texture(ui_cursor_texture, 0);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(
        ui_mouse_x - 2.0f, ui_mouse_y - 2.0f, 32.0f, 32.0f);
    grim_interface_ptr->grim_end_batch();
}
