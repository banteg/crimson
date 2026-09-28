#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern float ui_aim_enhancement_anim_timer;
extern float ui_aim_enhancement_pulse_phase;
extern int particles_texture;
extern int ui_aim_texture;
extern cvar_float_t *cv_aimEnhancementFade;

void effect_select_texture(int effect_id);
}

extern "C" void ui_render_aim_enhancement(float *xy)
{
    ui_aim_enhancement_anim_timer += frame_dt;
    ui_aim_enhancement_pulse_phase += frame_dt * 0.6f;

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 2u);
    grim_interface_ptr->grim_bind_texture(particles_texture, 0);
    effect_select_texture(13);

    if (cv_aimEnhancementFade->value > 1.0f) {
        cv_aimEnhancementFade->value = 1.0f;
    }
    if (cv_aimEnhancementFade->value < 0.0f) {
        cv_aimEnhancementFade->value = 0.0f;
    }

    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, cv_aimEnhancementFade->value);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(
        xy[0] - 32.0f, xy[1] - 32.0f, 64.0f, 64.0f);
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_bind_texture(ui_aim_texture, 0);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, cv_aimEnhancementFade->value);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(
        xy[0] - 10.0f, xy[1] - 10.0f, 20.0f, 20.0f);
    grim_interface_ptr->grim_end_batch();
}
