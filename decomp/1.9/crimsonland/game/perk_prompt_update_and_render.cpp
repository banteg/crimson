#include <math.h>

#include "crimsonland_gameplay.h"
#include "crimsonland_ui.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern int frame_dt_ms;
extern int perk_pending_count;
extern int perk_prompt_timer;
extern unsigned char config_ui_info_texts;
extern int config_key_pick_perk;
extern float perk_prompt_origin_y;
extern int config_screen_width;

char *input_key_name(int key_code);
void ui_element_render(ui_element_t *element);
}

extern "C" void perk_prompt_update_and_render(void)
{
    char text[128];

    if (demo_mode_active || config_game_mode == GAME_MODE_RUSH) {
        return;
    }

    if (perk_pending_count > 0 && game_state_id == GAME_STATE_GAMEPLAY) {
        perk_prompt_timer += frame_dt_ms;
        if (perk_prompt_timer > 200) {
            perk_prompt_timer = 200;
        }
    } else {
        perk_prompt_timer -= frame_dt_ms;
        if (perk_prompt_timer < 0) {
            perk_prompt_timer = 0;
        }
    }

    if (config_ui_info_texts && perk_prompt_timer > 0) {
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, perk_prompt_timer * 0.005f);
        crt_sprintf(
            text,
            "Press %s to pick a perk",
            input_key_name(config_key_pick_perk));
        grim_interface_ptr->grim_draw_text_small(
            (float)(config_screen_width
                    - grim_interface_ptr->grim_measure_text_width(text)
                    - 16),
            perk_prompt_origin_y + 8.0f,
            text);
    }

    float angle;
    ui_perk_prompt_element.active = 1;
    float cosine = (float)cos(
        angle = (1.0f - perk_prompt_timer * 0.005f) * -1.57079637f);
    ui_perk_prompt_element.rot_m00 = cosine;
    float sine = (float)sin(angle);
    ui_perk_prompt_element.rot_m01 = -sine;
    ui_perk_prompt_element.rot_m10 = sine;
    ui_perk_prompt_element.rot_m11 = cosine;
    ui_element_render(&ui_perk_prompt_element);
}
