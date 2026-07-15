#include <math.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern unsigned char console_open_flag;
extern unsigned char ui_transition_direction;
extern int frame_dt_ms;
extern int ui_elements_timeline;
extern game_state_id_t game_state_pending;
extern unsigned char quit_requested;
extern ui_element_t ui_sign_crimson;

void terrain_generate_random(void);
void config_load_presets(int reset);
int ui_elements_max_timeline(void);
void ui_element_update(ui_element_t *element);
void ui_element_render(ui_element_t *element);
}

static inline void ui_element_set_rotation(
    ui_element_t *element,
    double radians)
{
    float cosine = (float)cos(radians);
    element->rot_m00 = cosine;
    float sine = (float)sin(radians);

    element->rot_m01 = -sine;
    element->rot_m10 = sine;
    element->rot_m11 = cosine;
}

extern "C" void ui_elements_update_and_render(void)
{
    grim_interface_ptr->grim_set_config_var(0x15, 2u);

    if (!console_open_flag) {
        if (ui_transition_direction) {
            ui_elements_timeline += frame_dt_ms;
        } else {
            ui_elements_timeline -= frame_dt_ms;
        }
    }

    if (ui_elements_timeline < 0) {
        ui_elements_timeline = 0;
        if (demo_mode_active && game_state_pending == GAME_STATE_MAIN_MENU) {
            terrain_generate_random();
        }
        game_state_set(game_state_pending);
        game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
    }

    if (ui_elements_timeline > ui_elements_max_timeline()) {
        if (game_state_id == GAME_STATE_MAIN_MENU && demo_mode_active) {
            demo_mode_active = 0;
            config_load_presets(0);
        }
        ui_sign_crimson.focus_disabled = 1;
        ui_element_set_rotation(&ui_sign_crimson, 0.0);
        ui_elements_timeline = ui_elements_max_timeline();
    }

    if (game_state_id == GAME_STATE_GAMEPLAY) {
        return;
    }

    ui_element_t **element = &ui_element_table[40];
    do {
        ui_element_update(*element);
        ui_element_render(*element);
        --element;
    } while ((int)element >= (int)ui_element_table);

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    if (game_state_id == GAME_STATE_QUIT_TRANSITION) {
        quit_requested = 1;
    }
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
}
