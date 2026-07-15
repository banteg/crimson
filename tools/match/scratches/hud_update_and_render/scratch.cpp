#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct hud_vec2_t {
    float x;
    float y;

    hud_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct hud_color_t {
    float r;
    float g;
    float b;
    float a;

    hud_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

extern "C" {
extern int ui_elements_timeline;
extern ui_element_t ui_element_slot_28;
extern unsigned char gameplay_transition_latch;
extern int perk_doctor_target_creature_id;
extern float camera_offset_x;
extern float camera_offset_y;
extern unsigned char hud_show_health_panel;
extern unsigned char hud_show_weapon_panel;
extern unsigned char hud_show_xp_panel;
extern unsigned char hud_show_quest_panel;
extern unsigned char hud_show_timer_panel;

void ui_draw_progress_bar(float *xy, float width, float ratio, float *rgba);
void ui_render_hud(float transition_alpha);
}

extern "C" void hud_update_and_render(void)
{
    float transition_alpha = (float)ui_elements_timeline
        / (float)(ui_element_slot_28.timeline_end_ms
                  - ui_element_slot_28.timeline_start_ms);
    if (transition_alpha > 1.0f) {
        transition_alpha = 1.0f;
    }
    if (transition_alpha == 1.0f) {
        gameplay_transition_latch = 0;
    }

    int target_id = perk_doctor_target_creature_id;
    if (target_id != -1) {
        hud_vec2_t world_position(
            camera_offset_x + creature_pool[target_id].pos_x,
            camera_offset_y + creature_pool[target_id].pos_y);
        float ratio = creature_pool[target_id].health
            / creature_pool[target_id].max_health;
        if (ratio > 1.0f) {
            ratio = 1.0f;
        } else if (ratio < 0.0f) {
            ratio = 0.0f;
        }

        hud_color_t color(
            (1.0f - ratio) * 0.9f + 0.1f,
            ratio * 0.9f + 0.1f,
            0.2f,
            0.7f);
        hud_vec2_t position(
            world_position.x - 32.0f,
            world_position.y + 32.0f);
        ui_draw_progress_bar(
            (float *)&position, 64.0f, ratio, (float *)&color);
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    }

    if (config_game_mode == GAME_MODE_QUEST) {
        hud_show_health_panel = 1;
        hud_show_weapon_panel = 1;
        hud_show_xp_panel = 1;
        hud_show_quest_panel = 1;
        hud_show_timer_panel = 0;
    } else if (config_game_mode == GAME_MODE_SURVIVAL) {
        hud_show_health_panel = 1;
        hud_show_weapon_panel = 1;
        hud_show_xp_panel = 1;
        hud_show_quest_panel = 0;
        hud_show_timer_panel = 0;
    } else if (config_game_mode == GAME_MODE_RUSH) {
        hud_show_health_panel = 1;
        hud_show_weapon_panel = 0;
        hud_show_xp_panel = 0;
        hud_show_quest_panel = 0;
        hud_show_timer_panel = 1;
    } else if (config_game_mode == GAME_MODE_TYPO_SHOOTER) {
        hud_show_health_panel = 1;
        hud_show_weapon_panel = 0;
        hud_show_xp_panel = 1;
        hud_show_quest_panel = 0;
        hud_show_timer_panel = 1;
    } else {
        hud_show_health_panel = 0;
        hud_show_weapon_panel = 0;
        hud_show_xp_panel = 0;
        hud_show_quest_panel = 0;
        hud_show_timer_panel = 0;
    }

    if (!demo_mode_active) {
        ui_render_hud(transition_alpha);
    }
}
