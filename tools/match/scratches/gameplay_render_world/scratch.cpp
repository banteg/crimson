#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern int ui_elements_timeline;
extern ui_element_t ui_element_slot_28;
extern float ui_transition_alpha;
extern int config_player_count;
extern int survival_reward_weapon_guard_id;
extern unsigned char gameplay_transition_latch;
extern unsigned char ui_transition_direction;
extern game_state_id_t game_state_pending;

void fx_queue_render(void);
void player_render_overlays(void);
void creature_render_all(void);
void projectile_render(float transition_alpha);
void bonus_render(void);
}

static inline float ui_timeline_fraction(void)
{
    return (float)ui_elements_timeline
        / (float)(ui_element_slot_28.timeline_end_ms
                  - ui_element_slot_28.timeline_start_ms);
}

extern "C" void gameplay_render_world(void)
{
    ui_transition_alpha = ui_timeline_fraction();

    if (quest_unlock_index_full < 40) {
        if (player_state_table[0].weapon_id == 0x1d) {
            weapon_assign_player(0, 1);
        }
        if (player_state_table[1].weapon_id == 0x1d) {
            weapon_assign_player(1, 1);
        }
    }

    for (int player_index = 0; player_index < 2; ++player_index) {
        if (player_state_table[player_index].weapon_id == 0x19
            && survival_reward_weapon_guard_id != 0x19) {
            weapon_assign_player(player_index, 1);
        }
        if (player_state_table[player_index].weapon_id == 0x18
            && survival_reward_weapon_guard_id != 0x18) {
            weapon_assign_player(player_index, 1);
        }
    }

    if (!gameplay_transition_latch) {
        if (game_state_id == GAME_STATE_GAMEPLAY
            || game_state_id == GAME_STATE_PERK_SELECTION
            || ((game_state_id == GAME_STATE_QUEST_RESULTS
                 || game_state_id == GAME_STATE_QUEST_FAILED
                 || game_state_id == GAME_STATE_GAME_OVER)
                && ui_transition_direction)
            || game_state_pending == GAME_STATE_GAMEPLAY
            || game_state_pending == GAME_STATE_PERK_SELECTION
            || game_state_pending == GAME_STATE_PAUSE_MENU
            || game_state_pending == GAME_STATE_OPTIONS_MENU
            || game_state_pending == GAME_STATE_CONTROLS_MENU
            || (game_state_id == GAME_STATE_PAUSE_MENU
                && game_state_pending != GAME_STATE_MAIN_MENU)
            || game_state_id == GAME_STATE_OPTIONS_MENU
            || game_state_id == GAME_STATE_CONTROLS_MENU
            || game_state_pending == GAME_STATE_FINAL_QUEST_END_NOTE
            || game_state_pending == GAME_STATE_GAME_OVER
            || game_state_pending == GAME_STATE_QUEST_RESULTS
            || game_state_pending == GAME_STATE_QUEST_FAILED) {
            ui_transition_alpha = 1.0f;
        }
    }

    if (game_state_id == GAME_STATE_PAUSE_MENU
        && game_state_pending == GAME_STATE_MAIN_MENU) {
        ui_transition_alpha = ui_timeline_fraction();
    }

    if (ui_transition_alpha > 1.0f) {
        ui_transition_alpha = 1.0f;
    } else if (ui_transition_alpha < 0.0f) {
        ui_transition_alpha = 0.0f;
    }

    fx_queue_render();
    terrain_render();

    render_overlay_player_index = 0;
    while (render_overlay_player_index < config_player_count) {
        if (player_state_table[render_overlay_player_index].health <= 0.0f) {
            player_render_overlays();
        }
        ++render_overlay_player_index;
    }

    creature_render_all();

    render_overlay_player_index = 0;
    while (render_overlay_player_index < config_player_count) {
        if (player_state_table[render_overlay_player_index].health > 0.0f) {
            player_render_overlays();
        }
        ++render_overlay_player_index;
    }

    projectile_render(ui_transition_alpha);
    bonus_render();

    if (screen_fade_alpha > 0.0f) {
        grim_interface_ptr->grim_draw_fullscreen_color(
            0.0f, 0.0f, 0.0f, screen_fade_alpha);
    }
}
