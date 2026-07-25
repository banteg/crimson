#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

struct game_state_vec2_t {
    float x;
    float y;

    game_state_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }
};

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern game_state_id_t game_state_prev;
extern game_status_t game_status_blob;

extern unsigned char game_paused_flag;
extern unsigned char gameplay_transition_latch;
extern unsigned char highscore_return_latch;
extern unsigned char screen_fade_ramp_flag;
extern unsigned char typo_mode_reset_flag;
extern unsigned char plugin_runtime_active_latch;
extern unsigned char ui_transition_direction;
extern int ui_element_hover_focus_index;
extern int ui_elements_timeline;
extern int ui_screen_phase;
extern int game_state_reserved_zero;
extern int ui_item_texts_texture;

extern ui_element_t *ui_element_table_end;
extern ui_element_t ui_sign_crimson;
extern ui_element_t ui_element_slot_02_main_menu_primary;
extern ui_element_t ui_element_slot_03_main_menu_play_game;
extern ui_element_t ui_element_slot_04_main_menu_options;
extern ui_element_t ui_element_slot_05_main_menu_statistics;
extern ui_element_t ui_element_slot_footer_variant_a;
extern ui_element_t ui_element_slot_footer_variant_b;
extern ui_element_t ui_element_slot_09;
extern ui_element_t ui_element_slot_11;
extern ui_element_t ui_element_slot_12_layout_a;
extern ui_element_t ui_element_slot_13;
extern ui_element_t ui_element_slot_14;
extern ui_element_t ui_element_slot_18_layout_b;
extern ui_element_t ui_element_slot_23;
extern ui_element_t ui_element_slot_24;
extern ui_element_t ui_element_slot_25;
extern ui_element_t ui_element_slot_27;
extern ui_element_t ui_element_slot_28;
extern ui_element_t ui_element_slot_30;
extern ui_element_t ui_element_slot_31;
extern ui_element_t ui_element_slot_32_layout_c;
extern ui_element_t ui_element_slot_33;
extern ui_element_t ui_element_slot_35;
extern ui_element_t ui_element_slot_37;
extern ui_element_t ui_element_slot_39;
extern ui_element_t ui_element_slot_40;

void ui_elements_reset_state(void);
int console_input_poll(void);
bool mods_any_available(void);
void gameplay_reset_state(void);
void quest_start_selected(int major, int minor);
void j_highscore_load_table(void);
void game_save_status(void);

void ui_menu_main_click_mods(void);
void statistics_menu_update(void);
void ui_callback_noop(void);
void highscore_screen_update(void);
void credits_secret_alien_zookeeper_update(void);
void mods_menu_update(void);
void unlocked_weapons_database_update(void);
void unlocked_perks_database_update(void);
void credits_screen_update(void);
}

extern "C" void game_state_set(game_state_id_t state_id)
{
    ui_elements_reset_state();
    game_paused_flag = 0;
    game_state_prev = game_state_id;
    game_state_id = state_id;
    ui_element_hover_focus_index = 0;
    gameplay_transition_latch = 0;
    grim_interface_ptr->grim_flush_input();
    console_input_poll();

    if (state_id == GAME_STATE_MAIN_MENU) {
        highscore_return_latch = 0;
        render_pass_mode = 0;
        ui_sign_crimson.active = 1;

        if (game_is_full_version() && mods_any_available()) {
            ui_element_slot_02_main_menu_primary.active = 1;
        }
        if (!game_is_full_version()) {
            ui_element_slot_02_main_menu_primary.active = 1;
        } else {
            ui_element_slot_02_main_menu_primary.on_activate =
                ui_menu_main_click_mods;
        }

        game_state_id_t atlas_row = GAME_STATE_MAIN_MENU;
        for (int i = 2; i <= 7; ++i) {
            if (i == 2 && game_is_full_version()) {
                atlas_row = GAME_STATE_STATISTICS_MENU;
            }

            if (!grim_interface_ptr->grim_get_config_var(100)) {
                if (i == 6) {
                    atlas_row = GAME_STATE_PERK_SELECTION;
                }
                (&ui_element_table_end)[i]->overlay_texture_handle =
                    ui_item_texts_texture;
                *(game_state_vec2_t *)&(&ui_element_table_end)[i]
                    ->overlay_vertices[0].u =
                    game_state_vec2_t(0.0f, (float)atlas_row * 0.125f);
                *(game_state_vec2_t *)&(&ui_element_table_end)[i]
                    ->overlay_vertices[1].u =
                    game_state_vec2_t(1.0f, (float)atlas_row * 0.125f);
                *(game_state_vec2_t *)&(&ui_element_table_end)[i]
                    ->overlay_vertices[2].u =
                    game_state_vec2_t(
                        1.0f, (float)(atlas_row + 1) * 0.125f);
                *(game_state_vec2_t *)&(&ui_element_table_end)[i]
                    ->overlay_vertices[3].u =
                    game_state_vec2_t(
                        0.0f, (float)(atlas_row + 1) * 0.125f);
            } else {
                (&ui_element_table_end)[i]->overlay_texture_handle =
                    ui_item_texts_texture;
                *(game_state_vec2_t *)&(&ui_element_table_end)[i]
                    ->overlay_vertices[0].u =
                    game_state_vec2_t(0.0f, (float)atlas_row * 0.125f);
                *(game_state_vec2_t *)&(&ui_element_table_end)[i]
                    ->overlay_vertices[1].u =
                    game_state_vec2_t(1.0f, (float)atlas_row * 0.125f);
                *(game_state_vec2_t *)&(&ui_element_table_end)[i]
                    ->overlay_vertices[2].u =
                    game_state_vec2_t(
                        1.0f, (float)(atlas_row + 1) * 0.125f);
                *(game_state_vec2_t *)&(&ui_element_table_end)[i]
                    ->overlay_vertices[3].u =
                    game_state_vec2_t(
                        0.0f, (float)(atlas_row + 1) * 0.125f);
            }

            if (i == 2 && game_is_full_version()) {
                atlas_row = GAME_STATE_MAIN_MENU;
            }
            atlas_row = (game_state_id_t)(atlas_row + 1);
            if (atlas_row == GAME_STATE_STATISTICS_MENU) {
                atlas_row = (game_state_id_t)(atlas_row + 1);
            }
        }

        if (!game_is_full_version()) {
            ui_element_slot_02_main_menu_primary.active = 1;
        }
        ui_element_slot_03_main_menu_play_game.active = 1;
        ui_element_slot_04_main_menu_options.active = 1;
        ui_element_slot_05_main_menu_statistics.active = 1;
        ui_element_slot_footer_variant_a.active = 1;
        if (!grim_interface_ptr->grim_get_config_var(100)) {
            ui_element_slot_footer_variant_a.active = 0;
        }
        ui_element_slot_footer_variant_b.active = 1;
    } else if (state_id == GAME_STATE_PLUGIN_RUNTIME) {
        render_pass_mode = 0;
        ui_sign_crimson.focus_disabled = 0;
    } else if (state_id == GAME_STATE_GAMEPLAY) {
        ui_element_slot_28.active = 1;
        screen_fade_ramp_flag = 0;
        if (!render_pass_mode) {
            highscore_return_latch = 0;
            gameplay_reset_state();
            if (config_game_mode == GAME_MODE_QUEST) {
                ++game_status_blob.quest_play_counts[
                    quest_stage_major * 10 + quest_stage_minor];
                quest_start_selected(quest_stage_major, quest_stage_minor);
                render_pass_mode = 1;
                gameplay_transition_latch = 1;
            } else if (config_game_mode == GAME_MODE_RUSH) {
                unsigned int play_count = game_status_blob.mode_play_rush;
                render_pass_mode = 1;
                ++play_count;
                gameplay_transition_latch = 1;
                game_status_blob.mode_play_rush = play_count;
            } else if (config_game_mode == GAME_MODE_SURVIVAL) {
                unsigned int play_count = game_status_blob.mode_play_survival;
                render_pass_mode = 1;
                ++play_count;
                gameplay_transition_latch = 1;
                game_status_blob.mode_play_survival = play_count;
            } else if (config_game_mode == GAME_MODE_TYPO_SHOOTER) {
                unsigned int play_count = game_status_blob.mode_play_typo;
                render_pass_mode = 1;
                ++play_count;
                gameplay_transition_latch = 1;
                game_status_blob.mode_play_typo = play_count;
            } else {
                unsigned int play_count = game_status_blob.mode_play_other;
                render_pass_mode = 1;
                ++play_count;
                gameplay_transition_latch = 1;
                game_status_blob.mode_play_other = play_count;
            }
        }
    } else if (state_id == GAME_STATE_TYPO_GAMEPLAY) {
        config_blob.player_count = 1;
        typo_mode_reset_flag = 1;
        ui_element_slot_28.active = 1;
        screen_fade_ramp_flag = 0;
        if (!render_pass_mode) {
            highscore_return_latch = 0;
            gameplay_reset_state();
            render_pass_mode = 1;
            gameplay_transition_latch = 1;
        }
    } else if (state_id == GAME_STATE_PLAY_GAME_MENU) {
        ui_sign_crimson.active = 1;
        ui_element_slot_11.active = 1;
        ui_element_slot_12_layout_a.active = 1;
    } else if (state_id == GAME_STATE_OPTIONS_MENU) {
        if (!plugin_runtime_active_latch) {
            ui_sign_crimson.active = 1;
        }
        float screen_scale =
            (float)config_blob.screen_width * 0.00156250002f;
        *(game_state_vec2_t *)&ui_element_slot_13.pos =
            game_state_vec2_t(-180.0f, 135.0f);
        ui_element_slot_31.active = 1;
        ui_element_slot_13.pos.x = -58.0f;
        ui_element_slot_32_layout_c.active = 1;
        ui_screen_phase = 0;
        ui_element_slot_13.pos.y +=
            screen_scale * 150.0f + 10.0f - 150.0f;
    } else if (state_id == GAME_STATE_STATISTICS_MENU) {
        highscore_return_latch = 0;
        ui_sign_crimson.active = 1;
        ui_element_slot_39.active = 1;
        ui_element_slot_39.on_update = statistics_menu_update;
    } else if (state_id == GAME_STATE_HIGHSCORE_LEGACY) {
        ui_sign_crimson.active = 1;
        ui_element_slot_09.active = 1;
        ui_element_slot_09.on_update = ui_callback_noop;
        j_highscore_load_table();
    } else if (state_id == GAME_STATE_CONTROLS_MENU) {
        float screen_scale =
            (float)config_blob.screen_width * 0.00156250002f;
        *(game_state_vec2_t *)&ui_element_slot_13.pos =
            game_state_vec2_t(-180.0f, 139.0f);
        ui_sign_crimson.active = 1;
        ui_element_slot_14.active = 1;
        ui_element_slot_18_layout_b.active = 1;
        ui_element_slot_40.active = 1;
        ui_element_slot_13.pos.y =
            screen_scale * 150.0f - 150.0f + 139.0f;
    } else if (state_id == GAME_STATE_HIGHSCORES) {
        ui_sign_crimson.active = 1;
        ui_element_slot_09.active = 1;
        ui_element_slot_33.active = 1;
        ui_element_slot_09.on_update = highscore_screen_update;
        j_highscore_load_table();
    }

    ui_element_slot_33.on_update = 0;

    if (state_id == GAME_STATE_MENU_LEGACY_VARIANT) {
        ui_sign_crimson.active = 1;
        ui_element_slot_09.active = 1;
    } else if (state_id == GAME_STATE_CREDITS_SECRET) {
        ui_sign_crimson.active = 1;
        ui_element_slot_09.active = 1;
        ui_element_slot_09.on_update =
            credits_secret_alien_zookeeper_update;
    } else if (state_id == GAME_STATE_MODS_MENU) {
        ui_sign_crimson.active = 1;
        ui_element_slot_09.active = 1;
        ui_element_slot_09.on_update = mods_menu_update;
    } else if (state_id == GAME_STATE_WEAPON_DATABASE) {
        ui_sign_crimson.active = 1;
        ui_element_slot_09.active = 1;
        ui_element_slot_33.active = 1;
        ui_element_slot_09.on_update = unlocked_weapons_database_update;
    } else if (state_id == GAME_STATE_PERK_DATABASE) {
        ui_sign_crimson.active = 1;
        ui_element_slot_09.active = 1;
        ui_element_slot_33.active = 1;
        ui_element_slot_09.on_update = unlocked_perks_database_update;
    } else if (state_id == GAME_STATE_CREDITS) {
        ui_screen_phase = 0;
        ui_sign_crimson.active = 1;
        ui_element_slot_09.active = 1;
        ui_element_slot_09.on_update = credits_screen_update;
    } else if (state_id == GAME_STATE_QUEST_SELECT) {
        ui_sign_crimson.active = 1;
        ui_element_slot_37.active = 1;
    } else if (state_id == GAME_STATE_PAUSE_MENU) {
        if (!plugin_runtime_active_latch) {
            ui_sign_crimson.active = 1;
        }
        ui_sign_crimson.focus_disabled = 0;
        ui_element_slot_23.active = 1;
        ui_element_slot_24.active = 1;
        ui_element_slot_25.active = 1;
    } else if (state_id == GAME_STATE_PERK_SELECTION) {
        ui_element_slot_27.active = 1;
    } else if (state_id == GAME_STATE_QUEST_RESULTS) {
        ui_element_slot_35.active = 1;
        game_save_status();
        ui_screen_phase = -2;
    } else if (state_id == GAME_STATE_FINAL_QUEST_END_NOTE) {
        ui_element_slot_35.active = 1;
        ui_screen_phase = -1;
    } else if (state_id == GAME_STATE_QUEST_FAILED) {
        ui_element_slot_35.active = 1;
        ui_screen_phase = -1;
    } else if (state_id == GAME_STATE_GAME_OVER) {
        ui_element_slot_30.active = 1;
        game_state_reserved_zero = 0;
        ui_screen_phase = -1;
    }

    if (highscore_return_latch) {
        ui_sign_crimson.active = 0;
    }
    ui_elements_timeline = 0;
    ui_transition_direction = 1;
}
