#include <math.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern int frame_dt_ms;
extern int demo_trial_elapsed_ms;
extern int demo_trial_overlay_alpha_ms;
extern int pause_keybind_help_alpha_ms;
extern int perk_pending_count;
extern int perk_prompt_pulse;
extern unsigned char console_open_flag;
extern unsigned char game_paused_flag;
extern unsigned char time_scale_active;
extern bool mouse_button_down;
extern unsigned char demo_trial_overlay_active;
extern unsigned char ui_transition_direction;
extern unsigned char perk_prompt_hover_active;
extern unsigned char perk_choices_dirty;
extern float time_scale_factor;
extern float perk_prompt_origin_x;
extern float perk_prompt_origin_y;
extern float perk_prompt_bounds_min_x;
extern float perk_prompt_bounds_min_y;
extern float perk_prompt_bounds_max_x;
extern float perk_prompt_bounds_max_y;
extern game_state_id_t game_state_pending;

extern int sfx_ui_levelup;
extern int music_track_extra_0;
extern int music_track_crimson_theme_id;
extern int music_track_shortie_monk_id;

int game_sequence_get(void);
void perks_update_effects(void);
void creature_update_all(void);
void projectile_update(void);
void player_update(void);
void survival_update(void);
void rush_mode_update(void);
void quest_mode_update(void);
void camera_update(void);
void tutorial_timeline_update(void);
void console_input_poll(void);
void sfx_mute_all(int sfx_id);
void sfx_play_exclusive(int sfx_id);
void perks_generate_choices(void);
bool input_primary_just_pressed(void);
void bonus_update(void);
void ui_render_aim_indicators(void);
void hud_update_and_render(void);
void demo_trial_overlay_render(float *xy, float alpha);
void ui_render_keybind_help(float *xy, float alpha);
}

static __inline bool demo_trial_limit_reached(void)
{
    game_sequence_id = game_sequence_get();
    if ((int)game_sequence_id > 2400000) {
        return true;
    }

    if (demo_trial_elapsed_ms > 0) {
        if (config_blob.game_mode != GAME_MODE_QUEST) {
            return true;
        }
        if ((float)(demo_trial_elapsed_ms / 1000) * 0.016666668f
            <= 5.0f) {
            goto check_quest_progress;
        }
        return true;
    } else if (config_blob.game_mode != GAME_MODE_QUEST) {
        return false;
    }

check_quest_progress:
    return game_state_id == GAME_STATE_GAMEPLAY
        && (quest_stage_major > 1 || quest_stage_minor > 10);
}

static __inline bool demo_trial_blocks_gameplay(void)
{
    return !demo_mode_active
        && !game_is_full_version()
        && config_blob.game_mode != GAME_MODE_TUTORIAL
        && demo_trial_limit_reached();
}

static __inline void clamp_milliseconds(int *value)
{
    if (*value < 0) {
        *value = 0;
    } else if (*value > 1000) {
        *value = 1000;
    }
}

extern "C" void gameplay_update_and_render(void)
{
    float unscaled_frame_dt = frame_dt;

    if (time_scale_active) {
        time_scale_factor = 0.3f;
        if (bonus_reflex_boost_timer < 1.0f) {
            time_scale_factor =
                (1.0f - bonus_reflex_boost_timer) * 0.7f + 0.3f;
        }
        frame_dt *= time_scale_factor;
        frame_dt_ms = (int)(frame_dt * 1000.0f);
    }

    if (!demo_mode_active) {
        if ((!game_is_full_version()
             && config_blob.game_mode != GAME_MODE_TUTORIAL
             && demo_trial_limit_reached())
            || game_paused_flag) {
            frame_dt_ms = 0;
            frame_dt = 0.0f;
        }
    }

    if (!game_paused_flag && !console_open_flag) {
        perks_update_effects();
    }
    effects_update();

    if (!demo_trial_blocks_gameplay()
        && !game_paused_flag
        && game_state_id == GAME_STATE_GAMEPLAY) {
        creature_update_all();
        projectile_update();
    }

    if (!demo_trial_blocks_gameplay()
        && !game_paused_flag
        && game_state_id == GAME_STATE_GAMEPLAY) {
        for (render_overlay_player_index = 0;
             render_overlay_player_index < config_blob.player_count;
             ++render_overlay_player_index) {
            player_update();
        }
    }

    render_overlay_player_index = 0;
    if (config_blob.game_mode == GAME_MODE_SURVIVAL) {
        survival_update();
    }
    if (config_blob.game_mode == GAME_MODE_RUSH) {
        rush_mode_update();
    }
    if (config_blob.game_mode == GAME_MODE_QUEST) {
        quest_mode_update();
    }

    highscore_active_record.score_xp = player_state_table[0].experience;
    if (!console_open_flag && !game_paused_flag) {
        if (bonus_weapon_power_up_timer > 0.0f) {
            bonus_weapon_power_up_timer -= frame_dt;
        }
        if (bonus_energizer_timer > 0.0f) {
            bonus_energizer_timer -= frame_dt;
        }
        if (bonus_reflex_boost_timer > 0.0f) {
            bonus_reflex_boost_timer -= frame_dt;
            time_scale_active = 1;
        } else {
            time_scale_active = 0;
        }
        highscore_active_record.survival_elapsed_ms += frame_dt_ms;
        unsigned int &weapon_time =
            weapon_usage_time[player_state_table[0].weapon_id];
        weapon_time += frame_dt_ms;
    }

    camera_update();
    gameplay_render_world();
    if (config_blob.game_mode == GAME_MODE_TUTORIAL) {
        tutorial_timeline_update();
    }
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

    if (demo_mode_active) {
        for (int player_index = 0; player_index < 2; ++player_index) {
            player_state_table[player_index].health = 100.0f;
        }
    } else if (player_state_table[0].health <= 0.0f
               && player_state_table[0].death_timer < 0.0f
               && (config_blob.player_count == 1
                   || (player_state_table[1].health <= 0.0f
                       && player_state_table[1].death_timer < 0.0f))) {
        render_pass_mode = 0;
        ui_transition_direction = 0;
        game_state_pending = config_blob.game_mode == GAME_MODE_QUEST
            ? GAME_STATE_QUEST_FAILED
            : GAME_STATE_GAME_OVER;
        grim_interface_ptr->grim_flush_input();
        console_input_poll();
        sfx_mute_all(music_track_extra_0);
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_play_exclusive(music_track_shortie_monk_id);
    }

    if (config_blob.game_mode != GAME_MODE_RUSH) {
        int level_threshold = 1000
            - (int)((float)pow((float)player_state_table[0].level, 1.8f)
                    * -1000.0f);
        if (player_state_table[0].experience > level_threshold) {
            ++perk_pending_count;
            if (++config_blob.perk_prompt_counter > 50) {
                config_blob.perk_prompt_counter = 0;
                config_blob.ui_info_texts = 0;
            }
            sfx_play(sfx_ui_levelup, 1.0f);
            ++player_state_table[0].level;
        }
    }

    if (!console_open_flag && !game_paused_flag) {
        int pulse_delta = perk_prompt_hover_active
            ? frame_dt_ms * 3
            : -frame_dt_ms;
        perk_prompt_pulse += pulse_delta * 2;
        clamp_milliseconds(&perk_prompt_pulse);
    }

    if (!demo_mode_active
        && !game_paused_flag
        && !mouse_button_down
        && config_blob.game_mode != GAME_MODE_RUSH
        && perk_pending_count > 0
        && (player_state_table[0].health > 0.0f
            || (config_blob.player_count == 2
                && player_state_table[1].health > 0.0f))) {
        vec2f_t relative_mouse;
        relative_mouse.x = ui_mouse_x - perk_prompt_origin_x;
        relative_mouse.y = ui_mouse_y - perk_prompt_origin_y;

        if (game_state_pending != GAME_STATE_PERK_SELECTION) {
            if (grim_interface_ptr->grim_is_key_active(config_blob.key_pick_perk)
                || grim_interface_ptr->grim_was_key_pressed(57)
                || grim_interface_ptr->grim_was_key_pressed(78)) {
                perk_prompt_pulse = 1000;
                if (perk_choices_dirty) {
                    perks_generate_choices();
                    perk_choices_dirty = 0;
                }
                game_state_set(GAME_STATE_PERK_SELECTION);
            } else if (relative_mouse.x > perk_prompt_bounds_min_x
                       && relative_mouse.y > perk_prompt_bounds_min_y
                       && relative_mouse.x < perk_prompt_bounds_max_x
                       && relative_mouse.y < perk_prompt_bounds_max_y) {
                perk_prompt_hover_active = 1;
                if (input_primary_just_pressed()) {
                    if (perk_choices_dirty) {
                        perks_generate_choices();
                        perk_choices_dirty = 0;
                    }
                    game_state_set(GAME_STATE_PERK_SELECTION);
                }
            } else {
                perk_prompt_hover_active = 0;
            }
        }
    }

    mouse_button_down =
        grim_interface_ptr->grim_is_mouse_button_down(0) != 0;
    bonus_update();
    frame_dt = unscaled_frame_dt;
    frame_dt_ms = (int)(unscaled_frame_dt * 1000.0f);

    if (!demo_mode_active) {
        perk_prompt_update_and_render();
    }
    if (!demo_trial_blocks_gameplay()) {
        ui_render_aim_indicators();
    }

    hud_update_and_render();
    ui_elements_update_and_render();

    if (!game_is_full_version()) {
        if (demo_trial_blocks_gameplay()) {
            float overlay_position[2];
            overlay_position[0] = (float)config_blob.screen_width * 0.5f - 256.0f;
            overlay_position[1] = (float)config_blob.screen_height * 0.5f - 128.0f;
            demo_trial_overlay_alpha_ms += frame_dt_ms;
            demo_trial_overlay_render(overlay_position, 1.0f);
            demo_trial_overlay_active = 1;
        } else {
            demo_trial_overlay_alpha_ms -= frame_dt_ms;
            demo_trial_overlay_active = 0;
        }
        clamp_milliseconds(&demo_trial_overlay_alpha_ms);
    }

    if (grim_interface_ptr->grim_was_key_pressed(59)) {
        game_paused_flag = !game_paused_flag;
    }

    if (!game_is_full_version()
        && config_blob.game_mode != GAME_MODE_TUTORIAL
        && demo_trial_limit_reached()) {
        game_paused_flag = 0;
    }

    if (game_paused_flag) {
        pause_keybind_help_alpha_ms += frame_dt_ms * 2;
    } else {
        pause_keybind_help_alpha_ms += -frame_dt_ms * 4;
    }
    clamp_milliseconds(&pause_keybind_help_alpha_ms);
    if (pause_keybind_help_alpha_ms > 0) {
        float help_position[2];
        help_position[0] = (float)config_blob.screen_width * 0.5f - 256.0f;
        help_position[1] = (float)config_blob.screen_height * 0.5f - 128.0f;
        ui_render_keybind_help(
            help_position,
            (float)pause_keybind_help_alpha_ms * 0.001f);
    }

    if (!game_is_full_version()
        && config_blob.game_mode != GAME_MODE_TUTORIAL
        && demo_trial_limit_reached()
        && !demo_mode_active) {
        ui_cursor_render();
    }
}
