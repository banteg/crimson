#include <math.h>
#include <stdio.h>
#include <windows.h>

#include "crimsonland_audio.h"
#include "crimsonland_console.h"
#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern player_state_t player_state_table[];
extern quest_meta_t quest_selected_meta[];
extern ui_element_t ui_element_slot_01_main_menu_aux;
extern ui_element_t ui_element_slot_02_main_menu_primary;
extern mod_interface_t *plugin_interface_ptr;

extern unsigned char render_pass_mode;
extern unsigned char demo_trial_overlay_active;
extern unsigned char shareware_offer_seen_latch;
extern unsigned char main_menu_full_version_layout_latch;
extern unsigned char screen_fade_ramp_flag;
extern unsigned char input_mouse_delta_nonzero;
extern unsigned char ui_mouse_blocked;
extern int ui_analog_cursor_active;
extern unsigned char ui_transition_direction;
extern unsigned char demo_purchase_screen_active;
extern unsigned char quit_requested;
extern unsigned char update_notice_open_requested;
extern unsigned char update_notice_pending;
extern unsigned char full_version_recheck_pending_slot_1;
extern unsigned char full_version_recheck_pending;
extern unsigned char full_version_recheck_pending_slot_3;

extern int quest_unlock_index;
extern int quest_stage_major;
extern int quest_stage_minor;
extern unsigned int game_sequence_id;
extern int game_time_ms;
extern int frame_dt_ms;
extern int demo_trial_elapsed_ms;
extern int time_played_ms;
extern int screenshot_file_index;
extern int stats_menu_easter_egg_roll;
extern int ui_elements_timeline;
extern int online_sync_status;

extern float frame_dt;
extern float frame_dt_copy;
extern float game_time_s;
extern float screen_fade_alpha;
extern float ui_mouse_x;
extern float ui_mouse_y;
extern player_aim_screen_xy_t player_aim_screen_x;

extern game_state_id_t game_state_id;
extern game_state_id_t game_state_prev;
extern game_state_id_t game_state_pending;
extern cvar_float_t *cv_showFPS;
extern SYSTEMTIME local_system_time;
extern char screenshot_filename_buf[];
extern char *update_notice_url;

extern int perk_id_reflex_boosted;
extern int music_track_intro_id;

unsigned char game_is_full_version(...);
int game_sequence_get(void);
int demo_trial_time_limit_ms(void);
void terrain_generate(quest_meta_t *quest);
void terrain_generate_random(void);
void ui_menu_main_click_mods(void);
int perk_count_get(int perk_id);
void gameplay_update_and_render(void);
void demo_purchase_screen_update(void);
void plugin_runtime_update_and_render(void);
void perk_selection_screen_update(void);
void game_over_screen_update(void);
void quest_results_screen_update(void);
void quest_failed_screen_update(void);
void typo_gameplay_update_and_render(void);
void game_update_victory_screen(void);
void game_update_generic_menu(void);
int ui_elements_max_timeline(void);
void ui_render_loading(void);
void config_sync_from_grim(void);
void demo_mode_start(void);

int crt_sprintf(char *dst, const char *format, ...);
FILE *crt_fopen(char *path, char *mode);
int crt_fclose(FILE *fp);
int crt_rand(void);
}

struct frame_vec2_t {
    float x;
    float y;

    frame_vec2_t() {}

    frame_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    frame_vec2_t &operator+=(const frame_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

struct frame_color_t {
    float r;
    float g;
    float b;
    float a;

    frame_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}

    void set(float r_value, float g_value, float b_value, float a_value)
    {
        r = r_value;
        g = g_value;
        b = b_value;
        a = a_value;
    }
};

extern "C" unsigned char game_frame_update(void)
{
    frame_dt = grim_interface_ptr->grim_get_frame_dt();

    if (quest_unlock_index < 40) {
        config_blob.hardcore = 0;
    }

    if (!game_is_full_version()) {
        if ((int)game_sequence_id < 0) {
            game_sequence_id = 1200000;
        }
        game_sequence_id = game_sequence_get();
        config_blob.hardcore = 0;
    }

    if (game_is_full_version()) {
        ui_element_slot_02_main_menu_primary.on_activate =
            ui_menu_main_click_mods;
        shareware_offer_seen_latch = 0;
    }

    if (!main_menu_full_version_layout_latch && game_is_full_version()) {
        ui_element_slot_01_main_menu_aux.pos.y += 60.0f;
        ui_element_slot_01_main_menu_aux.timeline_end_ms =
            ui_element_slot_02_main_menu_primary.timeline_end_ms;
        ui_element_slot_01_main_menu_aux.timeline_start_ms =
            ui_element_slot_02_main_menu_primary.timeline_start_ms;
        main_menu_full_version_layout_latch = 1;
        ui_element_slot_02_main_menu_primary.active = 0;
        ui_element_slot_01_main_menu_aux.pos.x -= 20.0f;
    }

    if (!audio_suspend_flag) {
        if ((bool)grim_interface_ptr->grim_get_config_var(0x57)) {
            if (render_pass_mode && config_blob.game_mode == GAME_MODE_QUEST) {
                int minor = quest_stage_minor - 1;
                int major = quest_stage_major - 1;
                if (minor >= 10) {
                    minor -= (unsigned int)minor / 10 * 10;
                }
                if (major >= 4) {
                    major -= (unsigned int)major / 4 * 4;
                }
                terrain_generate(&quest_selected_meta[minor * 10 + major]);
            } else {
                terrain_generate_random();
            }
            grim_interface_ptr->grim_set_config_var(0x57, false);
        }
    }

    if (!game_is_full_version() && quest_unlock_index > 10) {
        quest_unlock_index = 10;
    }

    if (audio_suspend_flag) {
        audio_resume_all();
        return 1;
    }

    game_time_ms += frame_dt_ms;
    if (grim_interface_ptr->grim_was_key_pressed(0x29)) {
        console_log_queue.console_set_open(!console_log_queue.open);
    }
    console_log_queue.update();

    if (grim_interface_ptr->grim_was_key_pressed(0x58)) {
        unsigned char filename_available;
        do {
            if (screenshot_file_index < 10) {
                crt_sprintf(
                    screenshot_filename_buf,
                    "shot_00%d.bmp",
                    screenshot_file_index);
            } else if (screenshot_file_index < 100) {
                crt_sprintf(
                    screenshot_filename_buf,
                    "shot_0%d.bmp",
                    screenshot_file_index);
            } else {
                crt_sprintf(
                    screenshot_filename_buf,
                    "shot_%d.bmp",
                    screenshot_file_index);
            }

            FILE *fp = crt_fopen(screenshot_filename_buf, "rb");
            if (fp != 0) {
                crt_fclose(fp);
                filename_available = 0;
            } else {
                filename_available = 1;
            }
            ++screenshot_file_index;
        } while (!filename_available);

        grim_interface_ptr->grim_save_screenshot(screenshot_filename_buf);
    }

    if (!demo_mode_active && !demo_trial_overlay_active) {
        game_sequence_id = game_sequence_get();
        game_state_id_t current_state = game_state_id;
        if (!console_log_queue.open && render_pass_mode
            && current_state == GAME_STATE_GAMEPLAY) {
            game_sequence_id += (int)(frame_dt * 1000.0f);
        }
        if (demo_trial_elapsed_ms > 0 && !console_log_queue.open
            && render_pass_mode && current_state == GAME_STATE_GAMEPLAY
            && config_blob.game_mode != GAME_MODE_TUTORIAL) {
            demo_trial_elapsed_ms += (int)(frame_dt * 1000.0f);
        }
    }

    if (render_pass_mode && perk_count_get(perk_id_reflex_boosted) != 0
        && game_state_id == GAME_STATE_GAMEPLAY) {
        frame_dt *= 0.9f;
    }

    game_time_s += frame_dt;
    frame_dt_copy = frame_dt;
    frame_dt_ms = (int)(frame_dt * 1000.0f);
    if (!console_log_queue.open && render_pass_mode
        && game_state_id == GAME_STATE_GAMEPLAY
        && config_blob.game_mode != GAME_MODE_TUTORIAL) {
        time_played_ms += frame_dt_ms;
    }

    if (screen_fade_ramp_flag) {
        screen_fade_alpha += frame_dt * 10.0f;
    } else {
        screen_fade_alpha -= frame_dt * 2.0f;
    }
    if (screen_fade_alpha < 0.0f) {
        screen_fade_alpha = 0.0f;
    } else if (screen_fade_alpha > 1.0f) {
        screen_fade_alpha = 1.0f;
    }

    if (console_log_queue.open) {
        frame_dt = 0.0f;
    }

    input_mouse_delta_nonzero =
        grim_interface_ptr->grim_get_mouse_dx() != 0.0f
        && grim_interface_ptr->grim_get_mouse_dy() != 0.0f;
    if (input_mouse_delta_nonzero) {
        ui_mouse_blocked = 0;
        ui_analog_cursor_active = 0;
    }

    frame_vec2_t analog_input;
    frame_vec2_t cursor_delta(0.0f, 0.0f);
    analog_input.x = grim_interface_ptr->grim_get_config_float(
        player_state_table[0].input.axis_aim_x);
    analog_input.y = grim_interface_ptr->grim_get_config_float(
        player_state_table[0].input.axis_aim_y);
    if ((float)sqrt(
            analog_input.x * analog_input.x
            + analog_input.y * analog_input.y) > 0.2f) {
        cursor_delta.x = analog_input.x;
        cursor_delta.y = analog_input.y;
    }

    analog_input.x = grim_interface_ptr->grim_get_config_float(
        player_state_table[0].input.axis_move_x);
    analog_input.y = grim_interface_ptr->grim_get_config_float(
        player_state_table[0].input.axis_move_y);
    if ((float)sqrt(
            analog_input.x * analog_input.x
            + analog_input.y * analog_input.y) > 0.2f) {
        cursor_delta += analog_input;
    }
    if ((float)sqrt(
            cursor_delta.x * cursor_delta.x
            + cursor_delta.y * cursor_delta.y) > 0.2f) {
        ui_analog_cursor_active = 1;
    }

    if (game_state_id == GAME_STATE_GAMEPLAY) {
        ui_analog_cursor_active = 0;
    }
    if (game_state_id != GAME_STATE_GAMEPLAY
        && ui_analog_cursor_active == 1) {
        float cursor_scale = config_blob.mouse_sensitivity * frame_dt;
        ui_mouse_x += cursor_scale * cursor_delta.x * 540.0f;
        ui_mouse_y += cursor_scale * cursor_delta.y * 540.0f;
    } else {
        ui_mouse_x += grim_interface_ptr->grim_get_mouse_dx()
            * config_blob.mouse_sensitivity * 2.0f;
        ui_mouse_y += grim_interface_ptr->grim_get_mouse_dy()
            * config_blob.mouse_sensitivity * 2.0f;

        for (int aim_index = 0; aim_index < 4; aim_index += 2) {
            float *aim = &player_aim_screen_x[aim_index];
            aim[0] = ui_mouse_x;
            aim[1] = ui_mouse_y;
        }
    }

    if (ui_mouse_x < 0.0f) {
        ui_mouse_x = 0.0f;
    }
    if (ui_mouse_y < 0.0f) {
        ui_mouse_y = 0.0f;
    }
    if (ui_mouse_x > (float)(config_blob.screen_width - 1)) {
        ui_mouse_x = (float)(config_blob.screen_width - 1);
    }
    if (ui_mouse_y > (float)(config_blob.screen_height - 1)) {
        ui_mouse_y = (float)(config_blob.screen_height - 1);
    }

    if (game_state_id == GAME_STATE_PLUGIN_RUNTIME
        || plugin_runtime_active_latch) {
        plugin_runtime_update_and_render();
    } else if (game_state_id == GAME_STATE_GAMEPLAY) {
        if (demo_purchase_screen_active) {
            grim_interface_ptr->grim_clear_color(0.0f, 0.0f, 0.0f, 0.0f);
        } else {
            gameplay_update_and_render();
        }
        if (demo_mode_active) {
            demo_purchase_screen_update();
        }
        if (audio_suspend_flag) {
            return 1;
        }
    } else if (game_state_id == GAME_STATE_DEMO_UPSELL_GAMEPLAY) {
        gameplay_update_and_render();
        demo_purchase_screen_update();
        if (audio_suspend_flag) {
            return 1;
        }
    } else if (game_state_id == GAME_STATE_PERK_SELECTION) {
        perk_selection_screen_update();
    } else if (game_state_id == GAME_STATE_GAME_OVER) {
        game_over_screen_update();
    } else if (game_state_id == GAME_STATE_QUEST_RESULTS) {
        quest_results_screen_update();
    } else if (game_state_id == GAME_STATE_QUEST_FAILED) {
        quest_failed_screen_update();
    } else if (game_state_id == GAME_STATE_TYPO_GAMEPLAY) {
        typo_gameplay_update_and_render();
    } else if (game_state_id == GAME_STATE_FINAL_QUEST_END_NOTE) {
        game_update_victory_screen();
    } else {
        demo_purchase_screen_active = 0;
        game_update_generic_menu();
    }

    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 2.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.6f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.4f);
    if (!game_is_full_version()) {
        grim_interface_ptr->grim_set_color(1.0f, 0.3f, 0.3f, 0.6f);
        grim_interface_ptr->grim_set_config_var(0x18, 0.45f);
    }

    if (cv_showFPS->value != 0.0f) {
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.6f);
        if ((int)grim_interface_ptr->grim_get_fps() >= 400) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                (float)(config_blob.screen_width - 51),
                (float)(config_blob.screen_height - 24),
                "400+",
                (int)grim_interface_ptr->grim_get_fps());
        } else {
            grim_interface_ptr->grim_draw_text_small_fmt(
                (float)(config_blob.screen_width - 45),
                (float)(config_blob.screen_height - 24),
                "%d",
                (int)grim_interface_ptr->grim_get_fps());
        }
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.6f);
    }

    console_log_queue.render();
    crt_rand();
    audio_update();

    if (grim_interface_ptr->grim_was_key_pressed(1)
        && (render_pass_mode
            || game_state_id == GAME_STATE_PLUGIN_RUNTIME)
        && (game_state_id == GAME_STATE_GAMEPLAY
            || game_state_id == GAME_STATE_PLUGIN_RUNTIME
            || game_state_id == GAME_STATE_TYPO_GAMEPLAY)) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_PAUSE_MENU;
        if (plugin_interface_ptr != 0) {
            plugin_interface_ptr->parms.fields.onPause = 1;
        }
    }

    if (stats_menu_easter_egg_roll == -1) {
        stats_menu_easter_egg_roll = crt_rand() % 32;
    }
    if (game_state_id == GAME_STATE_STATISTICS_MENU && !render_pass_mode
        && local_system_time.wMonth == 3 && local_system_time.wDay == 3
        && stats_menu_easter_egg_roll == 3) {
        stats_menu_easter_egg_roll = -1;
        grim_interface_ptr->grim_set_color(0.2f, 1.0f, 0.6f, 0.5f);
        grim_interface_ptr->grim_draw_text_small(
            (float)(crt_rand() % 64 + 16),
            5.0f,
            "Orbes Volantes Exstare");
    }

    if (!game_is_full_version() && !demo_mode_active) {
        int time_limit_ms = demo_trial_time_limit_ms();
        float ratio = (float)(int)game_sequence_id;
        float time_limit = (float)time_limit_ms;
        ratio /= time_limit;
        if (ratio > 1.0f) {
            ratio = 1.0f;
        }

        frame_color_t bar_color(0.0f, 0.0f, 0.0f, 0.5f);
        frame_vec2_t bar_position(
            0.0f, (float)(config_blob.screen_height - 7));
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)&bar_position,
            (float)config_blob.screen_width,
            8.0f,
            (float *)&bar_color);

        float denominator = ratio * 4.0f + 1.0f;
        bar_color.set(
            ratio,
            0.9f / denominator,
            (float)(0.5 / denominator),
            0.5f);
        bar_position.set(
            2.0f, (float)(config_blob.screen_height - 5));
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)&bar_position,
            (float)(config_blob.screen_width - 4) * ratio,
            3.0f,
            (float *)&bar_color);
    }

    if (demo_mode_active && game_state_pending == GAME_STATE_MAIN_MENU) {
        int max_timeline = ui_elements_max_timeline();
        float fade;
        if (max_timeline == 0) {
            fade = 1.0f;
        } else {
            fade = 1.0f
                - (float)ui_elements_timeline / (float)max_timeline;
        }
            fade *= fade;
        if (game_state_prev == GAME_STATE_DEMO_UPSELL_GAMEPLAY) {
            fade = 1.0f - fade;
            demo_purchase_screen_active = 0;
        }
        if (fade < 0.0f) {
            fade = 0.0f;
        } else if (fade > 1.0f) {
            fade = 1.0f;
        }
        grim_interface_ptr->grim_draw_fullscreen_color(
            0.0f, 0.0f, 0.0f, fade);
    }

    if (game_state_pending == GAME_STATE_QUIT_TRANSITION) {
        int max_timeline = ui_elements_max_timeline();
        float fade;
        if (max_timeline == 0) {
            fade = 1.0f;
        } else {
            fade = 1.0f
                - (float)ui_elements_timeline / (float)max_timeline;
        }
        if (game_state_prev == GAME_STATE_PLUGIN_RUNTIME) {
            fade = 1.0f - fade;
        }
        if (fade < 0.0f) {
            fade = 0.0f;
        } else if (fade > 1.0f) {
            fade = 1.0f;
        }
        grim_interface_ptr->grim_draw_fullscreen_color(
            0.0f, 0.0f, 0.0f, fade);
    }

    if (grim_interface_ptr->grim_is_key_down(0x10)
        && grim_interface_ptr->grim_is_key_down(0x38)) {
        quit_requested = 1;
    }

    if (quit_requested) {
        if (game_is_full_version()) {
            config_sync_from_grim();
            return 0;
        }
        if (shareware_offer_seen_latch || game_is_full_version()) {
            return 0;
        }

        config_sync_from_grim();
        demo_mode_start();
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_extra_0);
        sfx_mute_all(music_track_intro_id);
        sfx_play_exclusive(music_track_shortie_monk_id);
        quit_requested = 0;
        shareware_offer_seen_latch = 1;
    }

    if (full_version_recheck_pending_slot_1) {
        full_version_recheck_pending_slot_1 = 0;
        ui_render_loading();
        ui_render_loading();
        audio_suspend_all();
        game_is_full_version(1);
    }
    if (full_version_recheck_pending) {
        full_version_recheck_pending = 0;
        ui_render_loading();
        ui_render_loading();
        audio_suspend_all();
        game_is_full_version(2);
    }
    if (full_version_recheck_pending_slot_3) {
        full_version_recheck_pending_slot_3 = 0;
        ui_render_loading();
        ui_render_loading();
        audio_suspend_all();
        game_is_full_version(3);
    }

    if (online_sync_status == 0 && update_notice_pending
        && update_notice_url != 0
        && (game_state_id != GAME_STATE_HIGHSCORES
            || update_notice_open_requested)) {
        Sleep(100);
        return 0;
    }

    return 1;
}
