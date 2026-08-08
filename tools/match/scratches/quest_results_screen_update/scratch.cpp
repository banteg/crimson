#include <string.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct quest_results_vec2_t {
    float x;
    float y;

    quest_results_vec2_t() {}

    quest_results_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    quest_results_vec2_t operator+(
        const quest_results_vec2_t &other) const
    {
        return quest_results_vec2_t(x + other.x, y + other.y);
    }
};

struct quest_results_text_input_t {
    char *text;
    int cursor;
    int max_chars;
    int width_px;
    float alpha;

    quest_results_text_input_t(char *buffer, int max, int width)
    {
        alpha = 1.0f;
        text = buffer;
        cursor = 0;
        max_chars = max;
        width_px = width;
    }

    ~quest_results_text_input_t() {}
};

struct quest_results_button_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    int hover_anim;
    int click_anim;
    float alpha;
    bool force_small;
    bool force_wide;

    quest_results_button_t()
    {
        enabled = true;
        force_wide = false;
        force_small = false;
        alpha = 1.0f;
        click_anim = 0;
        label = 0;
        hovered = false;
        activated = false;
        hover_anim = 0;
    }

    ~quest_results_button_t() {}
};

extern "C" {
extern game_state_id_t game_state_pending;
extern game_state_id_t game_state_prev;
extern unsigned char ui_transition_direction;
extern int ui_screen_phase;
extern unsigned char highscore_return_latch;
extern int highscore_return_quest_stage_major;
extern int highscore_return_quest_stage_minor;
extern game_mode_id_t highscore_return_game_mode_id;
extern unsigned char highscore_return_hardcore_flag;
extern int quest_results_highscore_rank_index;
extern char quest_results_name_input_buffer[];
extern ui_element_t ui_element_slot_35;
extern ui_element_t ui_sign_crimson;
extern int ui_text_well_done_texture;
extern float render_tint_color_r;
extern float render_tint_color_a;
extern int player_name_length;
extern int frame_dt_ms;
extern int perk_pending_count;
extern int quest_spawn_timeline;
extern float player_health[];
extern float player2_health[];
extern int quest_results_health_bonus_ms;
extern int quest_results_unlock_weapon_id;
extern int quest_results_unlock_perk_id;
extern int quest_results_anim_timer;
extern int quest_results_final_time_ms;
extern int quest_results_reveal_base_time_ms;
extern int quest_results_reveal_health_bonus_ms;
extern int quest_results_reveal_perk_bonus_s;
extern int quest_results_step;
extern int quest_results_reveal_total_time_ms;
extern int quest_results_reveal_step_timer_ms;
extern int perk_id_antiperk;
extern int sfx_ui_clink_01;
extern int sfx_ui_typeenter;
extern int sfx_shock_hit_01;
extern int music_track_shortie_monk_id;
extern int music_track_crimsonquest_id;
extern int music_track_crimson_theme_id;
extern int music_track_extra_0;

void highscore_load_table_thunk(void);
int highscore_rank_index(void);
void highscore_record_init(void);
void highscore_save_active(void);
char *time_format_mm_ss(int seconds);
char *weapon_table_entry(int weapon_id);
unsigned char input_primary_just_pressed(void);
unsigned char sfx_is_unmuted(int sfx_id);
void sfx_mute_all(int sfx_id);
void sfx_play(int sfx_id, float gain);
void sfx_play_exclusive(int sfx_id);
void ui_draw_textured_quad(
    int x, int y, int width, int height, int texture_id);
bool ui_text_input_update(float *xy, ui_text_input_state_t *input_state);
void ui_text_input_render(
    float *xy,
    highscore_record_t *record,
    float alpha,
    int rank);
bool ui_button_update(float *xy, ui_button_t *button);
}

extern "C" void quest_results_screen_update(void)
{
    bonus_reflex_boost_timer = 0.0f;
    quest_fail_retry_count = 0;
    if (game_state_id == GAME_STATE_QUEST_RESULTS
        && game_state_pending == GAME_STATE_PENDING_IDLE_SENTINEL
        && ui_transition_direction != 0
        && !sfx_is_unmuted(music_track_shortie_monk_id)) {
        sfx_play_exclusive(music_track_crimsonquest_id);
    }

    gameplay_render_world();
    ui_elements_update_and_render();

    static quest_results_button_t name_submit_button;
    static quest_results_text_input_t name_input(
        quest_results_name_input_buffer, 0x18, 0x60);

    quest_results_vec2_t panel_xy =
        *(quest_results_vec2_t *)&ui_element_slot_35.pos
        + *(quest_results_vec2_t *)&ui_element_slot_35.vertices[0].position
        + quest_results_vec2_t(180.0f, 40.0f);

    quest_results_vec2_t record_xy;
    quest_results_vec2_t xy = panel_xy;
    xy.x += ui_element_slot_35.render_offset_x;
    xy.x += 40.0f;
    ui_draw_textured_quad(
        (int)(xy.x - 18.0f),
        (int)(xy.y - 4.0f),
        256,
        64,
        ui_text_well_done_texture);
    xy.y += 56.0f;
    quest_results_vec2_t results_base_xy = xy;
    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, 1.0f);

    int phase;
    if (game_state_prev == GAME_STATE_HIGHSCORES
        && ui_transition_direction != 0
        && highscore_return_latch != 0) {
        highscore_return_latch = 0;
        ui_screen_phase = 2;
        goto show_results;
    }

    phase = ui_screen_phase;
    if (phase == -2) {
        int quest_index =
            quest_stage_minor + quest_stage_major * 10 - 11;
        quest_results_unlock_weapon_id =
            quest_selected_meta[quest_index].unlock_weapon_id;
        quest_results_unlock_perk_id =
            quest_selected_meta[quest_index].unlock_perk_id;

        player_health[0] = (float)(int)player_health[0];
        int health_bonus = (int)(player_health[0] * 50.0f);
        quest_results_health_bonus_ms = health_bonus;
        if (config_blob.player_count == 2) {
            health_bonus += (int)(player2_health[0] * 50.0f);
            quest_results_health_bonus_ms = health_bonus;
        }
        int final_time =
            quest_spawn_timeline
            - perk_pending_count * 1000
            - health_bonus;
        quest_results_final_time_ms = final_time;
        highscore_active_record.survival_elapsed_ms = final_time;
        if (final_time == 0) {
            highscore_active_record.survival_elapsed_ms = 1;
        }
        quest_results_anim_timer = 0;
        highscore_record_init();
        quest_results_reveal_step_timer_ms = 700;
        quest_results_reveal_base_time_ms = 0;
        quest_results_reveal_health_bonus_ms = 0;
        quest_results_reveal_perk_bonus_s = 0;
        quest_results_step = 0;
        quest_results_reveal_total_time_ms = 0;
        ++ui_screen_phase;
        phase = ui_screen_phase;
    }

    if (phase == -1) {
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 1.0f);
        quest_results_reveal_step_timer_ms -= frame_dt_ms;
        xy.y += 40.0f;
        if (quest_results_reveal_step_timer_ms <= 0) {
            if (quest_results_step < 3) {
                switch (quest_results_step) {
                case 0:
                    quest_results_reveal_step_timer_ms = 40;
                    quest_results_reveal_base_time_ms += 2000;
                    sfx_play(sfx_ui_clink_01, 1.0f);
                    {
                        int reveal_time =
                            quest_results_reveal_base_time_ms;
                        if (reveal_time >= quest_spawn_timeline) {
                            reveal_time = quest_spawn_timeline;
                            quest_results_reveal_base_time_ms =
                                reveal_time;
                            ++quest_results_step;
                        }
                        quest_results_reveal_total_time_ms =
                            reveal_time;
                    }
                    break;
                case 1:
                    quest_results_reveal_health_bonus_ms += 1000;
                    quest_results_reveal_step_timer_ms = 150;
                    sfx_play(sfx_ui_clink_01, 1.0f);
                    quest_results_reveal_total_time_ms -= 1000;
                    if (quest_results_reveal_health_bonus_ms
                        >= quest_results_health_bonus_ms) {
                        quest_results_reveal_health_bonus_ms =
                            quest_results_health_bonus_ms;
                        ++quest_results_step;
                    }
                    break;
                case 2:
                    quest_results_reveal_step_timer_ms = 300;
                    ++quest_results_reveal_perk_bonus_s;
                    sfx_play(sfx_ui_clink_01, 1.0f);
                    quest_results_reveal_total_time_ms -= 1000;
                    if (quest_results_reveal_perk_bonus_s
                        >= perk_pending_count) {
                        quest_results_reveal_perk_bonus_s =
                            perk_pending_count;
                        quest_results_reveal_step_timer_ms = 1000;
                        ++quest_results_step;
                        highscore_active_record.survival_elapsed_ms =
                            quest_results_final_time_ms;
                        quest_results_reveal_total_time_ms =
                            quest_results_final_time_ms;
                    }
                    break;
                }
            } else if (quest_results_step == 3) {
                quest_results_reveal_step_timer_ms = 50;
                ++quest_results_anim_timer;
            }
        }

        float alpha =
            1.0f - (float)quest_results_anim_timer * 0.1f;
        if (alpha < 0.0f) {
            alpha = 0.0f;
        } else if (alpha > 1.0f) {
            alpha = 1.0f;
        }
        xy.x += 32.0f;
        xy.y += 20.0f;
        if (quest_results_step == 0) {
            grim_interface_ptr->grim_set_color(
                0.1f, 0.8f, 0.1f, alpha);
        } else {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, alpha * 0.4f);
        }
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x, xy.y, "Base Time:");
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x + 132.0f,
            xy.y,
            "%s",
            time_format_mm_ss(
                quest_results_reveal_base_time_ms / 1000));

        xy.y += 20.0f;
        if (quest_results_step == 1) {
            grim_interface_ptr->grim_set_color(
                0.1f, 0.8f, 0.1f, alpha);
        } else {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, alpha * 0.4f);
        }
        if (quest_results_step < 1) {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, alpha * 0.2f);
        }
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x, xy.y, "Life Bonus:");
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x + 132.0f,
            xy.y,
            "%s",
            time_format_mm_ss(
                quest_results_reveal_health_bonus_ms / 1000));

        xy.y += 20.0f;
        if (quest_results_step == 2) {
            grim_interface_ptr->grim_set_color(
                0.1f, 0.8f, 0.1f, alpha);
        } else {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, alpha * 0.4f);
        }
        if (quest_results_step < 2) {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, alpha * 0.2f);
        }
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x, xy.y, "Unpicked Perk Bonus:");
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x + 132.0f,
            xy.y,
            "%s",
            time_format_mm_ss(
                quest_results_reveal_perk_bonus_s));

        xy.y += 20.0f;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, alpha);
        quest_results_vec2_t line_xy;
        line_xy.x = xy.x - 4.0f;
        line_xy.y = xy.y + 1.0f;
        grim_interface_ptr->grim_draw_rect_outline(
            (float *)&line_xy, 168.0f, 1.0f);
        xy.y += 8.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x, xy.y, "Final Time:");
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x + 132.0f,
            xy.y,
            "%s",
            time_format_mm_ss(
                quest_results_reveal_total_time_ms / 1000));
        xy.y += 20.0f;

        grim_interface_ptr->grim_flush_input();
        grim_interface_ptr->grim_was_key_pressed(0x1c);
        if (ui_screen_phase == -1
            && (grim_interface_ptr->grim_was_key_pressed(0x39)
                || input_primary_just_pressed())) {
            ++ui_screen_phase;
            goto done;
        }
        if (quest_results_anim_timer > 10) {
            quest_results_anim_timer = 0;
            ++ui_screen_phase;
        }
        goto done;
    }

    if (phase == 0) {
        highscore_load_table_thunk();
        quest_results_highscore_rank_index = highscore_rank_index();
        grim_interface_ptr->grim_flush_input();
        grim_interface_ptr->grim_was_key_pressed(0x1c);
        if (quest_results_highscore_rank_index >= 100) {
            name_input.cursor = 0;
            name_input.max_chars = 0;
            name_input.text = quest_results_name_input_buffer;
            ui_screen_phase = 2;
            goto done;
        }
        name_input.max_chars = 0x14;
        name_input.text = quest_results_name_input_buffer;
        ui_screen_phase = 1;
        strcpy(
            quest_results_name_input_buffer,
            highscore_active_record.player_name);
        name_input.cursor =
            strlen(highscore_active_record.player_name);
        goto done;
    }

    if (phase == 1) {
        if (quest_results_anim_timer < 500) {
            quest_results_anim_timer += frame_dt_ms;
        } else {
            quest_results_anim_timer = 500;
        }
        float alpha =
            (float)quest_results_anim_timer * 0.002f;
        xy.y += 22.0f;
        render_tint_color_a = alpha;
        grim_interface_ptr->grim_set_color_ptr(
            &render_tint_color_r);
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x + 42.0f,
            xy.y,
            "State your name trooper!");
        render_tint_color_a = 0.7f;
        xy.y += 32.0f;
        name_input.width_px = 166;
        name_input.alpha = alpha;
        name_submit_button.label = "Ok";
        name_submit_button.alpha = alpha;

        quest_results_vec2_t button_xy;
        button_xy.x = xy.x + 170.0f;
        button_xy.y = xy.y - 8.0f;
        ui_button_update(
            (float *)&button_xy,
            (ui_button_t *)&name_submit_button);
        if (ui_text_input_update(
                (float *)&xy,
                (ui_text_input_state_t *)&name_input)
            || name_submit_button.activated) {
            int length = strlen(quest_results_name_input_buffer);
            int first_non_space = 0;
            if (length >= 1) {
                while (first_non_space < length
                       && quest_results_name_input_buffer[
                              first_non_space]
                           == ' ') {
                    ++first_non_space;
                }
            }
            if (length >= 1
                && quest_results_name_input_buffer[first_non_space]
                    != 0) {
                ui_screen_phase = 2;
                sfx_play(sfx_ui_typeenter, 1.0f);
                size_t copy_size =
                    strlen(quest_results_name_input_buffer) + 1;
                int cursor = name_input.cursor;
                player_name_length = cursor;
                memcpy(
                    highscore_active_record.player_name,
                    quest_results_name_input_buffer,
                    copy_size);
                name_input.cursor = 0;
                name_input.max_chars = 0;
                highscore_active_record.player_name[cursor] = 0;
                name_input.text = quest_results_name_input_buffer;
                highscore_save_active();
                highscore_load_table_thunk();
            } else {
                name_submit_button.activated = false;
                sfx_play(sfx_shock_hit_01, 1.0f);
            }
        }

        xy.y += 30.0f;
        grim_interface_ptr->grim_set_color_ptr(
            &render_tint_color_r);
        button_xy.x = xy.x + 26.0f;
        button_xy.y = xy.y + 16.0f;
        ui_text_input_render(
            (float *)&button_xy,
            &highscore_active_record,
            alpha,
            quest_results_highscore_rank_index + 1);
        goto done;
    }

    if (phase == 2) {
show_results:
        xy = results_base_xy;
        if (quest_results_anim_timer < 500) {
            quest_results_anim_timer += frame_dt_ms;
        } else {
            quest_results_anim_timer = 500;
        }
        float alpha =
            (float)quest_results_anim_timer * 0.002f;
        xy.x += 30.0f;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, alpha);
        if (quest_results_highscore_rank_index >= 100) {
            xy.y += 6.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                xy.x + 8.0f,
                xy.y,
                "Score too low for top%d.",
                100);
            xy.y += 6.0f;
        }

        quest_results_vec2_t record_xy;
        record_xy.x = xy.x;
        record_xy.y = xy.y + 16.0f;
        ui_text_input_render(
            (float *)&record_xy,
            &highscore_active_record,
            alpha,
            quest_results_highscore_rank_index + 1);
        xy.y += 78.0f;
        xy.y += 6.0f;

        if (quest_results_unlock_weapon_id != 0) {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.7f);
            grim_interface_ptr->grim_draw_text_small_fmt(
                xy.x, xy.y + 1.0f, "Weapon unlocked:");
            xy.y += 14.0f;
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.9f);
            grim_interface_ptr->grim_draw_text_small_fmt(
                xy.x,
                xy.y,
                "%s",
                weapon_table_entry(
                    quest_selected_meta[
                        quest_stage_minor
                        + quest_stage_major * 10
                        - 11]
                            .unlock_weapon_id));
            xy.y += 16.0f;
        }
        if (quest_results_unlock_perk_id != perk_id_antiperk) {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.7f);
            grim_interface_ptr->grim_draw_text_small_fmt(
                xy.x, xy.y + 1.0f, "Perk unlocked:");
            xy.y += 14.0f;
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.9f);
            int quest_index =
                quest_stage_minor + quest_stage_major * 10 - 11;
            int perk_id =
                quest_selected_meta[quest_index].unlock_perk_id;
            grim_interface_ptr->grim_draw_text_small_fmt(
                xy.x,
                xy.y,
                "%s",
                perk_meta_table[perk_id].name);
            xy.y += 16.0f;
        }

        static quest_results_button_t play_next_button;
        play_next_button.label = "Play Next";
        static quest_results_button_t play_again_button;
        play_again_button.label = "Play Again";
        static quest_results_button_t highscores_button;
        highscores_button.label = "High scores";
        static quest_results_button_t main_menu_button;
        main_menu_button.label = "Main Menu";

        xy.y += 6.0f;
        if (quest_stage_major == 5 && quest_stage_minor == 10) {
            play_next_button.label = "Show End Note";
        }
        play_next_button.alpha = alpha;
        highscores_button.alpha = alpha;
        xy.x += 20.0f;
        play_again_button.alpha = alpha;
        main_menu_button.alpha = alpha;
        ui_button_update(
            (float *)&xy,
            (ui_button_t *)&play_next_button);
        xy.y += 32.0f;
        ui_button_update(
            (float *)&xy,
            (ui_button_t *)&play_again_button);
        xy.y += 32.0f;
        ui_button_update(
            (float *)&xy,
            (ui_button_t *)&highscores_button);
        xy.y += 32.0f;
        ui_button_update(
            (float *)&xy,
            (ui_button_t *)&main_menu_button);
        xy.y += 32.0f;

        if (play_next_button.activated) {
            if (quest_stage_major == 5 && quest_stage_minor == 10) {
                render_pass_mode = 0;
                game_state_pending =
                    GAME_STATE_FINAL_QUEST_END_NOTE;
                ui_transition_direction = 0;
            } else {
                sfx_mute_all(music_track_extra_0);
                sfx_mute_all(music_track_crimson_theme_id);
                sfx_mute_all(music_track_shortie_monk_id);
                ui_transition_direction = 0;
                game_state_pending = GAME_STATE_GAMEPLAY;
                render_pass_mode = 0;
                ++quest_stage_minor;
            }
        }
        if (play_again_button.activated) {
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_GAMEPLAY;
            sfx_mute_all(music_track_crimson_theme_id);
            sfx_mute_all(music_track_shortie_monk_id);
            sfx_mute_all(music_track_extra_0);
            render_pass_mode = 0;
        }
        if (highscores_button.activated) {
            highscore_return_game_mode_id = config_game_mode;
            highscore_return_latch = 1;
            highscore_return_quest_stage_major = quest_stage_major;
            highscore_return_quest_stage_minor = quest_stage_minor;
            highscore_return_hardcore_flag = config_hardcore;
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_HIGHSCORES;
        }
        if (main_menu_button.activated) {
            sfx_mute_all(music_track_extra_0);
            sfx_mute_all(music_track_crimson_theme_id);
            sfx_mute_all(music_track_shortie_monk_id);
            sfx_play_exclusive(music_track_crimson_theme_id);
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_MAIN_MENU;
            ui_sign_crimson.focus_disabled = 0;
        }
    }

done:
    perk_prompt_update_and_render();
    ui_cursor_render();
}
