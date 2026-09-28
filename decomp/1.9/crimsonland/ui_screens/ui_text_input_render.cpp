#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

struct highscore_card_pos_t {
    float x;
    float y;

    highscore_card_pos_t() {}
    highscore_card_pos_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct highscore_card_color_t {
    float r;
    float g;
    float b;
    float a;
};

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern float render_tint_color_r;

extern float highscore_card_divider_color_r;
extern char highscore_card_text_buffer[];

extern int ui_screen_phase;
extern int ui_weapon_icons_texture;
extern float ui_stats_hover_weapon;
extern float ui_stats_hover_time;
extern float ui_stats_hover_hit_ratio;

char *highscore_format_date_label(int day, int month_index, int year);
char *format_ordinal(int value);
void highscore_card_draw_horizontal_divider(float *xy);
void highscore_card_draw_vertical_divider(float *xy);
void ui_draw_clock_gauge(int x, int y, int time_ms, float alpha);
int crt_sprintf(char *dst, const char *format, ...);
}

static __inline void highscore_card_update_hover(
    float &hover,
    bool inside)
{
    if (inside) {
        hover += frame_dt + frame_dt;
    } else {
        hover -= frame_dt + frame_dt;
    }
}

static __inline void highscore_card_clamp_hover(float &hover)
{
    if (hover > 1.0f) {
        hover = 1.0f;
    } else if (hover < 0.0f) {
        hover = 0.0f;
    }
}

extern "C" void ui_text_input_render(
    float *xy,
    highscore_record_t *record,
    float alpha,
    int rank)
{
    highscore_card_color_t &render_tint =
        *(highscore_card_color_t *)&render_tint_color_r;
    highscore_card_color_t &divider_tint =
        *(highscore_card_color_t *)&highscore_card_divider_color_r;

    render_tint.a = 0.7f;
    divider_tint = render_tint;
    float tooltip_alpha = alpha * 0.7f;
    divider_tint.a = tooltip_alpha;

    int player_name_width =
        grim_interface_ptr->grim_measure_text_width(record->player_name);
    highscore_card_pos_t position;
    position.x = xy[0] + 4.0f;
    position.y = xy[1];

    if (game_state_id != GAME_STATE_GAME_OVER
        && game_state_id != GAME_STATE_QUEST_RESULTS
        && game_state_id != GAME_STATE_QUEST_FAILED) {
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
        grim_interface_ptr->grim_draw_text_small(
            position.x, position.y, record->player_name);

        grim_interface_ptr->grim_set_color_ptr(
            &highscore_card_divider_color_r);
        highscore_card_pos_t underline(
            position.x, position.y + 13.0f);
        grim_interface_ptr->grim_draw_rect_outline(
            (float *)&underline, (float)player_name_width, 1.0f);

        if ((record->flags & 2) != 0) {
            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, alpha * 0.8f);
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x,
                position.y + 14.0f,
                "Internet score of local origin");
            grim_interface_ptr->grim_set_color(
                0.5f, 0.5f, 0.5f, alpha * 0.5f);
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 94.0f,
                position.y - 12.0f,
                "uni#%d",
            record->random_tag);
            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, alpha * 0.8f);
        } else {
            if ((record->flags & 1) != 0) {
                grim_interface_ptr->grim_set_color(
                    0.7f, 1.0f, 0.7f, alpha * 0.8f);
                grim_interface_ptr->grim_draw_text_small_fmt(
                    position.x,
                    position.y + 14.0f,
                    "Score from the Internet");
            } else {
                grim_interface_ptr->grim_set_color(
                    0.8f, 0.8f, 0.8f, alpha * 0.8f);
                grim_interface_ptr->grim_draw_text_small_fmt(
                    position.x,
                    position.y + 14.0f,
                    "Local score");
            }
        }

        position.y += 15.0f;
        grim_interface_ptr->grim_set_color(
            0.9f, 0.9f, 0.9f, alpha * 0.8f);
        grim_interface_ptr->grim_draw_text_small(
            position.x + 192.0f - 32.0f - 8.0f
                - grim_interface_ptr->grim_measure_text_width(
                      highscore_format_date_label(
                          record->day,
                          record->month,
                          record->year_offset + 2000))
                    / 2,
            position.y + 13.0f,
            highscore_format_date_label(
                record->day,
                record->month,
                record->year_offset + 2000));

        position.y += 13.0f;
        position.x = xy[0] + 16.0f;
        highscore_card_draw_horizontal_divider((float *)&position);
        position.y += 14.0f;
    }

    float label_alpha = alpha * 0.8f;
    grim_interface_ptr->grim_set_color(
        0.9f, 0.9f, 0.9f, label_alpha);
    grim_interface_ptr->grim_draw_text_small(
        position.x + 32.0f
            - grim_interface_ptr->grim_measure_text_width("Score") / 2,
        position.y,
        "Score");

    if (record->game_mode_id == GAME_MODE_RUSH) {
        crt_sprintf(
            highscore_card_text_buffer,
            "%.2f secs",
            (float)(int)record->survival_elapsed_ms * 0.001f);
    } else if (record->game_mode_id == GAME_MODE_QUEST) {
        crt_sprintf(
            highscore_card_text_buffer,
            "%.2f secs",
            (float)(int)record->survival_elapsed_ms * 0.001f);
    } else {
        crt_sprintf(
            highscore_card_text_buffer, "%d", record->score_xp);
    }

    grim_interface_ptr->grim_set_color(0.9f, 0.9f, 1.0f, alpha);
    int score_width = grim_interface_ptr->grim_measure_text_width(
        highscore_card_text_buffer);
    grim_interface_ptr->grim_draw_text_small(
        position.x + 32.0f - score_width / 2,
        position.y + 15.0f,
        highscore_card_text_buffer);

    if (game_state_id != GAME_STATE_QUEST_FAILED) {
        crt_sprintf(
            highscore_card_text_buffer, "Rank: %s", format_ordinal(rank));
        int rank_width = grim_interface_ptr->grim_measure_text_width(
            highscore_card_text_buffer);
        grim_interface_ptr->grim_set_color(
            0.9f, 0.9f, 0.9f, label_alpha);
        grim_interface_ptr->grim_draw_text_small(
            position.x + 32.0f - rank_width / 2,
            position.y + 30.0f,
            highscore_card_text_buffer);
    }

    position.x += 96.0f;
    highscore_card_draw_vertical_divider((float *)&position);
    if (record->game_mode_id == GAME_MODE_QUEST) {
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "Experience");
        crt_sprintf(
            highscore_card_text_buffer, "%d", record->score_xp);
        int experience_width = grim_interface_ptr->grim_measure_text_width(
            highscore_card_text_buffer);
        grim_interface_ptr->grim_set_color(
            0.9f, 0.9f, 0.9f, label_alpha);
        grim_interface_ptr->grim_draw_text_small(
            position.x + 32.0f - experience_width / 2,
            position.y + 15.0f,
            highscore_card_text_buffer);
        ui_stats_hover_time -= frame_dt + frame_dt;
    } else {
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 6.0f, position.y, "Game time");
        ui_draw_clock_gauge(
            (int)(position.x + 8.0f),
            (int)(position.y + 13.0f),
            record->survival_elapsed_ms,
            alpha);
        highscore_card_update_hover(
            ui_stats_hover_time,
            position.x + 8.0f < ui_mouse_x
                && position.x + 72.0f > ui_mouse_x
                && position.y + 16.0f < ui_mouse_y
                && position.y + 45.0f > ui_mouse_y);

        grim_interface_ptr->grim_set_color(
            0.9f, 0.9f, 0.9f, label_alpha);
        int elapsed_seconds =
            (int)record->survival_elapsed_ms / 1000;
        int elapsed_minutes = elapsed_seconds / 60;
        elapsed_seconds %= 60;
        if (elapsed_seconds < 10) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 40.0f,
                position.y + 19.0f,
                "%d:0%d",
                elapsed_minutes,
                elapsed_seconds);
        } else {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 40.0f,
                position.y + 19.0f,
                "%d:%d",
                elapsed_minutes,
                elapsed_seconds);
        }
    }

    position.y += 52.0f;
    position.x -= 96.0f;
    if (!((ui_screen_phase == 2
           && game_state_id == GAME_STATE_QUEST_RESULTS)
          || ((game_state_id == GAME_STATE_GAME_OVER
               || game_state_id == GAME_STATE_QUEST_RESULTS
               || game_state_id == GAME_STATE_QUEST_FAILED)
              && ui_screen_phase == 0))) {
        highscore_card_draw_horizontal_divider((float *)&position);
        grim_interface_ptr->grim_bind_texture(
            ui_weapon_icons_texture, 0);
        grim_interface_ptr->grim_set_config_var(0x15, 1u);
        grim_interface_ptr->grim_set_sub_rect(
            8,
            2,
            1,
            weapon_table[record->most_used_weapon_id].hud_icon_id * 2);
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, alpha);
        grim_interface_ptr->grim_draw_quad(
            (float)(int)position.x,
            (float)(int)position.y,
            64.0f,
            32.0f);
        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_config_var(0x15, 2u);

        if (ui_mouse_x <= position.x
            || position.x + 64.0f <= ui_mouse_x
            || ui_mouse_y <= position.y
            || position.y + 32.0f <= ui_mouse_y) {
            ui_stats_hover_weapon -= frame_dt + frame_dt;
        } else {
            ui_stats_hover_weapon += frame_dt + frame_dt;
        }

        grim_interface_ptr->grim_set_color(
            0.9f, 0.9f, 0.9f, tooltip_alpha);
        int weapon_name_x = 32
            - grim_interface_ptr->grim_measure_text_width(
                  weapon_table[record->most_used_weapon_id].name)
                / 2;
        float weapon_name_offset = (float)weapon_name_x;
        if (weapon_name_offset < 0.0f) {
            weapon_name_offset = 0.0f;
        }
        grim_interface_ptr->grim_draw_text_small(
            position.x + weapon_name_offset,
            position.y + 32.0f,
            weapon_table[record->most_used_weapon_id].name);
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 110.0f,
            position.y + 1.0f,
            "Frags: %d",
            record->creature_kill_count);
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 110.0f,
            position.y + 16.0f - 1.0f,
            "Hit %%: %d%%",
            (int)((int)record->shots_hit * 100.0f
                  / (int)record->shots_fired));

        highscore_card_update_hover(
            ui_stats_hover_hit_ratio,
            position.x + 110.0f < ui_mouse_x
                && position.x + 174.0f > ui_mouse_x
                && position.y + 16.0f - 1.0f < ui_mouse_y
                && position.y + 32.0f > ui_mouse_y);
        position.y += 48.0f;
    } else {
        ui_stats_hover_hit_ratio = 0.0f;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    highscore_card_draw_horizontal_divider((float *)&position);

    highscore_card_clamp_hover(ui_stats_hover_weapon);
    highscore_card_clamp_hover(ui_stats_hover_time);
    highscore_card_clamp_hover(ui_stats_hover_hit_ratio);

    if (game_state_id == GAME_STATE_GAME_OVER
        || game_state_id == GAME_STATE_QUEST_RESULTS
        || game_state_id == GAME_STATE_QUEST_FAILED) {
        grim_interface_ptr->grim_set_color(
            0.9f, 0.9f, 0.9f, tooltip_alpha);
        if (ui_stats_hover_weapon > 0.5f) {
            float hover_alpha =
                (ui_stats_hover_weapon - 0.5f) * alpha * 2.0f;
            grim_interface_ptr->grim_set_color(
                0.9f, 0.9f, 0.9f, hover_alpha);
            grim_interface_ptr->grim_draw_text_small(
                position.x - 20.0f,
                position.y,
                "Most used weapon during the game");
        }
        if (ui_stats_hover_time > 0.5f) {
            float hover_alpha =
                (ui_stats_hover_time - 0.5f) * alpha * 2.0f;
            grim_interface_ptr->grim_set_color(
                0.9f, 0.9f, 0.9f, hover_alpha);
            grim_interface_ptr->grim_draw_text_small(
                position.x + 12.0f,
                position.y,
                "The time the game lasted");
        }
        if (ui_stats_hover_hit_ratio > 0.5f) {
            float hover_alpha =
                (ui_stats_hover_hit_ratio - 0.5f) * alpha * 2.0f;
            grim_interface_ptr->grim_set_color(
                0.9f, 0.9f, 0.9f, hover_alpha);
            grim_interface_ptr->grim_draw_text_small(
                position.x - 22.0f,
                position.y,
                "The % of shot bullets hit the target");
        }
    }
}
