#include <math.h>

#include "crimsonland_gameplay.h"
#include "crimsonland_ui.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct credits_secret_vec2_t {
    float x;
    float y;

    credits_secret_vec2_t() {}
    credits_secret_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    credits_secret_vec2_t operator+(
        const credits_secret_vec2_t &other) const
    {
        return credits_secret_vec2_t(x + other.x, y + other.y);
    }

    credits_secret_vec2_t operator*(float scale) const
    {
        return credits_secret_vec2_t(x * scale, y * scale);
    }

    credits_secret_vec2_t &operator+=(
        const credits_secret_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }

    credits_secret_vec2_t &operator*=(float scale)
    {
        x *= scale;
        y *= scale;
        return *this;
    }
};

struct credits_secret_color_t {
    float r;
    float g;
    float b;
    float a;

    credits_secret_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value)
    {
    }
};

struct credits_secret_button_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    unsigned char padding;
    int hover_anim;
    int click_anim;
    float alpha;
    bool force_small;
    bool force_wide;
    unsigned char padding_tail[2];

    credits_secret_button_t()
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

    ~credits_secret_button_t() {}
};

extern "C" {
extern ui_element_t ui_element_slot_09;
extern creature_type_table_t creature_type_table;
extern int frame_dt_ms;
extern int credits_secret_selected_index;
extern int credits_secret_board[36];
extern int credits_secret_timer_ms;
extern int credits_secret_anim_time_ms;
extern int credits_secret_score;
extern unsigned char credits_secret_flags;
extern int sfx_ui_clink_01;
extern char menu_label_back[];
extern game_state_id_t game_state_pending;
extern unsigned char ui_transition_direction;

unsigned char credits_secret_match3_find(
    int board[][6], int *out_index, unsigned char *out_direction);
bool ui_button_update(float *xy, ui_button_t *button);
unsigned char input_primary_just_pressed(void);
}

extern "C" void credits_secret_alien_zookeeper_update(void)
{
    credits_secret_vec2_t panel_position =
        *(credits_secret_vec2_t *)&ui_element_slot_09.pos_x
        + *(credits_secret_vec2_t *)&ui_element_slot_09.vertices[0].x
        + credits_secret_vec2_t(300.0f, 40.0f);

    credits_secret_vec2_t board_position = panel_position;
    board_position.x =
        board_position.x
        + ui_element_slot_09.render_offset_x
        - 80.0f;
    board_position.y += 10.0f;
    credits_secret_vec2_t button_origin = board_position;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.8f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        board_position.x,
        board_position.y - 14.0f,
        "AlienZooKeeper");
    grim_interface_ptr->grim_set_config_var(0x18, 0.45f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        board_position.x + 12.0f,
        board_position.y + 10.0f,
        "a puzzle game unfinished");
    grim_interface_ptr->grim_draw_text_small_fmt(
        board_position.x + 18.0f,
        board_position.y + 23.0f,
        "..or something more?");
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.8f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.42f);

    credits_secret_anim_time_ms += frame_dt_ms;
    if (credits_secret_timer_ms > 0) {
        credits_secret_timer_ms -= frame_dt_ms;
        if (credits_secret_timer_ms <= 0) {
            sfx_play(sfx_trooper_die_01, 1.0f);
        }
    }
    if (credits_secret_timer_ms < 0) {
        credits_secret_timer_ms = 0;
    }

    board_position.y += 40.0f;
    board_position.x += 22.0f;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        board_position.x + 124.0f,
        board_position.y - 16.0f,
        "score: %d",
        credits_secret_score);

    {
        credits_secret_color_t color(0.0f, 0.0f, 0.0f, 0.6f);
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)&board_position,
            192.0f,
            192.0f,
            (float *)&color);
    }
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_draw_rect_outline(
        (float *)&board_position, 192.0f, 192.0f);

    int timer_width = credits_secret_timer_ms / 100;
    if (timer_width > 192) {
        timer_width = 192;
    }
    {
        credits_secret_vec2_t timer_position(
            board_position.x, board_position.y + 200.0f);
        credits_secret_color_t color(0.2f, 0.6f, 1.0f, 0.6f);
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)&timer_position,
            (float)timer_width,
            6.0f,
            (float *)&color);
    }
    {
        credits_secret_vec2_t timer_position(
            board_position.x, board_position.y + 200.0f);
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_draw_rect_outline(
            (float *)&timer_position, 192.0f, 6.0f);
    }

    int selected_row = 0;
    int selected_index = 0;
    do {
        int selected_column = 0;
        do {
            if (credits_secret_selected_index == selected_index) {
                credits_secret_vec2_t selected_position(
                    (float)selected_column,
                    (float)selected_row);
                selected_position *= 32.0f;
                selected_position += board_position;
                selected_position +=
                    credits_secret_vec2_t(4.0f, 4.0f);
                credits_secret_color_t color(
                    0.2f, 0.4f, 0.7f, 0.4f);
                grim_interface_ptr->grim_draw_rect_filled(
                    (float *)&selected_position,
                    24.0f,
                    24.0f,
                    (float *)&color);
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, 1.0f);
                grim_interface_ptr->grim_draw_rect_outline(
                    (float *)&selected_position, 24.0f, 24.0f);
            }
            ++selected_column;
            ++selected_index;
        } while (selected_column < 6);
        ++selected_row;
    } while (selected_index < 36);

    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_bind_texture(
        creature_type_table[2].texture_handle, 0);
    grim_interface_ptr->grim_set_rotation(0.0f);

    int row = 0;
    int row_y_offset = 0;
    int row_base_index = 0;
    int *cell = credits_secret_board;
    do {
        int column_x_offset = 0;
        int column = 0;
        do {
            int value = *cell;
            if (value != -3) {
                grim_interface_ptr->grim_set_atlas_frame(
                    8,
                    (credits_secret_anim_time_ms / 50 + value * 2)
                        % 32);
                if (*cell == 0) {
                    grim_interface_ptr->grim_set_color(
                        1.0f, 0.5f, 0.5f, 1.0f);
                } else if (*cell == 1) {
                    grim_interface_ptr->grim_set_color(
                        0.5f, 0.5f, 1.0f, 1.0f);
                } else if (*cell == 2) {
                    grim_interface_ptr->grim_set_color(
                        1.0f, 0.5f, 1.0f, 1.0f);
                } else if (*cell == 3) {
                    grim_interface_ptr->grim_set_color(
                        0.5f, 1.0f, 1.0f, 1.0f);
                } else if (*cell == 4) {
                    grim_interface_ptr->grim_set_color(
                        1.0f, 1.0f, 0.5f, 1.0f);
                }

                grim_interface_ptr->grim_draw_quad(
                    board_position.x + (float)column_x_offset,
                    board_position.y + (float)row_y_offset,
                    32.0f,
                    32.0f);

                if (credits_secret_timer_ms > 0) {
                    credits_secret_vec2_t hit_position =
                        credits_secret_vec2_t(
                            (float)column, (float)row)
                        * 32.0f
                        + board_position;
                    if ((unsigned char)ui_mouse_inside_rect(
                            (float *)&hit_position, 32, 32)
                        && input_primary_just_pressed()) {
                        sfx_play(sfx_ui_clink_01, 1.0f);
                        int old_selection =
                            credits_secret_selected_index;
                        if (old_selection != -1) {
                            int old_value = *cell;
                            *cell = credits_secret_board[old_selection];
                            credits_secret_board[old_selection] =
                                old_value;
                            credits_secret_selected_index = -1;

                            int match_index = 0;
                            unsigned char match_direction = 0;
                            if (credits_secret_match3_find(
                                    (int (*)[6])credits_secret_board,
                                    &match_index,
                                    &match_direction)) {
                                credits_secret_board[match_index] = -3;
                                if (match_direction) {
                                    credits_secret_board[
                                        match_index + 1] = -3;
                                    credits_secret_board[
                                        match_index + 2] = -3;
                                } else {
                                    credits_secret_board[
                                        match_index + 6] = -3;
                                    credits_secret_board[
                                        match_index + 12] = -3;
                                }
                                ++credits_secret_score;
                                sfx_play(sfx_ui_bonus, 1.0f);
                                credits_secret_timer_ms += 2000;
                            }
                        } else {
                            credits_secret_selected_index =
                                row_base_index + column;
                        }
                    }
                }
            }

            column_x_offset += 32;
            ++cell;
            ++column;
        } while (column_x_offset < 192);
        ++row;
        row_base_index += 6;
        row_y_offset += 32;
    } while ((int)cell < (int)(credits_secret_board + 36));

    grim_interface_ptr->grim_end_batch();

    if (credits_secret_timer_ms == 0) {
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_set_config_var(0x18, 1.0f);
        if ((float)cos(
                (float)credits_secret_anim_time_ms * 0.005f)
            > 0.0f) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                board_position.x + 38.0f,
                board_position.y + 96.0f - 22.0f,
                "Game Over");
        }
    }

    int *fill_cell = credits_secret_board;
    do {
        int fill_count = 6;
        do {
            if (*fill_cell == -1) {
                *fill_cell = crt_rand() % 5;
            }
            ++fill_cell;
            --fill_count;
        } while (fill_count != 0);
    } while ((int)fill_cell < (int)(credits_secret_board + 36));

    static credits_secret_button_t reset_button;
    reset_button.label = "Reset";
    credits_secret_vec2_t button_position(
        button_origin.x + 38.0f, button_origin.y + 256.0f);
    if (ui_button_update(
            (float *)&button_position,
            (ui_button_t *)&reset_button)) {
        int match_index = 0;
        unsigned char match_direction = 0;
        do {
            int *reroll_cell = credits_secret_board;
            do {
                int reroll_count = 6;
                do {
                    *reroll_cell = crt_rand() % 5;
                    ++reroll_cell;
                    --reroll_count;
                } while (reroll_count != 0);
            } while ((int)reroll_cell
                < (int)(credits_secret_board + 36));
        } while (credits_secret_match3_find(
            (int (*)[6])credits_secret_board,
            &match_index,
            &match_direction));

        credits_secret_selected_index = -1;
        credits_secret_score = 0;
        credits_secret_timer_ms = 9600;
    }

    static credits_secret_button_t back_button;
    back_button.label = menu_label_back;
    button_position.x = button_origin.x + 138.0f;
    button_position.y = button_origin.y + 256.0f;
    if (ui_button_update(
            (float *)&button_position,
            (ui_button_t *)&back_button)) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_STATISTICS_MENU;
    }
}
