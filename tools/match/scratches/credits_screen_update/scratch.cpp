#include <string.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct credits_vec2_t {
    float x;
    float y;

    credits_vec2_t() {}

    credits_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}

    credits_vec2_t operator+(const credits_vec2_t &other) const {
        return credits_vec2_t(x + other.x, y + other.y);
    }

    credits_vec2_t &operator+=(const credits_vec2_t &other) {
        x += other.x;
        y += other.y;
        return *this;
    }

    void set(float x_value, float y_value) {
        x = x_value;
        y = y_value;
    }
};

struct credits_button_t {
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

    credits_button_t() {
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

    ~credits_button_t() {}
};

extern "C" {
extern int ui_screen_phase;
extern ui_element_t ui_element_slot_09;
extern game_state_id_t game_state_pending;
extern unsigned char ui_transition_direction;
extern float credits_scroll_time_s;
extern int credits_scroll_line_start_index;
extern int credits_scroll_line_end_index;
extern int credits_secret_line_base_index;
extern unsigned char credits_secret_unlock_flag;

void credits_build_lines(void);
void credits_line_clear_flag(int index);
bool ui_button_update(float *xy, ui_button_t *button);
bool ui_mouse_inside_rect(float *xy, int height, int width);
bool input_primary_just_pressed(void);
void ui_callback_noop(void);
}

extern "C" void credits_screen_update(void) {
    static credits_button_t back_button;
    static credits_button_t secret_button;

    credits_vec2_t panel_position =
        *(credits_vec2_t *)&ui_element_slot_09.pos_x +
        *(credits_vec2_t *)&ui_element_slot_09.vertices[0].x;
    panel_position += credits_vec2_t(300.0f, 40.0f);
    credits_vec2_t position = panel_position;

    secret_button.label = "Secret";
    position.x =
        panel_position.x + ui_element_slot_09.render_offset_x + 48.0f - 110.0f;
    position.y += 10.0f;
    position.x -= 40.0f;

    if (ui_screen_phase == 0) {
        ui_screen_phase = 1;
        credits_build_lines();
        credits_scroll_time_s = 0.0f;
        credits_scroll_line_start_index = 0;
    } else if (ui_screen_phase == 1) {
        credits_vec2_t hit_position;
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

        if (credits_scroll_line_start_index > credits_line_max_index + 2) {
            credits_scroll_time_s = 0.0f;
            credits_scroll_line_start_index = 0;
        }

        position.y -= 4.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(position.x + 4.0f,
                                                     position.y, "credits");
        position.y += 20.0f;
        position.y -= 6.0f;

        credits_scroll_time_s += frame_dt;
        int whole_line = (int)credits_scroll_time_s;
        credits_scroll_line_start_index = whole_line - 15;
        credits_scroll_line_end_index = credits_scroll_line_start_index + 16;
        if (credits_scroll_line_end_index > credits_line_max_index) {
            credits_scroll_line_end_index = credits_line_max_index;
        }

        float scroll_offset = credits_scroll_time_s * 16.0f;
        while (scroll_offset > 16.0f) {
            scroll_offset -= 16.0f;
        }

        int row = 0;
        if (credits_scroll_line_end_index - credits_scroll_line_start_index >
            0) {
            int line_offset = 0;
            do {
                int index = credits_scroll_line_start_index + row;
                if (index < 0) {
                    index = 0;
                }

                int width = grim_interface_ptr->grim_measure_text_width(
                    credits_line_table[index].text);
                float line_y = (float)line_offset + position.y - scroll_offset;

                float alpha;
                float edge_y = position.y - 16.0f + 24.0f;
                if (line_y < edge_y) {
                    alpha = 1.0f - (edge_y - line_y) / 24.0f;
                } else {
                    edge_y = (float)((credits_scroll_line_end_index -
                                      credits_scroll_line_start_index - 1) *
                                     16) +
                             position.y - 24.0f;
                    if (line_y > edge_y) {
                        alpha = (edge_y - line_y) / 24.0f + 1.0f;
                    } else {
                        alpha = 1.0f;
                    }
                }

                if (alpha > 1.0f) {
                    alpha = 1.0f;
                } else if (alpha < 0.0f) {
                    alpha = 0.0f;
                }

                hit_position.x = position.x + 140.0f - (float)(width / 2);
                hit_position.y = line_y;
                if (ui_mouse_inside_rect((float *)&hit_position, 16, width) &&
                    input_primary_just_pressed()) {
                    if (strchr(credits_line_table[index].text, 'o') != 0) {
                        if ((credits_line_table[index].flags & 4) == 0) {
                            sfx_play(sfx_ui_bonus, 1.0f);
                        }
                        credits_line_table[index].flags |= 4;
                    } else {
                        credits_line_clear_flag(index);
                    }
                }

                int flags = credits_line_table[index].flags;
                if ((flags & 4) != 0) {
                    if ((flags & 1) != 0) {
                        grim_interface_ptr->grim_set_color(0.9f, 1.0f, 0.9f,
                                                           alpha);
                    } else {
                        grim_interface_ptr->grim_set_color(0.4f, 0.7f, 0.7f,
                                                           alpha);
                    }
                } else {
                    if ((flags & 1) != 0) {
                        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f,
                                                           alpha);
                    } else {
                        grim_interface_ptr->grim_set_color(0.4f, 0.5f, 0.7f,
                                                           alpha);
                    }
                }

                grim_interface_ptr->grim_draw_text_small(
                    position.x + 140.0f - (float)(width / 2), line_y,
                    credits_line_table[index].text);

                ++row;
                line_offset += 16;
            } while (row < credits_scroll_line_end_index -
                               credits_scroll_line_start_index);
        }

        position.x += 100.0f;
        back_button.label = "Back";
        position.y += 250.0f;
        ui_button_update((float *)&position, (ui_button_t *)&back_button);

        credits_line_t *line = credits_line_table;
        while ((int)line < (int)(credits_line_table + 0x100)) {
            if (line->text != 0 && strchr(line->text, 'o') != 0 &&
                (line->flags & 4) == 0) {
                goto check_actions;
            }
            ++line;
        }

        if (!credits_secret_unlock_flag) {
            credits_secret_unlock_flag = 1;
            int index = credits_secret_line_base_index;

            credits_line_table[index].flags |= 4;
            credits_line_table[++index].flags |= 4;
            credits_line_table[++index].flags |= 4;
            credits_line_table[++index].flags |= 4;
            credits_line_table[++index].flags |= 4;
            credits_line_table[++index].flags |= 4;
            credits_line_table[++index].flags |= 4;
            credits_line_table[++index].flags |= 4;
            credits_line_table[++index].flags |= 4;
            credits_line_table[++index].flags |= 4;

            index = credits_secret_line_base_index;

            credits_line_table[index].text =
                strdup_malloc("Inside Dead Let Mighty Blood");
            credits_line_table[++index].text =
                strdup_malloc("Do Firepower See Mark Of");
            credits_line_table[++index].text =
                strdup_malloc("The Sacrifice Old Center");
            credits_line_table[++index].text =
                strdup_malloc("Yourself Ground First For");
            credits_line_table[++index].text =
                strdup_malloc("Triangle Cube Last Not Flee");
            credits_line_table[++index].text =
                strdup_malloc("0001001110000010101110011");
            credits_line_table[++index].text =
                strdup_malloc("0101001011100010010101100");
            credits_line_table[++index].text = strdup_malloc("011111001000111");
            credits_line_table[++index].text =
                strdup_malloc("(4 bits for index) <- OOOPS I meant FIVE!");
            crt_free(credits_line_table[++index].text);
            credits_line_table[index].text =
                strdup_malloc("(4 bits for index)");
        }

        hit_position.set(position.x + 94.0f, position.y);
        ui_button_update((float *)&hit_position, (ui_button_t *)&secret_button);
    }

check_actions:
    if (back_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_STATISTICS_MENU;
        ui_callback_noop();
    }
    if (secret_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_CREDITS_SECRET;
        ui_callback_noop();
    }
    if (grim_interface_ptr->grim_was_key_pressed(1)) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_STATISTICS_MENU;
        ui_callback_noop();
    }
}
