#include <string.h>

#include "crimsonland_ui.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct scrollbar_vec2_t {
    float x;
    float y;

    scrollbar_vec2_t() {}
    scrollbar_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    scrollbar_vec2_t operator+(const scrollbar_vec2_t &other) const
    {
        return scrollbar_vec2_t(x + other.x, y + other.y);
    }
};

struct scrollbar_color_t {
    float r;
    float g;
    float b;
    float a;

    scrollbar_color_t() {}
    scrollbar_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value)
    {
    }
};

extern "C" {
extern unsigned char ui_scrollbar_drag_active;
extern float ui_scrollbar_drag_offset;

unsigned char ui_focus_update(int id);
void ui_focus_draw(float *xy);
unsigned char input_primary_just_pressed(void);
unsigned char input_primary_is_down(void);
}

extern "C" void ui_scrollbar_update(
    vec2f_t *xy, ui_scrollbar_t *state)
{
    xy->x = (float)(int)xy->x;
    xy->y = (float)(int)xy->y;
    state->hovered_index = -1;

    unsigned char focused = ui_focus_update((int)state);
    if (focused) {
        scrollbar_vec2_t position(xy->x - 16.0f, xy->y);
        ui_focus_draw((float *)&position);
    }

    int first_item;
    {
    float height = (float)(state->visible_rows * 16 + 4);
    {
        scrollbar_color_t color(1.0f, 1.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)xy, 250.0f, height, (float *)&color);
    }

    float interior_height;
    {
        scrollbar_vec2_t position(xy->x + 1.0f, xy->y + 1.0f);
        scrollbar_color_t color(0.0f, 0.0f, 0.0f, 1.0f);
        interior_height = height - 2.0f;
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)&position,
            248.0f,
            interior_height,
            (float *)&color);
    }

    if (state->item_count > state->visible_rows) {
        scrollbar_vec2_t position(xy->x + 240.0f, xy->y);
        scrollbar_color_t color(1.0f, 1.0f, 1.0f, 0.8f);
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)&position, 1.0f, height, (float *)&color);
    }

    if (grim_interface_ptr->grim_get_mouse_wheel_delta() > 0.0f) {
        state->scroll_offset -= 1.0f;
    }
    if (grim_interface_ptr->grim_get_mouse_wheel_delta() < 0.0f) {
        state->scroll_offset += 1.0f;
    }

    if (focused) {
        if (grim_interface_ptr->grim_was_key_pressed(200)) {
            state->scroll_offset -= 1.0f;
        }
        if (grim_interface_ptr->grim_was_key_pressed(208)) {
            state->scroll_offset += 1.0f;
        }
    }
    if (grim_interface_ptr->grim_was_key_pressed(201)) {
        state->scroll_offset -= (float)(state->visible_rows - 1);
    }
    if (grim_interface_ptr->grim_was_key_pressed(209)) {
        state->scroll_offset += (float)(state->visible_rows - 1);
    }

    int item_count = state->item_count;
    int visible_rows = state->visible_rows;
    int max_scroll = item_count - visible_rows;
    if ((float)max_scroll < state->scroll_offset) {
        state->scroll_offset = (float)max_scroll;
    }
    if (state->scroll_offset < 0.0f) {
        state->scroll_offset = 0.0f;
    }

    first_item = (int)state->scroll_offset;
    float thumb_height =
        (float)visible_rows / (float)item_count * interior_height;
    if (thumb_height > interior_height) {
        thumb_height = height - 3.0f;
    }
    float thumb_y =
        (height - 3.0f - thumb_height) / (float)max_scroll
            * (float)first_item
        + 1.0f + xy->y;
    scrollbar_vec2_t thumb_position;
    thumb_position.y = thumb_y;
    thumb_position.x = xy->x + 241.0f;

    if (item_count > visible_rows) {
        {
            scrollbar_color_t color(1.0f, 1.0f, 1.0f, 0.8f);
            grim_interface_ptr->grim_draw_rect_filled(
                (float *)&thumb_position,
                8.0f,
                thumb_height + 1.0f,
                (float *)&color);
        }

        unsigned char track_hovered;
        {
            scrollbar_vec2_t track_position(xy->x + 240.0f, xy->y);
            track_hovered = (unsigned char)ui_mouse_inside_rect(
                (float *)&track_position, (int)height, 10);
        }
        if (track_hovered) {
            {
                scrollbar_vec2_t fill_position =
                    thumb_position + scrollbar_vec2_t(1.0f, 1.0f);
                scrollbar_color_t color(0.2f, 0.4f, 0.8f, 1.0f);
                grim_interface_ptr->grim_draw_rect_filled(
                    (float *)&fill_position,
                    6.0f,
                    thumb_height - 1.0f,
                    (float *)&color);
            }
            ui_scrollbar_drag_active = 1;
            if (input_primary_just_pressed()) {
                if ((unsigned char)ui_mouse_inside_rect(
                        (float *)&thumb_position, (int)thumb_height, 8)) {
                    ui_scrollbar_drag_offset =
                        ui_mouse_y - xy->y
                        - state->scroll_offset
                            / (float)state->item_count * height;
                } else {
                    ui_scrollbar_drag_offset = 0.0f;
                }
            }
        } else {
            {
                scrollbar_vec2_t fill_position(
                    thumb_position.x + 1.0f, thumb_position.y + 1.0f);
                scrollbar_color_t color(0.1f, 0.2f, 0.4f, 1.0f);
                grim_interface_ptr->grim_draw_rect_filled(
                    (float *)&fill_position,
                    6.0f,
                    thumb_height - 1.0f,
                    (float *)&color);
            }
            if (!input_primary_is_down()) {
                ui_scrollbar_drag_active = 0;
            }
        }

        if (ui_scrollbar_drag_active && input_primary_is_down()) {
            float scroll_offset =
                (ui_mouse_y - xy->y - ui_scrollbar_drag_offset)
                / height * (float)state->item_count;
            state->scroll_offset = scroll_offset;
            float max_offset =
                (float)(state->item_count - state->visible_rows);
            if (scroll_offset > max_offset) {
                state->scroll_offset = max_offset;
            }
            if (state->scroll_offset < 0.0f) {
                state->scroll_offset = 0.0f;
            }
        }
    }

    }

    scrollbar_vec2_t row_position(xy->x - 2.0f, xy->y);
    int row = 0;
    if (state->visible_rows <= 0) {
        return;
    }

    int item_index = first_item;
    int item_offset = first_item * 4;
    do {
        if (row >= state->item_count) {
            return;
        }

        float alpha;
        if ((unsigned char)ui_mouse_inside_rect(
                (float *)&row_position, 17, 240)) {
            alpha = 1.0f;
            state->hovered_index = item_index;
            if (input_primary_just_pressed()) {
                state->selected_index = item_index;
            }
        } else {
            alpha = 0.9f;
            if (state->selected_index != item_index) {
                alpha = 0.7f;
            }
        }

        char *text =
            *(char **)((char *)state->items + item_offset);
        if (text[0] == '\\') {
            if (text[1] == 'g') {
                grim_interface_ptr->grim_set_color(
                    0.7f, 1.0f, 0.7f, alpha);
                text += 2;
            }
        } else {
            grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
        }

        int text_length = strlen(text) + 1;
        int cursor = 0;
        int column = 0;
        if (text_length > 0) {
            do {
                if (text[cursor] == '\t' || text[cursor] == '\0') {
                    text[cursor] = '\0';
                    int x_offset =
                        state->column_offsets[column] * column;
                    grim_interface_ptr->grim_draw_text_small(
                        row_position.x + (float)x_offset + 8.0f,
                        row_position.y + 2.0f,
                        text);

                    ++column;
                    ++cursor;
                    text += cursor;
                    text_length -= cursor;
                    cursor = 0;
                }
                ++cursor;
            } while (cursor < text_length);
        }

        row_position.y += 16.0f;
        ++row;
        item_offset += 4;
        ++item_index;
    } while (row < state->visible_rows);
}
