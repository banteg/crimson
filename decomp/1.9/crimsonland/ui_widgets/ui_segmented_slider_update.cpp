#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct ui_segmented_slider_t {
    int value;
    int max;
    int min;
    bool enabled;
};

struct ui_slider_point_t {
    float x;
    float y;
};

struct ui_slider_vec2_t {
    float x;
    float y;

    ui_slider_vec2_t() {}

    ui_slider_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

extern "C" {
bool ui_focus_update(int id);
void ui_focus_draw(float *xy);
void ui_focus_set(int id, char reset_timer);
bool ui_mouse_inside_rect(float *xy, int h, int w);
bool input_primary_is_down(void);

extern float ui_mouse_x;
extern int ui_segmented_slider_tex_on;
extern int ui_segmented_slider_tex_off;
}

extern "C" void ui_segmented_slider_update(
    ui_slider_point_t *xy,
    ui_segmented_slider_t *state)
{
    bool focused = ui_focus_update((int)state);
    bool hovered = false;
    float slider_width = (float)(state->max * 8);
    ui_slider_point_t draw_position = *xy;
    {
        ui_slider_vec2_t position(xy->x - 3.0f, xy->y - 1.0f);

        if (ui_mouse_inside_rect(
                (float *)&position, 18, (int)(slider_width + 6.0f))) {
            hovered = true;
            ui_focus_set((int)state, 0);
        }

        if (focused) {
            position.set(xy->x - 16.0f, xy->y);
            ui_focus_draw((float *)&position);
            if (state->enabled) {
                if (grim_interface_ptr->grim_was_key_pressed(205)) {
                    ++state->value;
                    if (state->value > state->max) {
                        state->value = state->max;
                    }
                }
                if (grim_interface_ptr->grim_was_key_pressed(203)) {
                    --state->value;
                    if (state->value < 0) {
                        state->value = 0;
                    }
                }
            }
        }
    }

    if (hovered && input_primary_is_down() && state->enabled) {
        state->value = (int)((ui_mouse_x - xy->x) * 0.125f);
        if (state->value < state->min) {
            state->value = state->min;
        }
        if (state->value > state->max) {
            state->value = state->max;
        }
    }

    if (ui_segmented_slider_tex_on == -1) {
        ui_segmented_slider_tex_on =
            grim_interface_ptr->grim_get_texture_handle("ui_rectOn");
    }
    if (ui_segmented_slider_tex_off == -1) {
        ui_segmented_slider_tex_off =
            grim_interface_ptr->grim_get_texture_handle("ui_rectOff");
    }

    grim_interface_ptr->grim_bind_texture(ui_segmented_slider_tex_off, 0);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.5f);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);

    int i = 0;
    if (i < state->max) {
        int offset = 0;
        do {
            grim_interface_ptr->grim_draw_quad(
                draw_position.x + (float)offset,
                draw_position.y,
                8.0f,
                16.0f);
            ++i;
            offset += 8;
        } while (i < state->max);
    }
    grim_interface_ptr->grim_end_batch();

    if (state->value > 0) {
        grim_interface_ptr->grim_bind_texture(ui_segmented_slider_tex_on, 0);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

        i = 0;
        if (i < state->value) {
            int offset = 0;
            do {
                grim_interface_ptr->grim_draw_quad(
                    draw_position.x + (float)offset,
                    draw_position.y,
                    8.0f,
                    16.0f);
                ++i;
                offset += 8;
            } while (i < state->value);
        }
        grim_interface_ptr->grim_end_batch();
    }
}
