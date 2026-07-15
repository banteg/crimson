#include <math.h>

#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct ui_text_input_state_t {
    unsigned char *text;
    int cursor;
    int max_chars;
    int width_px;
};

struct ui_text_vec2_t {
    float x;
    float y;

    ui_text_vec2_t() {}

    ui_text_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

struct ui_text_color_t {
    float r;
    float g;
    float b;
    float a;

    ui_text_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

extern "C" {
bool ui_focus_update(int id);
void ui_focus_draw(float *xy);
void ui_focus_set(int id, char reset_timer);
bool ui_mouse_inside_rect(float *xy, int h, int w);
int console_input_poll(void);
int crt_rand(void);
void sfx_play(int sfx_id, float volume);

extern float game_time_s;
extern int sfx_ui_typeclick_01;
extern int sfx_ui_typeenter;
}

extern "C" bool ui_text_input_update(
    float *xy,
    ui_text_input_state_t *input_state)
{
    ui_text_input_state_t *id = input_state;
    bool submitted = false;
    bool focused = ui_focus_update((int)id);
    float width = (float)id->width_px;

    if (ui_mouse_inside_rect(xy, 18, (int)width)) {
        ui_focus_set((int)id, 0);
    }

    ui_text_vec2_t position;
    if (focused) {
        position.set(xy[0] - 16.0f, xy[1]);
        ui_focus_draw((float *)&position);
    }

    id->text[id->cursor + 1] = 0;
    int key = console_input_poll();
    if (key == 13) {
        grim_interface_ptr->grim_was_key_pressed(28);
        grim_interface_ptr->grim_was_key_pressed(156);
        sfx_play(sfx_ui_typeenter, 1.0f);
        submitted = true;
    } else {
        grim_interface_ptr->grim_set_key_char_buffer(
            id->text,
            &id->cursor,
            id->max_chars);
        if (key) {
            sfx_play(sfx_ui_typeclick_01 + crt_rand() % 2, 1.0f);
        }
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_draw_rect_outline(xy, width, 18.0f);

    ui_text_color_t background(0.0f, 0.0f, 0.0f, 1.0f);
    position.set(xy[0] + 1.0f, xy[1] + 1.0f);
    grim_interface_ptr->grim_draw_rect_filled(
        (float *)&position, width - 2.0f, 16.0f, (float *)&background);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

    float max_text_width = width - 8.0f - 2.0f;
    int start = 0;
    int visible_width;
    while (true) {
        visible_width = grim_interface_ptr->grim_measure_text_width(
            (char *)&id->text[start]);
        if ((float)visible_width <= max_text_width) {
            break;
        }
        ++start;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.8f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        xy[0] + 4.0f,
        xy[1] + 2.0f,
        "%s",
        (char *)&id->text[start]);

    float cursor_alpha = 1.0f;
    const float cursor_blink_threshold = 0.0f;
    if ((float)sin(game_time_s * 4.0f) > cursor_blink_threshold) {
        cursor_alpha = 0.4f;
    }
    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, cursor_alpha);
    position.set(
        xy[0] + (float)visible_width + 4.0f,
        xy[1] + 2.0f);
    grim_interface_ptr->grim_draw_rect_outline(
        (float *)&position, 1.0f, 14.0f);

    return submitted;
}
