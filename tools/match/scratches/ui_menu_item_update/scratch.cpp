#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct ui_menu_item_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
};

struct ui_menu_vec2_t {
    float x;
    float y;

    ui_menu_vec2_t() {}

    ui_menu_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

struct ui_menu_color_t {
    float r;
    float g;
    float b;
    float a;

    ui_menu_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}

    ~ui_menu_color_t() {}
};

extern "C" {
bool ui_focus_update(int id);
void ui_focus_draw(float *xy);
void ui_focus_set(int id, char reset_timer);
bool ui_mouse_inside_rect(float *xy, int h, int w);
bool input_primary_just_pressed(void);
void sfx_play(int sfx_id, float volume);

extern int sfx_ui_buttonclick;
}

extern "C" bool ui_menu_item_update(float *xy, ui_menu_item_t *item)
{
    bool focused = ui_focus_update((int)item);
    static ui_menu_color_t idle_color(
        0.274509817f, 0.70588237f, 0.941176474f, 0.600000024f);
    static ui_menu_color_t hover_color(
        0.274509817f, 0.70588237f, 0.941176474f, 1.0f);

    ui_menu_vec2_t draw_position;
    if (focused) {
        draw_position.set(xy[0] - 16.0f, xy[1]);
        ui_focus_draw((float *)&draw_position);
    }

    float width = (float)grim_interface_ptr->grim_measure_text_width(item->label);
    if (width <= 0.0f) {
        width = 8.0f;
    }

    item->hovered = ui_mouse_inside_rect(xy, 16, (int)width);
    if (item->hovered) {
        ui_focus_set((int)item, 0);
        grim_interface_ptr->grim_set_color_ptr((float *)&hover_color);
    } else {
        grim_interface_ptr->grim_set_color_ptr((float *)&idle_color);
    }

    grim_interface_ptr->grim_draw_text_small_fmt(
        xy[0], xy[1], "%s", item->label);
    grim_interface_ptr->grim_begin_batch();
    draw_position.set(xy[0], xy[1] + 13.0f);
    grim_interface_ptr->grim_draw_rect_outline(
        (float *)&draw_position, width, 1.0f);
    grim_interface_ptr->grim_end_batch();

    if (item->enabled) {
        item->activated =
            focused
            && (grim_interface_ptr->grim_was_key_pressed(28)
                || (item->hovered && input_primary_just_pressed()));
    } else {
        item->activated = 0;
    }

    if (item->activated) {
        sfx_play(sfx_ui_buttonclick, 1.0f);
    }
    return item->activated;
}
