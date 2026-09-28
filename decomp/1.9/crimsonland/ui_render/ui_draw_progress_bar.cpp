#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct ui_vec2_t {
    float x;
    float y;
    ui_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}

    void set(float x_value, float y_value) {
        x = x_value;
        y = y_value;
    }
};

struct ui_color_t {
    float r;
    float g;
    float b;
    float a;

    ui_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

extern "C" void ui_draw_progress_bar(
    float *xy, float width, float ratio, float *rgba)
{
    if (ratio < 0.0f) {
        ratio = 0.0f;
    } else if (ratio > 1.0f) {
        ratio = 1.0f;
    }

    ui_color_t background(
        rgba[0] * 0.6f,
        rgba[1] * 0.6f,
        rgba[2] * 0.6f,
        rgba[3] * 0.4f);
    ui_vec2_t pos(xy[0], xy[1]);
    grim_interface_ptr->grim_draw_rect_filled(
        (float *)&pos, width, 4.0f, (float *)&background);

    pos.set(xy[0] + 1.0f, xy[1] + 1.0f);
    grim_interface_ptr->grim_draw_rect_filled(
        (float *)&pos, (width - 2.0f) * ratio, 2.0f, rgba);
}
