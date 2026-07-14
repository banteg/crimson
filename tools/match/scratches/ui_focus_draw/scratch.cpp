#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" int ui_focus_timer_ms;

struct ui_vec2_t {
    float x;
    float y;

    ui_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}
};

struct ui_color_t {
    float r;
    float g;
    float b;
    float a;

    ui_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

extern "C" void ui_focus_draw(float *xy)
{
    ui_color_t color(
        0.8f,
        0.8f,
        0.6f,
        (float)ui_focus_timer_ms * (0.8f / 1000.0f));
    ui_vec2_t pos(xy[0], xy[1] + 4.0f);
    grim_interface_ptr->grim_draw_rect_filled(
        (float *)&pos, 6.0f, 6.0f, (float *)&color);
}
