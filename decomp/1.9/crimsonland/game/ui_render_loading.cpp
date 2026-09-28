#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern int config_screen_width;
extern int config_screen_height;
}

struct ui_vec2_t {
    float x;
    float y;

    ui_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    void set(float x_value, float y_value)
    {
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

extern "C" void ui_render_loading(void)
{
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

    ui_color_t color(0.0f, 0.0f, 0.0f, 0.5f);
    ui_vec2_t position(
        (float)(config_screen_width / 2 - 110),
        (float)(config_screen_height / 2 - 30));
    grim_interface_ptr->grim_draw_rect_filled(
        (float *)&position, 220.0f, 60.0f, (float *)&color);

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    position.set(
        (float)(config_screen_width / 2 - 110),
        (float)(config_screen_height / 2 - 30));
    grim_interface_ptr->grim_draw_rect_outline(
        (float *)&position, 220.0f, 60.0f);

    char *label = "Please wait...";
    grim_interface_ptr->grim_draw_text_small(
        (float)(config_screen_width / 2
                - grim_interface_ptr->grim_measure_text_width(label) / 2),
        (float)(config_screen_height / 2 - 8),
        label);

    grim_interface_ptr->grim_set_config_var(0x36, true);
}
