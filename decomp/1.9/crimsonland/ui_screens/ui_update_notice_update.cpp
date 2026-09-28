#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct ui_notice_color_t {
    float r;
    float g;
    float b;
    float a;

    ui_notice_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

struct ui_notice_vec2_t {
    float x;
    float y;

    ui_notice_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct ui_notice_button_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    int hover_anim;
    int click_anim;
    float alpha;
    bool force_small;
    bool force_wide;

    ui_notice_button_t()
    {
        enabled = true;
        force_small = force_wide = false;
        alpha = 1.0f;
        click_anim = 0;
        label = 0;
        hovered = false;
        activated = false;
        hover_anim = 0;
    }

    ~ui_notice_button_t() {}
};

extern "C" {
extern unsigned char update_notice_open_requested;
extern char s_empty_string[];

int ui_button_update(float *xy, ui_button_t *button);
}

extern "C" void ui_update_notice_update(float *xy, float alpha)
{
    ui_notice_color_t panel_color(0.0f, 0.0f, 0.0f, alpha * 0.8f);
    grim_interface_ptr->grim_draw_rect_filled(
        xy, 266.0f, 76.0f, (float *)&panel_color);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    grim_interface_ptr->grim_draw_rect_outline(xy, 266.0f, 76.0f);

    grim_interface_ptr->grim_set_color(1.0f, 0.2f, 0.2f, 1.0f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        xy[0] + 12.0f, xy[1] + 14.0f, "NOTE:");

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.8f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        xy[0] + 60.0f, xy[1] + 4.0f,
        "There is a newer version of the");
    grim_interface_ptr->grim_draw_text_small_fmt(
        xy[0] + 60.0f, xy[1] + 18.0f,
        "game available for download.");
    grim_interface_ptr->grim_draw_text_small_fmt(
        xy[0] + 60.0f, xy[1] + 32.0f, s_empty_string);
    grim_interface_ptr->grim_draw_text_small_fmt(
        xy[0] + 60.0f, xy[1] + 46.0f, s_empty_string);

    static ui_notice_button_t update_button;
    update_button.label = "Get the update";

    ui_notice_vec2_t button_xy(
        xy[0] + 65.0f,
        xy[1] + 42.0f - 2.0f);
    ui_button_update((float *)&button_xy, (ui_button_t *)&update_button);
    if (update_button.activated) {
        update_notice_open_requested = 1;
    }
}
