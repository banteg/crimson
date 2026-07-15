#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct button_vec2_t {
    float x;
    float y;

    button_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct button_color_t {
    float r;
    float g;
    float b;
    float a;

    button_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

struct button_state_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    int hover_anim;
    int click_anim;
    float alpha;
    bool force_small;
    bool force_wide;
};

extern "C" {
extern int ui_button_tex_small;
extern int ui_button_tex_medium;
extern int frame_dt_ms;
extern int ui_focus_timer_ms;
extern int sfx_ui_buttonclick;

bool ui_focus_update(int id);
void ui_focus_draw(float *xy);
void ui_focus_set(int id, char reset_timer);
bool ui_mouse_inside_rect(float *xy, int height, int width);
bool input_primary_just_pressed(void);
}

extern "C" bool ui_button_update(float *xy, button_state_t *button)
{
    bool focused = ui_focus_update((int)button);
    if (focused) {
        button_vec2_t focus_xy(xy[0] - 16.0f, xy[1]);
        ui_focus_draw((float *)&focus_xy);
    }

    float text_width =
        (float)grim_interface_ptr->grim_measure_text_width(button->label);
    if (ui_button_tex_small == -1) {
        ui_button_tex_small =
            grim_interface_ptr->grim_get_texture_handle("ui_buttonSm");
    }
    if (ui_button_tex_medium == -1) {
        ui_button_tex_medium =
            grim_interface_ptr->grim_get_texture_handle("ui_buttonMd");
    }

    float width;
    if (text_width < 40.0f || button->force_small) {
        width = 82.0f;
    } else {
        width = 145.0f;
    }
    if (button->force_wide) {
        width = 145.0f;
    }

    xy[1] += 2.0f;
    button->hovered = ui_mouse_inside_rect(xy, 28, (int)width);
    xy[1] -= 2.0f;
    if (button->hovered) {
        ui_focus_set((int)button, 0);
    }

    if (button->enabled
        && (button->hovered || (focused && ui_focus_timer_ms > 800))) {
        button->hover_anim += frame_dt_ms * 6;
    } else {
        button->hover_anim -= frame_dt_ms * 4;
    }

    if (button->click_anim > 0) {
        button->click_anim -= frame_dt_ms * 6;
    }
    if (button->click_anim < 0) {
        button->click_anim = 0;
    }
    if (button->hover_anim < 0) {
        button->hover_anim = 0;
    } else if (button->hover_anim > 1000) {
        button->hover_anim = 1000;
    }

    button_color_t highlight(0.5f, 0.5f, 0.7f, 0.0f);
    int click_anim = button->click_anim;
    if (click_anim > 0) {
        highlight.r =
            (float)click_anim * 0.001f * 0.5f + 0.5f;
        highlight.g =
            (float)click_anim * 0.001f * 0.5f + 0.5f;
        highlight.b =
            (float)click_anim * 0.001f * 0.7f + 0.7f;
        if (highlight.r > 1.0f) {
            highlight.r = 1.0f;
        }
        if (highlight.g > 1.0f) {
            highlight.g = 1.0f;
        }
        if (highlight.b > 1.0f) {
            highlight.b = 1.0f;
        }
    }

    int hover_anim = button->hover_anim;
    if (hover_anim > 0) {
        float hover_alpha = (float)hover_anim * 0.001f;
        highlight.a = hover_alpha * button->alpha;
        button_vec2_t highlight_xy(xy[0] + 12.0f, xy[1] + 5.0f);
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)&highlight_xy,
            width - 24.0f,
            22.0f,
            (float *)&highlight);
    }

    if (text_width < 40.0f || button->force_small) {
        grim_interface_ptr->grim_bind_texture(ui_button_tex_small, 0);
    } else {
        grim_interface_ptr->grim_bind_texture(ui_button_tex_medium, 0);
    }
    if (button->force_wide) {
        grim_interface_ptr->grim_bind_texture(ui_button_tex_medium, 0);
    }

    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, button->alpha);
    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(xy[0], xy[1], width, 32.0f);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x15, 2u);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

    if (button->hovered) {
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, button->alpha);
    } else {
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, button->alpha * 0.7f);
    }
    grim_interface_ptr->grim_draw_text_small_fmt(
        xy[0] + width * 0.5f
            - (float)(grim_interface_ptr->grim_measure_text_width(button->label) / 2)
            + 1.0f,
        xy[1] + 10.0f,
        "%s",
        button->label);

    if (button->enabled) {
        button->activated =
            focused
            && (grim_interface_ptr->grim_was_key_pressed(0x1c)
                || (button->hovered && input_primary_just_pressed()));
    } else {
        button->activated = 0;
    }

    if (button->activated) {
        button->click_anim = 1000;
        sfx_play(sfx_ui_buttonclick, 1.0f);
    }
    return button->activated;
}
