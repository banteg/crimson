#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct keybind_vec2_t {
    float x;
    float y;

    keybind_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct keybind_color_t {
    float r;
    float g;
    float b;
    float a;

    keybind_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

extern "C" char *input_key_name(int key_code);

extern "C" void ui_render_keybind_help(float *xy, float alpha)
{
    keybind_color_t panel_color(0.0f, 0.0f, 0.0f, alpha * 0.8f);
    grim_interface_ptr->grim_draw_rect_filled(
        xy, 512.0f, 256.0f, (float *)&panel_color);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    grim_interface_ptr->grim_draw_rect_outline(xy, 512.0f, 256.0f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.8f);
    grim_interface_ptr->grim_draw_text_mono_fmt(
        xy[0] + 16.0f, xy[1] + 16.0f, "key info");

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

    keybind_vec2_t position = *(keybind_vec2_t *)xy;
    position.x += 32.0f;
    position.y += 50.0f;
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x, position.y, "Level Up:");
    float value_x = position.x + 128.0f;
    grim_interface_ptr->grim_draw_text_small_fmt(
        value_x,
        position.y,
        "%s or SPACE BAR or KeyPadAdd",
        input_key_name(config_blob.key_pick_perk));

    position.y += 18.0f;
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x, position.y, "Reload:");
    grim_interface_ptr->grim_draw_text_small_fmt(
        value_x,
        position.y,
        "%s",
        input_key_name(config_blob.key_reload));

    position.y += 18.0f;
    position.y += 20.0f;
    for (int player = 0; player < 2; ++player) {
        int key_index = player * 5;
        if (player == 1) {
            position.x += 256.0f;
        }

        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "Player %d", player + 1);

        position.y += 22.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "Up:");
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 64.0f,
            position.y,
            "%s",
            input_key_name(config_blob.keybinds_p1[key_index++]));

        position.y += 16.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "Down:");
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 64.0f,
            position.y,
            "%s",
            input_key_name(config_blob.keybinds_p1[key_index++]));

        position.y += 16.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "Left:");
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 64.0f,
            position.y,
            "%s",
            input_key_name(config_blob.keybinds_p1[key_index++]));

        position.y += 16.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "Right:");
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 64.0f,
            position.y,
            "%s",
            input_key_name(config_blob.keybinds_p1[key_index++]));

        position.y += 16.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "Fire:");
        int fire_key = config_blob.keybinds_p1[key_index];
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 64.0f,
            position.y,
            "%s",
            input_key_name(fire_key));

        if (player == 0) {
            position.y -= 94.0f;
        }
    }

    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x - 20.0f,
        position.y + 32.0f,
        "Press F1 to return to game");
}
