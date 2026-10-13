#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern "C" char typo_target_name_table[384][64];
extern "C" float camera_offset_x;
extern "C" float camera_offset_y;
extern IGrim2D_cpp *grim_interface_ptr;

struct typo_vec2_t {
    float x;
    float y;

    typo_vec2_t() {}

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

struct typo_color_t {
    float r;
    float g;
    float b;
    float a;

    typo_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

extern "C" void typo_target_name_draw_labels(void)
{
    typo_color_t background_color(0.0f, 0.0f, 0.0f, 1.0f);
    int width;
    float alpha;
    typo_vec2_t text_position;
    typo_vec2_t background_position;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(24, 0.5f);

    for (int i = 0; i < 384; ++i) {
        if (creature_pool[i].active) {
            width = grim_interface_ptr->grim_measure_text_width(
                typo_target_name_table[i]);
            alpha = creature_pool[i].death_timer < 0.0f
                ? (creature_pool[i].death_timer + 10.0f) * 0.1f
                : 1.0f;
            if (alpha > 1.0f) {
                alpha = 1.0f;
            } else if (alpha < 0.0f) {
                alpha = 0.0f;
            }

            text_position.x = camera_offset_x + creature_pool[i].pos_x
                - (float)width * 0.5f;
            text_position.y =
                camera_offset_y + creature_pool[i].pos_y - 50.0f;
            background_color.a = alpha * 0.67f;
            background_position.set(
                text_position.x - 4.0f, text_position.y);
            width += 8;

            grim_interface_ptr->grim_draw_rect_filled(
                (float *)&background_position,
                (float)width,
                15.0f,
                (float *)&background_color);
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, alpha);
            grim_interface_ptr->grim_draw_text_small(
                text_position.x, text_position.y, typo_target_name_table[i]);
        }
    }
}
