#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern "C" double cos(double angle);
extern "C" double sin(double angle);
extern "C" double sqrt(double value);

extern IGrim2D_cpp *grim_interface_ptr;

struct aim_vec2_t {
    float x;
    float y;

    aim_vec2_t() {}

    aim_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    aim_vec2_t operator+(const aim_vec2_t &other) const
    {
        return aim_vec2_t(x + other.x, y + other.y);
    }

    aim_vec2_t operator-(const aim_vec2_t &other) const
    {
        return aim_vec2_t(x - other.x, y - other.y);
    }

    aim_vec2_t operator*(float scale) const
    {
        return aim_vec2_t(x * scale, y * scale);
    }

    ~aim_vec2_t() {}
};

struct aim_static_lifetime_t {
    aim_static_lifetime_t() {}
    ~aim_static_lifetime_t() {}
};

extern "C" {
extern int config_player_count;
extern unsigned char config_direction_arrow_flags[];
extern int config_movement_schemes[];
extern aim_vec2_t camera_offset;
extern int bullet_trail_texture;
extern int world_arrow_marker_texture;

void ui_draw_clock_gauge_at(float *xy, float radius, float progress);
void ui_render_aim_enhancement(float *xy);
}

extern "C" void ui_render_aim_indicators(void)
{
    if (demo_mode_active) {
        return;
    }

    static aim_vec2_t aim_screen;
    static aim_static_lifetime_t aim_lifetime;

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);

    for (render_overlay_player_index = 0;
         render_overlay_player_index < config_player_count;
         ++render_overlay_player_index) {
        if (player_state_table[render_overlay_player_index].health > 0.0f) {
            float dx =
                player_state_table[render_overlay_player_index].aim_x
                - player_state_table[render_overlay_player_index].pos_x;
            float dy =
                player_state_table[render_overlay_player_index].aim_y
                - player_state_table[render_overlay_player_index].pos_y;
            float radius =
                (float)sqrt(dx * dx + dy * dy)
                * player_state_table[render_overlay_player_index].spread_heat
                * 0.5f;
            if (radius < 6.0f) {
                radius = 6.0f;
            }

            grim_interface_ptr->grim_set_uv(0.5f, 0.5f, 0.5f, 0.5f);
            grim_interface_ptr->grim_set_color(0.0f, 0.0f, 0.1f, 0.3f);
            aim_screen =
                camera_offset
                + *(aim_vec2_t *)&player_state_table[render_overlay_player_index]
                       .aim_x;
            grim_interface_ptr->grim_draw_circle_filled(
                aim_screen.x, aim_screen.y, radius);

            grim_interface_ptr->grim_bind_texture(bullet_trail_texture, 0);
            grim_interface_ptr->grim_set_uv(0.5f, 0.0f, 0.5f, 1.0f);
            grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.55f);
            grim_interface_ptr->grim_draw_circle_outline(
                aim_screen.x, aim_screen.y, radius);

            grim_interface_ptr->grim_set_color(1.0f, 0.7f, 0.1f, 0.8f);
            aim_screen =
                camera_offset
                + *(aim_vec2_t *)&player_state_table[render_overlay_player_index]
                       .aim_x;
            ui_draw_clock_gauge_at(
                (float *)&aim_screen,
                48.0f,
                player_state_table[render_overlay_player_index].reload_timer
                    / player_state_table[render_overlay_player_index]
                          .reload_timer_max);
            grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
        }
    }

    for (render_overlay_player_index = 0;
         render_overlay_player_index < config_player_count;
         ++render_overlay_player_index) {
        if (player_state_table[render_overlay_player_index].health > 0.0f
            && config_direction_arrow_flags[render_overlay_player_index]) {
            grim_interface_ptr->grim_set_rotation(
                player_state_table[render_overlay_player_index].heading);
            grim_interface_ptr->grim_bind_texture(
                world_arrow_marker_texture, 0);
            grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);

            if (config_player_count == 2) {
                if (render_overlay_player_index == 0) {
                    grim_interface_ptr->grim_set_color(
                        0.8f, 0.9f, 1.0f, 0.6f);
                } else {
                    grim_interface_ptr->grim_set_color(
                        1.0f, 0.9f, 0.8f, 0.6f);
                }
            } else {
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, 0.3f);
            }

            grim_interface_ptr->grim_begin_batch();
            if (config_movement_schemes[render_overlay_player_index] == 4) {
                aim_vec2_t inset(16.0f, 16.0f);
                aim_screen =
                    camera_offset
                    + *(aim_vec2_t *)&player_state_table
                          [render_overlay_player_index]
                              .move_target_x
                    - inset;
            } else {
                float angle =
                    player_state_table[render_overlay_player_index].heading
                    - 1.57079637f;
                aim_vec2_t direction(
                    (float)cos(angle), (float)sin(angle));
                aim_screen =
                    (camera_offset
                     + *(aim_vec2_t *)&player_state_table
                           [render_overlay_player_index]
                               .pos_x)
                    + direction * 60.0f
                    - aim_vec2_t(16.0f, 16.0f);
            }
            grim_interface_ptr->grim_draw_quad(
                aim_screen.x, aim_screen.y, 32.0f, 32.0f);
            grim_interface_ptr->grim_end_batch();
        }
    }

    for (render_overlay_player_index = 0;
         render_overlay_player_index < config_player_count;
         ++render_overlay_player_index) {
        if (player_state_table[render_overlay_player_index].health > 0.0f) {
            aim_vec2_t enhancement_position =
                camera_offset
                + *(aim_vec2_t *)&player_state_table[render_overlay_player_index]
                       .aim_x;
            ui_render_aim_enhancement((float *)&enhancement_position);
        }
    }

    render_overlay_player_index = 0;
}
