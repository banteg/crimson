#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern console_cvar_entry_t *cv_terrainFilter;
extern unsigned char terrain_texture_failed;
extern int terrain_render_target;
extern int terrain_texture_width;
extern int terrain_texture_height;
extern int config_screen_width;
extern int config_screen_height;
extern float camera_offset_x;
extern float camera_offset_y;
}

extern "C" void terrain_render(void)
{
    if (cv_terrainFilter->value == 2.0f) {
        grim_interface_ptr->grim_set_config_var(0x15, 1u);
    }

    if (terrain_texture_failed) {
        grim_interface_ptr->grim_bind_texture(terrain_render_target, 0);
        grim_interface_ptr->grim_set_config_var(0x12, false);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);

        int row = 0;
        if (terrain_texture_height / 256 + 1 > 0) {
            int y = 0;
            do {
                int column = 0;
                if (terrain_texture_width / 256 + 1 > 0) {
                    int x = 0;
                    do {
                        grim_interface_ptr->grim_draw_quad(
                            (float)x + camera_offset_x,
                            (float)y + camera_offset_y,
                            256.0f,
                            256.0f);
                        ++column;
                        x += 256;
                    } while (
                        column < terrain_texture_width / 256 + 1);
                }
                ++row;
                y += 256;
            } while (row < terrain_texture_height / 256 + 1);
        }

        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_config_var(0x15, 2u);
        grim_interface_ptr->grim_set_config_var(0x12, true);
        return;
    }

    grim_interface_ptr->grim_bind_texture(terrain_render_target, 0);
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

    float u0 = -camera_offset_x / (float)terrain_texture_width;
    float v0 = -camera_offset_y / (float)terrain_texture_height;
    grim_interface_ptr->grim_set_uv(
        u0,
        v0,
        (float)config_screen_width / (float)terrain_texture_width + u0,
        (float)config_screen_height / (float)terrain_texture_height + v0);
    grim_interface_ptr->grim_draw_fullscreen_quad(0);
    grim_interface_ptr->grim_set_config_var(0x15, 2u);
}
