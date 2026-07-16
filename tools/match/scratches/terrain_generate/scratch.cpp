#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct terrain_vec2_t {
    float x;
    float y;

    terrain_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    terrain_vec2_t &operator*=(float scale)
    {
        x *= scale;
        y *= scale;
        return *this;
    }
};

extern "C" {
extern float config_texture_scale;
extern unsigned char terrain_texture_failed;
extern int terrain_render_target;
extern int terrain_texture_width;
extern int terrain_texture_height;
extern int terrain_texture_handles[];
extern terrain_vec2_t camera_offset;
}

extern "C" void terrain_generate(quest_meta_t *quest)
{
    float inv_scale = 1.0f / config_texture_scale;

    camera_offset = terrain_vec2_t(0.0f, 0.0f);
    if (terrain_texture_failed) {
        terrain_render_target = terrain_texture_handles[quest->terrain_id];
        return;
    }

    grim_interface_ptr->grim_set_config_var(0x12, true);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_render_target(terrain_render_target);
    grim_interface_ptr->grim_clear_color(
        0.24705882f, 0.21960784f, 0.09803922f, 1.0f);

    grim_interface_ptr->grim_bind_texture(
        terrain_texture_handles[quest->terrain_id], 0);
    grim_interface_ptr->grim_set_color(0.7f, 0.7f, 0.7f, 0.9f);
    grim_interface_ptr->grim_begin_batch();

    int index = 0;
    if (terrain_texture_width * terrain_texture_height * 800 / 0x80000 > 0) {
        float size = inv_scale * 128.0f;
        do {
            grim_interface_ptr->grim_set_rotation(
                (float)(crt_rand() % 314) * 0.01f);
            terrain_vec2_t position(
                (float)(crt_rand() % (terrain_texture_width + 128)) - 64.0f,
                (float)(crt_rand() % (terrain_texture_width + 128)) - 64.0f);
            position *= inv_scale;
            grim_interface_ptr->grim_draw_quad_xy(&position.x, size, size);
            ++index;
        } while (
            index
            < terrain_texture_width * terrain_texture_height * 800 / 0x80000);
    }

    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_bind_texture(
        terrain_texture_handles[quest->terrain_id_b], 0);
    grim_interface_ptr->grim_set_color(0.7f, 0.7f, 0.7f, 0.9f);
    grim_interface_ptr->grim_begin_batch();

    index = 0;
    if (terrain_texture_width * terrain_texture_height * 35 / 0x80000 > 0) {
        float size = inv_scale * 128.0f;
        do {
            grim_interface_ptr->grim_set_rotation(
                (float)(crt_rand() % 314) * 0.01f);
            terrain_vec2_t position(
                (float)(crt_rand() % (terrain_texture_width + 128)) - 64.0f,
                (float)(crt_rand() % (terrain_texture_width + 128)) - 64.0f);
            position *= inv_scale;
            grim_interface_ptr->grim_draw_quad_xy(&position.x, size, size);
            ++index;
        } while (
            index
            < terrain_texture_width * terrain_texture_height * 35 / 0x80000);
    }

    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_bind_texture(
        terrain_texture_handles[quest->terrain_id_c], 0);
    grim_interface_ptr->grim_set_color(0.7f, 0.7f, 0.7f, 0.6f);
    grim_interface_ptr->grim_begin_batch();

    index = 0;
    if (terrain_texture_width * terrain_texture_height * 15 / 0x80000 > 0) {
        float size = inv_scale * 128.0f;
        do {
            grim_interface_ptr->grim_set_rotation(
                (float)(crt_rand() % 314) * 0.01f);
            terrain_vec2_t position(
                (float)(crt_rand() % (terrain_texture_width + 128)) - 64.0f,
                (float)(crt_rand() % (terrain_texture_width + 128)) - 64.0f);
            position *= inv_scale;
            grim_interface_ptr->grim_draw_quad_xy(&position.x, size, size);
            ++index;
        } while (
            index
            < terrain_texture_width * terrain_texture_height * 15 / 0x80000);
    }

    grim_interface_ptr->grim_end_batch();
    camera_offset = terrain_vec2_t(0.0f, 0.0f);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x13, 1u);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_set_config_var(0x15, 2u);
    grim_interface_ptr->grim_set_render_target(-1);
}
