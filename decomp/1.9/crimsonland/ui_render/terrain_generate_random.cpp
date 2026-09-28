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
extern int terrain_texture_selectors[3];
extern int terrain_texture_handles[];
extern terrain_vec2_t camera_offset;
extern game_status_t game_status_blob;
extern quest_meta_t quest_meta_terrain_desc_unlock_gt_0x13;
extern quest_meta_t quest_meta_terrain_desc_unlock_gt_0x1d;
extern quest_meta_t quest_meta_terrain_desc_unlock_gt_0x27;
}

#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"

extern "C" void terrain_generate_random(void)
{
    float inv_scale = 1.0f / config_texture_scale;
    float size;

    terrain_texture_selectors[0] = crt_rand() % 7;
    terrain_texture_selectors[1] = crt_rand() % 7;
    terrain_texture_selectors[2] = crt_rand() % 7;
    terrain_texture_selectors[0] = 0;
    terrain_texture_selectors[1] = 1;
    terrain_texture_selectors[2] = 0;

    int textures[3];
    textures[0] = terrain_texture_handles[terrain_texture_selectors[0]];
    textures[1] = terrain_texture_handles[terrain_texture_selectors[1]];
    textures[2] = terrain_texture_handles[terrain_texture_selectors[2]];

    if (game_status_blob.quest_unlock_index >= 40
        && (crt_rand() & 7) == 3) {
        terrain_generate(&quest_meta_terrain_desc_unlock_gt_0x27);
        return;
    }
    if (game_status_blob.quest_unlock_index >= 30
        && (crt_rand() & 7) == 3) {
        terrain_generate(&quest_meta_terrain_desc_unlock_gt_0x1d);
        return;
    }
    if (game_status_blob.quest_unlock_index >= 20
        && (crt_rand() & 7) == 3) {
        terrain_generate(&quest_meta_terrain_desc_unlock_gt_0x13);
        return;
    }

    camera_offset = terrain_vec2_t(0.0f, 0.0f);
    if (terrain_texture_failed) {
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

    grim_interface_ptr->grim_bind_texture(textures[0], 0);
    grim_interface_ptr->grim_set_color(0.7f, 0.7f, 0.7f, 0.9f);
    grim_interface_ptr->grim_begin_batch();

    int index = 0;
    if (terrain_texture_width * terrain_texture_height * 800 / 0x80000 > 0) {
        size = inv_scale * 128.0f;
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
    grim_interface_ptr->grim_bind_texture(textures[1], 0);
    grim_interface_ptr->grim_set_color(0.7f, 0.7f, 0.7f, 0.9f);
    grim_interface_ptr->grim_begin_batch();

    index = 0;
    if (terrain_texture_width * terrain_texture_height * 35 / 0x80000 > 0) {
        size = inv_scale * 128.0f;
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
    grim_interface_ptr->grim_bind_texture(textures[2], 0);
    grim_interface_ptr->grim_set_color(0.7f, 0.7f, 0.7f, 0.6f);
    grim_interface_ptr->grim_begin_batch();

    index = 0;
    if (terrain_texture_width * terrain_texture_height * 15 / 0x80000 > 0) {
        size = inv_scale * 128.0f;
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

    if (cv_verbose->value != 0.0f) {
        console_printf(&console_log_queue, "- Generated terrain.\n");
    }
}
