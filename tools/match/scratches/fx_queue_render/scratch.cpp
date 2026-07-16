typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_types.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct fx_render_vec2_t {
    float x;
    float y;

    fx_render_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    fx_render_vec2_t operator+(const fx_render_vec2_t &other) const
    {
        return fx_render_vec2_t(x + other.x, y + other.y);
    }

    fx_render_vec2_t operator-(const fx_render_vec2_t &other) const
    {
        return fx_render_vec2_t(x - other.x, y - other.y);
    }
};

extern "C" {
extern float config_texture_scale;
extern unsigned char terrain_texture_failed;
extern int terrain_render_target;
extern int terrain_texture_width;
extern int bodyset_texture;
extern int particles_texture;
extern float camera_offset_x;
extern float camera_offset_y;
extern creature_type_table_t creature_type_table;
extern fx_queue_entry_t fx_queue[];
extern int fx_queue_count;
extern int fx_queue_rotated;
extern fx_render_vec2_t fx_rotated_pos_x[];
extern float fx_rotated_scale[];
extern float fx_rotated_rotation[];
extern int fx_rotated_effect_id[];
extern effect_color_t fx_rotated_color_r[];
extern fx_render_vec2_t effect_uv4[];
extern fx_render_vec2_t render_scratch_f0;
extern fx_render_vec2_t render_scratch_f2;

void effect_select_texture(int effect_id);
}

extern "C" void fx_queue_render(void)
{
    float texture_scale_inv = 1.0f / config_texture_scale;
    float half_texel =
        1.0f
        / ((float)terrain_texture_width / config_texture_scale * 0.5f);

    if (terrain_texture_failed) {
        if (fx_queue_rotated <= 0) {
            return;
        }

        grim_interface_ptr->grim_bind_texture(bodyset_texture, 0);
        grim_interface_ptr->grim_set_config_var(0x13, 1u);
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
        grim_interface_ptr->grim_begin_batch();

        int index;
        for (index = 0; index < fx_queue_rotated; ++index) {
            int frame = creature_type_table[
                fx_rotated_effect_id[index]].corpse_frame;
            render_scratch_f0 = effect_uv4[frame];
            render_scratch_f2 =
                effect_uv4[frame] + fx_render_vec2_t(0.25f, 0.25f);
            grim_interface_ptr->grim_set_uv(
                render_scratch_f0.x,
                render_scratch_f0.y,
                render_scratch_f2.x,
                render_scratch_f2.y);
            grim_interface_ptr->grim_set_color(
                fx_rotated_color_r[index].r,
                fx_rotated_color_r[index].g,
                fx_rotated_color_r[index].b,
                fx_rotated_color_r[index].a * 0.5f);
            grim_interface_ptr->grim_set_rotation(
                fx_rotated_rotation[index] - 1.5707964f);
            render_scratch_f0 =
                fx_rotated_pos_x[index] + fx_render_vec2_t(2.0f, 2.0f);
            float size = fx_rotated_scale[index] * 1.04f;
            grim_interface_ptr->grim_draw_quad(
                render_scratch_f0.x + camera_offset_x,
                render_scratch_f0.y + camera_offset_y,
                size,
                size);
        }

        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_config_var(0x13, 5u);
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
        grim_interface_ptr->grim_begin_batch();

        for (index = 0; index < fx_queue_rotated; ++index) {
            int frame = creature_type_table[
                fx_rotated_effect_id[index]].corpse_frame;
            render_scratch_f0 = effect_uv4[frame];
            render_scratch_f2 =
                effect_uv4[frame] + fx_render_vec2_t(0.25f, 0.25f);
            grim_interface_ptr->grim_set_uv(
                render_scratch_f0.x,
                render_scratch_f0.y,
                render_scratch_f2.x,
                render_scratch_f2.y);
            grim_interface_ptr->grim_set_color(
                fx_rotated_color_r[index].r,
                fx_rotated_color_r[index].g,
                fx_rotated_color_r[index].b,
                fx_rotated_color_r[index].a);
            grim_interface_ptr->grim_set_rotation(
                fx_rotated_rotation[index] - 1.5707964f);
            float size = fx_rotated_scale[index];
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + fx_rotated_pos_x[index].x,
                camera_offset_y + fx_rotated_pos_x[index].y,
                size,
                size);
        }

        grim_interface_ptr->grim_end_batch();
        return;
    }

    if (fx_queue_rotated != 0 || fx_queue_count != 0) {
            grim_interface_ptr->grim_set_render_target(terrain_render_target);
            grim_interface_ptr->grim_bind_texture(particles_texture, 0);

            if (fx_queue_count > 0) {
                grim_interface_ptr->grim_begin_batch();
                grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);

                int index;
                for (index = 0; index < fx_queue_count; ++index) {
                    fx_queue_entry_t *entry = &fx_queue[index];
                    grim_interface_ptr->grim_set_color_ptr(&entry->color.r);
                    grim_interface_ptr->grim_set_rotation(entry->rotation);
                    effect_select_texture(entry->effect_id);
                    grim_interface_ptr->grim_draw_quad(
                        (entry->pos_x - entry->width * 0.5f)
                            * texture_scale_inv,
                        (entry->pos_y - entry->height * 0.5f)
                            * texture_scale_inv,
                        texture_scale_inv * entry->width,
                        texture_scale_inv * entry->height);
                }

                grim_interface_ptr->grim_end_batch();
            }

            if (fx_queue_rotated > 0) {
                grim_interface_ptr->grim_bind_texture(bodyset_texture, 0);
                grim_interface_ptr->grim_set_config_var(0x13, 1u);
                grim_interface_ptr->grim_set_config_var(0x14, 6u);
                grim_interface_ptr->grim_begin_batch();

                int index;
                for (index = 0; index < fx_queue_rotated; ++index) {
                    int frame = creature_type_table[
                        fx_rotated_effect_id[index]].corpse_frame;
                    render_scratch_f0 = effect_uv4[frame];
                    render_scratch_f2 =
                        effect_uv4[frame]
                        + fx_render_vec2_t(0.25f, 0.25f);
                    grim_interface_ptr->grim_set_uv(
                        render_scratch_f0.x,
                        render_scratch_f0.y,
                        render_scratch_f2.x,
                        render_scratch_f2.y);
                    grim_interface_ptr->grim_set_color(
                        fx_rotated_color_r[index].r,
                        fx_rotated_color_r[index].g,
                        fx_rotated_color_r[index].b,
                        fx_rotated_color_r[index].a * 0.5f);
                    grim_interface_ptr->grim_set_rotation(
                        fx_rotated_rotation[index] - 1.5707964f);
                    render_scratch_f0 =
                        fx_rotated_pos_x[index]
                        - fx_render_vec2_t(0.5f, 0.5f);
                    float size =
                        fx_rotated_scale[index] * texture_scale_inv * 1.064f;
                    grim_interface_ptr->grim_draw_quad(
                        render_scratch_f0.x * texture_scale_inv - half_texel,
                        render_scratch_f0.y * texture_scale_inv - half_texel,
                        size,
                        size);
                }

                grim_interface_ptr->grim_end_batch();
                grim_interface_ptr->grim_set_config_var(0x13, 5u);
                grim_interface_ptr->grim_set_config_var(0x14, 6u);
                grim_interface_ptr->grim_begin_batch();

                for (index = 0; index < fx_queue_rotated; ++index) {
                    int frame = creature_type_table[
                        fx_rotated_effect_id[index]].corpse_frame;
                    render_scratch_f0 = effect_uv4[frame];
                    render_scratch_f2 =
                        effect_uv4[frame]
                        + fx_render_vec2_t(0.25f, 0.25f);
                    grim_interface_ptr->grim_set_uv(
                        render_scratch_f0.x,
                        render_scratch_f0.y,
                        render_scratch_f2.x,
                        render_scratch_f2.y);
                    grim_interface_ptr->grim_set_color(
                        fx_rotated_color_r[index].r,
                        fx_rotated_color_r[index].g,
                        fx_rotated_color_r[index].b,
                        fx_rotated_color_r[index].a);
                    grim_interface_ptr->grim_set_rotation(
                        fx_rotated_rotation[index] - 1.5707964f);
                    float size = fx_rotated_scale[index] * texture_scale_inv;
                    grim_interface_ptr->grim_draw_quad(
                        fx_rotated_pos_x[index].x * texture_scale_inv
                            - half_texel,
                        fx_rotated_pos_x[index].y * texture_scale_inv
                            - half_texel,
                        size,
                        size);
                }

                grim_interface_ptr->grim_end_batch();
            }

            fx_queue_count = 0;
            fx_queue_rotated = 0;
            grim_interface_ptr->grim_set_render_target(-1);
    }
}
