#include <math.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern int particles_texture;
extern float camera_offset_x;
extern float camera_offset_y;
}

union EffectPackedColor {
    unsigned long value;
    unsigned char channel[4];
};

static inline void effect_pack_color(
    effect_color_t *source,
    unsigned long *result)
{
    EffectPackedColor packed;
    packed.channel[3] = (unsigned char)(source->a * 255.0f);
    packed.channel[2] = (unsigned char)(source->r * 255.0f);
    packed.channel[1] = (unsigned char)(source->g * 255.0f);
    packed.channel[0] = (unsigned char)(source->b * 255.0f);
    *result = packed.value;
}

static inline void effect_render_entry(effect_entry_t *entry)
{
    unsigned long color;
    float rotation;
    effect_vec2_t offset;
    float matrix[4];

    rotation = entry->rotation;
    matrix[0] = (float)cos(rotation);
    matrix[1] = -(float)sin(rotation);
    matrix[2] = (float)sin(rotation);
    matrix[3] = (float)cos(rotation);

    matrix[0] *= entry->scale;
    matrix[1] *= entry->scale;
    matrix[2] *= entry->scale;
    matrix[3] *= entry->scale;

    effect_pack_color(&entry->color, &color);

    offset.x = camera_offset_x + entry->pos_x;
    offset.y = camera_offset_y + entry->pos_y;
    grim_interface_ptr->grim_submit_vertices_transform_color(
        &entry->vertices[0].pos.x,
        4,
        &offset.x,
        matrix,
        &color);
}

extern "C" void effects_render(void)
{
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_bind_texture(particles_texture, 0);
    grim_interface_ptr->grim_begin_batch();

    int index;
    for (index = 0; index < 512; ++index) {
        effect_entry_t *entry = &effect_pool[index];
        int flags = entry->flags;
        if (flags != 0 && entry->age >= 0.0f && (flags & 0x40) != 0) {
            effect_render_entry(entry);
        }
    }

    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x14, 2u);
    grim_interface_ptr->grim_begin_batch();

    for (index = 0; index < 512; ++index) {
        effect_entry_t *entry = &effect_pool[index];
        int flags = entry->flags;
        if (flags != 0 && entry->age >= 0.0f && (flags & 0x40) == 0) {
            effect_render_entry(entry);
        }
    }

    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
}
