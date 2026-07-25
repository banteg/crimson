#include "crimsonland_gameplay.h"

struct effect_spawn_vec2_t {
    float x;
    float y;

    effect_spawn_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    effect_spawn_vec2_t operator+(const effect_spawn_vec2_t &other) const
    {
        return effect_spawn_vec2_t(x + other.x, y + other.y);
    }
};

extern "C" {
extern int effect_spawn_detail_skip_counter;
extern int config_detail_preset;
extern float effect_uv_step_2;
extern float effect_uv_step_4;
extern float effect_uv_step_8;
extern float effect_uv_step_16;
}

#define EFFECT_BUILD_QUAD(uv_table, uv_step)                                \
    do {                                                                    \
        *(effect_spawn_vec2_t *)&entry->vertices[0].tex =                  \
            *(const effect_spawn_vec2_t *)&(uv_table)[frame];              \
        *(effect_spawn_vec2_t *)&entry->vertices[0].pos =                  \
            effect_spawn_vec2_t(                                           \
            -effect_template.half_width, -effect_template.half_height);     \
        *(effect_spawn_vec2_t *)&entry->vertices[1].tex =                  \
            *(const effect_spawn_vec2_t *)&(uv_table)[frame]               \
                + effect_spawn_vec2_t((uv_step), 0.0f);                    \
        *(effect_spawn_vec2_t *)&entry->vertices[1].pos =                  \
            effect_spawn_vec2_t(                                           \
            effect_template.half_width, -effect_template.half_height);      \
        *(effect_spawn_vec2_t *)&entry->vertices[2].tex =                  \
            *(const effect_spawn_vec2_t *)&(uv_table)[frame]               \
                + effect_spawn_vec2_t((uv_step), (uv_step));               \
        *(effect_spawn_vec2_t *)&entry->vertices[2].pos =                  \
            effect_spawn_vec2_t(                                           \
            effect_template.half_width, effect_template.half_height);       \
        *(effect_spawn_vec2_t *)&entry->vertices[3].tex =                  \
            *(const effect_spawn_vec2_t *)&(uv_table)[frame]               \
                + effect_spawn_vec2_t(0.0f, (uv_step));                    \
        *(effect_spawn_vec2_t *)&entry->vertices[3].pos =                  \
            effect_spawn_vec2_t(                                           \
            -effect_template.half_width, effect_template.half_height);      \
    } while (0)

extern "C" effect_entry_t *effect_spawn(
    int effect_id,
    const vec2f_t *pos)
{
    if (config_detail_preset <= 2) {
        if ((effect_spawn_detail_skip_counter++ & 1) != 0) {
            return &effect_discard_entry;
        }
    }

    effect_entry_t *entry = effect_free_list_head;
    int size_code = effect_id_table[effect_id].size_code;
    int frame = effect_id_table[effect_id].frame;
    if (entry->next_free != 0) {
        effect_free_list_head = entry->next_free;
    } else {
        entry = &effect_discard_entry;
    }

    *(effect_template_t *)&entry->velocity = effect_template;
    entry->pos_x = pos->x;
    entry->pos_y = pos->y;
    entry->effect_id = (unsigned char)effect_id;

    if (size_code == 0x10) {
        EFFECT_BUILD_QUAD(effect_uv16, effect_uv_step_16);
    } else if (size_code == 0x20) {
        EFFECT_BUILD_QUAD(effect_uv8, effect_uv_step_8);
    } else if (size_code == 0x40) {
        EFFECT_BUILD_QUAD(effect_uv4, effect_uv_step_4);
    } else if (size_code == 0x80) {
        EFFECT_BUILD_QUAD(effect_uv2, effect_uv_step_2);
    }
    return entry;
}
