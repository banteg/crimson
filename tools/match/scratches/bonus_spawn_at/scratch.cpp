#include "crimsonland_gameplay.h"

#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"

extern "C" bonus_entry_t *bonus_spawn_at(
    vec2f_t *pos,
    bonus_id_t bonus_id,
    int duration_override)
{
    bonus_entry_t *entry;
    int count;

    if (pos->x < 32.0f) {
        pos->x = 32.0f;
    }
    if (pos->y < 32.0f) {
        pos->y = 32.0f;
    }
    if ((float)(terrain_texture_width - 32) < pos->x) {
        pos->x = (float)(terrain_texture_width - 32);
    }
    if ((float)(terrain_texture_height - 32) < pos->y) {
        pos->y = (float)(terrain_texture_height - 32);
    }
    if (config_game_mode == GAME_MODE_RUSH) {
        return &bonus_pool_sentinel;
    }

    entry = bonus_alloc_slot();
    entry->state = 0;
    entry->time.position = *pos;
    entry->time.time_left = 10.0f;
    entry->time.time_max = 10.0f;
    entry->bonus_id = bonus_id;
    entry->time.amount = duration_override;
    if (duration_override == -1) {
        entry->time.amount = bonus_meta_table[bonus_id].default_amount;
    }

    {
        effect_color_t color = {0.4f, 0.5f, 1.0f, 0.5f};

        effect_template.flags = 0x1d;
        effect_template.color = color;
        effect_template.lifetime = 0.5f;
        effect_template.half_extent.x = 32.0f;
        effect_template.half_extent.y = 32.0f;
    }

    count = 16;
    do {
        effect_template_rotation = (float)(crt_rand() & 0x7f) * 0.049087387f;
        effect_template_vel_x = (float)(crt_rand() % 128 - 64);
        effect_template_vel_y = (float)(crt_rand() % 128 - 64);
        effect_template_scale_step = (float)(crt_rand() % 100) * 0.01f + 0.1f;
        effect_spawn(0, pos);
        --count;
    } while (count != 0);

    return entry;
}
