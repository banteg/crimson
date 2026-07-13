#include <math.h>

#include "crimsonland_gameplay.h"

extern "C" bonus_entry_t *bonus_spawn_at_pos(float *pos)
{
    if (pos[0] < 32.0f
        || (float)(terrain_texture_width - 32) < pos[0]
        || pos[1] < 32.0f
        || (float)(terrain_texture_height - 32) < pos[1]
        || config_blob.game_mode == GAME_MODE_RUSH) {
        return &bonus_pool_sentinel;
    }
    {
        bonus_entry_t *entry = bonus_alloc_slot();
        bonus_entry_t *scan = &bonus_pool[0];
        while ((int)scan < (int)&bonus_pool[16]) {
            if (scan->bonus_id != BONUS_ID_NONE) {
                float dx = pos[0] - scan->time.pos_x;
                float dy = pos[1] - scan->time.pos_y;
                float distance_sq = dx * dx;
                distance_sq += dy * dy;
                if ((float)sqrt(distance_sq) < 32.0f) {
                    entry = &bonus_pool_sentinel;
                    break;
                }
            }
            ++scan;
        }

        entry->state = 0;
        entry->time.pos_x = pos[0];
        entry->time.pos_y = pos[1];
        entry->time.time_left = 10.0f;
        entry->time.time_max = 10.0f;
        entry->bonus_id = bonus_pick_random_type();

        if (entry->bonus_id == BONUS_ID_WEAPON) {
            entry->time.amount = weapon_pick_random_available();
            return entry;
        }
        if (entry->bonus_id == BONUS_ID_POINTS) {
            entry->time.amount = 500;
            if ((crt_rand() & 7) <= 2) {
                entry->time.amount = 1000;
                return entry;
            }
        } else {
            entry->time.amount = bonus_meta_table[entry->bonus_id].default_amount;
        }
        return entry;
    }
}
