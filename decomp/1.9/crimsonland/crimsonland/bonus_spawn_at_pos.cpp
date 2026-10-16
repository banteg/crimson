#include <math.h>

#include "crimsonland_gameplay.h"

#if CL_BUILD == 10908
/*
 * Translation-unit context for 1.9.8: bonus_alloc_slot precedes this function in the original
 * unit (see bonus_alloc_slot.cpp), and C2 9044 keeps `pos` in edx across the call because the
 * callee leaves it alone. 1.9.93's C2 (8966) ignores this.
 */
extern "C" bonus_entry_t *bonus_alloc_slot(void)
{
    int index;
    for (index = 0; index < 0x10; index++) {
        if (bonus_pool[index].bonus_id == BONUS_ID_NONE) {
            return &bonus_pool[index];
        }
    }
    return &bonus_pool_sentinel;
}
#endif

inline bonus_entry_t *bonus_spawn_valid_pos(
    const vec2f_t *pos)
{
    bonus_entry_t *entry = bonus_alloc_slot();
    for (int i = 0; i < 16; i++) {
        if (bonus_pool[i].bonus_id != BONUS_ID_NONE) {
            const vec2f_t *position = &bonus_pool[i].time.position;
            float dx = pos->x - position->x;
            float dy = pos->y - position->y;
            float distance_sq = dx * dx;
            distance_sq += dy * dy;
            if ((float)sqrt(distance_sq) < 32.0f) {
                entry = &bonus_pool_sentinel;
                break;
            }
        }
    }

    entry->picked = 0;
    entry->time.position = *pos;
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

extern "C" bonus_entry_t *bonus_spawn_at_pos(const vec2f_t *pos)
{
    if (pos->x < 32.0f
        || (float)(terrain_texture_width - 32) < pos->x
        || pos->y < 32.0f
        || (float)(terrain_texture_height - 32) < pos->y
        || config_blob.game_mode == GAME_MODE_RUSH) {
        return &bonus_pool_sentinel;
    }
    return bonus_spawn_valid_pos(pos);
}
