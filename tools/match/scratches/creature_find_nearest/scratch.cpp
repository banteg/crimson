#include <math.h>
#include "crimsonland_gameplay.h"

extern "C" int creature_find_nearest(float *pos, int exclude_id, float min_dist)
{
    float best_distance = 1000000.0f;
    int best_index = 0;

    if (exclude_id == -1) {
        int index = 0;
        creature_t *creature = creature_pool;

        do {
            if (creature->active && creature->lifecycle_stage == 16.0f) {
                float dx = pos[0] - creature->pos_x;
                float dy = pos[1] - creature->pos_y;
                float distance = (float)sqrt(dx * dx + dy * dy);
                if (distance < best_distance) {
                    best_index = index;
                    best_distance = distance;
                }
            }
            ++creature;
            ++index;
        } while ((int)creature < (int)&creature_pool[0x180]);
        return best_index;
    }

    int index = 0;
    creature_t *creature = creature_pool;

    do {
        if (creature->active && index != exclude_id) {
            float dx = pos[0] - creature->pos_x;
            float dy = pos[1] - creature->pos_y;
            float distance = (float)sqrt(dx * dx + dy * dy);
            if (min_dist < distance && distance < best_distance) {
                best_index = index;
                best_distance = distance;
            }
        }
        ++creature;
        ++index;
    } while ((int)creature < (int)&creature_pool[0x180]);
    return best_index;
}
