#include <math.h>
#include "crimsonland_gameplay.h"

static __inline float vec2_distance(const vec2f_t *lhs, const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    float distance_sq = dx * dx;
    distance_sq += dy * dy;
    return (float)sqrt(distance_sq);
}

extern "C" int creature_find_nearest(
    const vec2f_t *pos,
    int exclude_id,
    float min_dist)
{
    float best_distance = 1000000.0f;
    int best_index = 0;

    if (exclude_id == -1) {
        int index = 0;

        do {
            if (creature_pool[index].active
                && creature_pool[index].lifecycle_stage == 16.0f) {
                float distance = vec2_distance(
                    pos,
                    &creature_pool[index].position
                );
                if (distance < best_distance) {
                    best_index = index;
                    best_distance = distance;
                }
            }
            ++index;
        } while (index < 0x180);
        return best_index;
    }

    int index = 0;
    creature_t *creature = creature_pool;

    do {
        if (creature->active && index != exclude_id) {
            float dx = pos->x - creature->pos_x;
            float dy = pos->y - creature->pos_y;
            float distance = (float)sqrt(dx * dx + dy * dy);
            if (distance > min_dist && distance < best_distance) {
                best_index = index;
                best_distance = distance;
            }
        }
        ++creature;
        ++index;
    } while ((int)creature < (int)&creature_pool[0x180]);
    return best_index;
}
