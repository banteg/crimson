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

extern "C" int plaguebearer_spread_infection(int creature_id)
{
    register int other_id = 0;
    creature_t *creature = creature_pool;

    do {
        if (creature->active) {
            if (vec2_distance(
                    (vec2f_t *)&creature->pos_x,
                    (vec2f_t *)&creature_pool[creature_id].pos_x
                ) < 45.0f) {
                break;
            }
        }
        ++creature;
        ++other_id;
    } while ((int)creature < (int)&creature_pool[0x180]);

    if ((int)creature >= (int)&creature_pool[0x180]) {
        return 0;
    }

    if (creature_pool[other_id].collision_flag
        && creature_pool[creature_id].health < 150.0f) {
        creature_pool[creature_id].collision_flag = 1;
    }
    if (creature_pool[creature_id].collision_flag
        && creature_pool[other_id].health < 150.0f) {
        creature_pool[other_id].collision_flag = 1;
    }
    return other_id;
}
